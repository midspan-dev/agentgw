package e2e

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/midspan-dev/agentgw/internal/harness"
	"github.com/midspan-dev/agentgw/pkg/contracts"
)

// oauthAS is a copy of the fake authorization server in internal/oauth's
// tests, reduced to the knobs these tests use. It serves the protected
// resource metadata at /prm-custom and the AS metadata at the issuer root.
type oauthAS struct {
	*httptest.Server

	PRMAuthSrv   string        // PRM authorization_servers[0]; default the AS itself
	RefreshDelay time.Duration // delays the refresh reply (the rotation still happens)

	Hits          atomic.Int64
	Refreshes     atomic.Int64
	InvalidGrants atomic.Int64
	LastBasic     atomic.Value // "id:secret" of the last token request, "" without Basic

	mu       sync.Mutex
	resource string
	codes    map[string]codeInfo
	cur      string
	old      map[string]bool
	revoked  bool
	n        int
}

type codeInfo struct{ challenge, redirect, clientID string }

func newOAuthAS(t *testing.T) *oauthAS {
	f := &oauthAS{codes: map[string]codeInfo{}, old: map[string]bool{}}
	f.Server = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.Close)
	return f
}

func (f *oauthAS) set(fn func()) { f.mu.Lock(); fn(); f.mu.Unlock() }

func (f *oauthAS) res() string { f.mu.Lock(); defer f.mu.Unlock(); return f.resource }

func (f *oauthAS) serve(w http.ResponseWriter, r *http.Request) {
	js := func(v any) { w.Header().Set("Content-Type", "application/json"); json.NewEncoder(w).Encode(v) }
	f.Hits.Add(1)
	switch p := r.URL.Path; p {
	case "/prm-custom":
		as := f.PRMAuthSrv
		if as == "" {
			as = f.URL
		}
		js(map[string]any{"resource": f.res(), "authorization_servers": []string{as}})
	case "/.well-known/oauth-authorization-server":
		js(map[string]any{"issuer": f.URL, "authorization_endpoint": f.URL + "/as/authorize",
			"token_endpoint": f.URL + "/as/token", "registration_endpoint": f.URL + "/as/register"})
	case "/as/register":
		w.WriteHeader(201)
		js(map[string]any{"client_id": "dcr-client"})
	case "/as/authorize":
		q := r.URL.Query()
		if q.Get("code_challenge_method") != "S256" || q.Get("resource") != f.res() || q.Get("state") == "" || q.Get("client_id") == "" {
			http.Error(w, "invalid authorize request", 400)
			return
		}
		b := make([]byte, 12)
		rand.Read(b)
		code := base64.RawURLEncoding.EncodeToString(b)
		f.set(func() { f.codes[code] = codeInfo{q.Get("code_challenge"), q.Get("redirect_uri"), q.Get("client_id")} })
		rq := url.Values{"state": {q.Get("state")}, "code": {code}}
		http.Redirect(w, r, q.Get("redirect_uri")+"?"+rq.Encode(), http.StatusFound)
	case "/as/token":
		f.token(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (f *oauthAS) token(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	if u, p, ok := r.BasicAuth(); ok {
		f.LastBasic.Store(u + ":" + p)
	} else {
		f.LastBasic.Store("")
	}
	fail := func(code string) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(400)
		fmt.Fprintf(w, `{"error":%q}`, code)
	}
	if r.PostForm.Get("resource") != f.res() {
		fail("invalid_target")
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.n++
	issue := func() {
		f.cur = fmt.Sprintf("rt-%d", f.n)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": fmt.Sprintf("at-%d", f.n), "token_type": "Bearer", "expires_in": 3600, "refresh_token": f.cur,
		})
	}
	switch r.PostForm.Get("grant_type") {
	case "authorization_code":
		ci, ok := f.codes[r.PostForm.Get("code")]
		delete(f.codes, r.PostForm.Get("code"))
		sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
		if !ok || base64.RawURLEncoding.EncodeToString(sum[:]) != ci.challenge ||
			r.PostForm.Get("redirect_uri") != ci.redirect || r.PostForm.Get("client_id") != ci.clientID {
			fail("invalid_grant")
			return
		}
		issue()
	case "refresh_token":
		f.Refreshes.Add(1)
		rt := r.PostForm.Get("refresh_token")
		if f.revoked || f.old[rt] || rt != f.cur {
			f.InvalidGrants.Add(1)
			fail("invalid_grant")
			return
		}
		f.old[rt] = true
		issue()
		if f.RefreshDelay > 0 {
			f.mu.Unlock()
			time.Sleep(f.RefreshDelay)
			f.mu.Lock()
		}
	default:
		fail("unsupported_grant_type")
	}
}

// oauthUp is the fake hosted MCP server: it records every request's headers,
// answers 401 with a resource_metadata challenge to a request without
// Authorization, and proxies the rest to a harness HTTP server.
type oauthUp struct {
	*httptest.Server
	mu   sync.Mutex
	hdrs []http.Header
}

func newOAuthUp(t *testing.T, as *oauthAS) *oauthUp {
	target := harness.StartServer(t, harness.Options{HTTP: true, Tools: harness.DefaultTools(t)})
	tu, err := url.Parse(target.URL)
	if err != nil {
		t.Fatal(err)
	}
	rp := &httputil.ReverseProxy{FlushInterval: -1, Director: func(r *http.Request) { r.URL.Scheme, r.URL.Host = tu.Scheme, tu.Host }}
	u := &oauthUp{}
	u.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u.mu.Lock()
		u.hdrs = append(u.hdrs, r.Header.Clone())
		u.mu.Unlock()
		if r.Header.Get("Authorization") == "" {
			w.Header().Set("WWW-Authenticate", `Bearer resource_metadata="`+as.URL+`/prm-custom"`)
			w.WriteHeader(401)
			return
		}
		rp.ServeHTTP(w, r)
	}))
	t.Cleanup(u.Close)
	as.set(func() { as.resource = u.URL })
	return u
}

func (u *oauthUp) seen() []http.Header {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]http.Header(nil), u.hdrs...)
}

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *syncBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

// oauthGW is a gateway config for one authorization_code upstream named docs.
func oauthGW(t *testing.T, up *oauthUp, auth map[string]any) (*gw, string) {
	t.Helper()
	addr := freeAddr(t)
	auth["kind"] = "authorization_code"
	g := setup(t, map[string]any{"name": "docs", "url": up.URL, "path": "/mcp", "auth": auth}, addr, "10m")
	return g, addr
}

// startServe runs `agentgw serve` and returns its stderr once it listens.
func startServe(t *testing.T, g *gw, addr string, env ...string) *syncBuf {
	t.Helper()
	cmd := exec.Command(bin, "serve", "--config", g.cfg)
	cmd.Env = append(os.Environ(), env...)
	stderr := &syncBuf{}
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cmd.Process.Signal(syscall.SIGTERM); cmd.Wait() })
	for i := 0; ; i++ {
		c, err := net.Dial("tcp", addr)
		if err == nil {
			c.Close()
			return stderr
		}
		if i == 100 {
			t.Fatalf("serve did not listen on %s\n%s", addr, stderr.String())
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// login runs `agentgw login --no-browser docs`, follows the printed URL like a
// browser would and returns stdout and stderr once the command exits 0.
func login(t *testing.T, g *gw, env ...string) (string, string) {
	t.Helper()
	cmd := exec.Command(bin, "login", "--config", g.cfg, "--no-browser", "docs")
	cmd.Env = append(os.Environ(), env...)
	stderr := &syncBuf{}
	cmd.Stderr = stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	var all strings.Builder
	followed := false
	sc := bufio.NewScanner(stdout)
	for sc.Scan() {
		line := sc.Text()
		all.WriteString(line + "\n")
		if strings.HasPrefix(line, "http://") && !followed {
			followed = true
			resp, err := http.Get(line)
			if err != nil {
				t.Fatal(err)
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if resp.StatusCode != 200 {
				t.Fatalf("authorization URL answered %d", resp.StatusCode)
			}
		}
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("login: %v\nstdout: %s\nstderr: %s", err, all.String(), stderr.String())
	}
	if !followed {
		t.Fatalf("login printed no URL: %s", all.String())
	}
	return all.String(), stderr.String()
}

func readTokenFile(t *testing.T, path string) contracts.TokenFile {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var tf contracts.TokenFile
	if err := json.Unmarshal(b, &tf); err != nil {
		t.Fatal(err)
	}
	return tf
}

func seedTokenFile(t *testing.T, path string, tf contracts.TokenFile) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(tf)
	write(t, path, b)
}

// wantBearer asserts every request carries exactly one Authorization: Bearer tok.
func wantBearer(t *testing.T, hs []http.Header, tok string) {
	t.Helper()
	if len(hs) == 0 {
		t.Fatal("upstream saw no requests")
	}
	for i, h := range hs {
		if vs := h.Values("Authorization"); len(vs) != 1 || vs[0] != "Bearer "+tok {
			t.Fatalf("request %d Authorization %v, want Bearer %s", i, vs, tok)
		}
	}
}

// noLeak asserts none of the secrets appears in the gateway's ledger file.
func noLeak(t *testing.T, g *gw, secrets ...string) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(g.dir, "ledger.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range secrets {
		if strings.Contains(string(b), s) {
			t.Fatalf("ledger contains %q", s)
		}
	}
}

func seedFor(as *oauthAS, up *oauthUp, expires time.Duration) contracts.TokenFile {
	return contracts.TokenFile{Version: "1", Upstream: "docs", Resource: up.URL, Issuer: as.URL, TokenEndpoint: as.URL + "/as/token",
		ClientID: "dcr-client", AccessToken: "at-seed", RefreshToken: "rt-seed",
		ExpiresAt: time.Now().Add(expires).UTC().Format(time.RFC3339)}
}

// callOnce handshakes and calls echo n=1 without using testing.T, so it can run in a goroutine.
func callOnce(url string) error {
	do := func(session, body string) (string, string, error) {
		req, _ := http.NewRequest("POST", url, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		req.Header.Set("Authorization", "Bearer client-token")
		if session != "" {
			req.Header.Set("Mcp-Session-Id", session)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return "", "", err
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		out := string(b)
		for _, l := range strings.Split(out, "\n") {
			if d, ok := strings.CutPrefix(l, "data: "); ok {
				out = d
			}
		}
		return out, resp.Header.Get("Mcp-Session-Id"), nil
	}
	_, sid, err := do("", `{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"raw","version":"1"}}}`)
	if err != nil {
		return err
	}
	if _, _, err := do(sid, `{"jsonrpc":"2.0","method":"notifications/initialized"}`); err != nil {
		return err
	}
	out, _, err := do(sid, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{"n":1}}}`)
	if err != nil {
		return err
	}
	if !strings.Contains(out, `{\"n\":1}`) || strings.Contains(out, `"error"`) {
		return fmt.Errorf("call failed: %s", out)
	}
	return nil
}

// bareCall POSTs tools/call with no handshake (the gateway answers before any upstream hop).
func bareCall(t *testing.T, url string, id int) string {
	t.Helper()
	got, _ := post(t, url, "", fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"tools/call","params":{"name":"echo","arguments":{"n":%d}}}`, id, id))
	return got
}

func TestE2ELoginThenServe(t *testing.T) {
	as := newOAuthAS(t)
	up := newOAuthUp(t, as)
	g, addr := oauthGW(t, up, map[string]any{})

	out, _ := login(t, g)
	tokPath := filepath.Join(g.dir, "tokens", "docs.json")
	if !strings.Contains(out, "logged in to docs; tokens in "+tokPath) {
		t.Fatalf("login output: %s", out)
	}
	fi, err := os.Stat(tokPath)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("token file: %v %v", fi, err)
	}
	tf := readTokenFile(t, tokPath)
	if tf.Upstream != "docs" || tf.AccessToken == "" {
		t.Fatalf("token file: %+v", tf)
	}

	before := len(up.seen())
	url := "http://" + addr + "/mcp"
	startServe(t, g, addr)
	wantEchoes(t, echoCalls(t, url, 5))
	wantBearer(t, up.seen()[before:], tf.AccessToken)
	noLeak(t, g, "client-token", tf.AccessToken, tf.RefreshToken)
	// The shared "allow" golden names the server "harness"; this upstream is docs.
	es := g.entries()
	if len(es) != 5 {
		t.Fatalf("%d ledger entries, want 5", len(es))
	}
	for _, e := range es {
		if e.Action.Server != "docs" || e.Action.Tool != "echo" || e.Decision.Outcome != contracts.OutcomeAllow || e.Outcome != contracts.EntryOK {
			t.Fatalf("entry: %+v", e)
		}
	}
	if o := g.cli("verify"); !strings.HasPrefix(o, "ok: ") {
		t.Fatalf("verify: %q", o)
	}
}

func TestE2EServeConcurrentRefresh(t *testing.T) {
	as := newOAuthAS(t)
	as.RefreshDelay = 300 * time.Millisecond
	up := newOAuthUp(t, as)
	as.set(func() { as.cur = "rt-seed" })
	tokPath := filepath.Join(t.TempDir(), "docs.json")
	seedTokenFile(t, tokPath, seedFor(as, up, 5*time.Second)) // inside the 60 s refresh window: stale at once

	var urls []string
	for i := 0; i < 2; i++ {
		g, addr := oauthGW(t, up, map[string]any{"token_file": tokPath})
		startServe(t, g, addr)
		urls = append(urls, "http://"+addr+"/mcp")
	}
	before := len(up.seen())
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for _, u := range urls {
		for i := 0; i < 4; i++ {
			wg.Add(1)
			go func() { defer wg.Done(); errs <- callOnce(u) }()
		}
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	wantBearer(t, up.seen()[before:], "at-1") // never the stale at-seed
	if as.Refreshes.Load() != 1 || as.InvalidGrants.Load() != 0 {
		t.Fatalf("refreshes %d, invalid_grant %d; want 1 and 0", as.Refreshes.Load(), as.InvalidGrants.Load())
	}
	if tf := readTokenFile(t, tokPath); tf.RefreshToken != "rt-1" || tf.AccessToken != "at-1" {
		t.Fatalf("token file after refresh: %+v", tf)
	}
}

func TestE2EServeRevokedRefresh(t *testing.T) {
	as := newOAuthAS(t)
	up := newOAuthUp(t, as)
	as.set(func() { as.cur = "rt-seed"; as.revoked = true })
	g, addr := oauthGW(t, up, map[string]any{})
	seedTokenFile(t, filepath.Join(g.dir, "tokens", "docs.json"), seedFor(as, up, -time.Hour))
	startServe(t, g, addr)
	url := "http://" + addr + "/mcp"

	for i := 1; i <= 3; i++ {
		got := bareCall(t, url, i)
		if !strings.Contains(got, `"error"`) || strings.Contains(got, `"result"`) || !strings.Contains(got, "run agentgw login docs") {
			t.Fatalf("call %d: %s", i, got)
		}
	}
	if n := len(up.seen()); n != 0 {
		t.Fatalf("upstream saw %d requests, want 0", n)
	}
	if n := as.Refreshes.Load(); n != 1 {
		t.Fatalf("%d refresh attempts for 3 calls, want 1", n)
	}
	for _, e := range g.entries() {
		if e.Outcome == contracts.EntryOK {
			t.Fatalf("ok entry despite revoked refresh: %+v", e)
		}
	}

	login(t, g)
	before := len(up.seen())
	wantEchoes(t, echoCalls(t, url, 1))
	tf := readTokenFile(t, filepath.Join(g.dir, "tokens", "docs.json"))
	if tf.AccessToken == "at-seed" || tf.AccessToken == "" {
		t.Fatalf("login did not replace the token: %+v", tf)
	}
	wantBearer(t, up.seen()[before:], tf.AccessToken)
	noLeak(t, g, "client-token", "at-seed", "rt-seed", tf.AccessToken, tf.RefreshToken)
}

func TestE2EServeNotLoggedIn(t *testing.T) {
	as := newOAuthAS(t)
	up := newOAuthUp(t, as)
	g, addr := oauthGW(t, up, map[string]any{})
	stderr := startServe(t, g, addr)
	if s := stderr.String(); !strings.Contains(s, "upstream docs: not logged in; run agentgw login docs") {
		t.Fatalf("stderr: %s", s)
	}
	if got := bareCall(t, "http://"+addr+"/mcp", 1); !strings.Contains(got, "run agentgw login") {
		t.Fatalf("call: %s", got)
	}
	if n := len(up.seen()); n != 0 {
		t.Fatalf("upstream saw %d requests, want 0", n)
	}
}

func TestE2ELoginPinnedIssuer(t *testing.T) {
	as := newOAuthAS(t)
	other := newOAuthAS(t)
	as.PRMAuthSrv = other.URL
	up := newOAuthUp(t, as)
	g, _ := oauthGW(t, up, map[string]any{"client_id": "cid", "secret_env": "OAUTH_E2E_SECRET", "issuer": as.URL})

	stdout, stderr := login(t, g, "OAUTH_E2E_SECRET=sekret")
	if strings.Contains(stdout+stderr, "sekret") {
		t.Fatalf("client secret in login output:\n%s\n%s", stdout, stderr)
	}
	if n := other.Hits.Load(); n != 0 {
		t.Fatalf("the PRM's authorization server saw %d requests, want 0", n)
	}
	if b, _ := as.LastBasic.Load().(string); b != "cid:sekret" {
		t.Fatalf("exchange Basic auth %q, want cid:sekret", b)
	}
	if tf := readTokenFile(t, filepath.Join(g.dir, "tokens", "docs.json")); tf.ClientID != "cid" || tf.AccessToken == "" {
		t.Fatalf("token file: %+v", tf)
	}
}
