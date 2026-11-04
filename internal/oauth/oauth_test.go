package oauth

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	neturl "net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/midspan-dev/agentgw/internal/harness"
	"github.com/midspan-dev/agentgw/internal/proxy"
	"github.com/midspan-dev/agentgw/pkg/contracts"
)

func storeIn(t *testing.T) *Store {
	return &Store{Path: filepath.Join(t.TempDir(), "tokens", "docs.json")}
}

// browser simulates the user's browser: follow the authorization URL and its redirect to the loopback.
func browser(t *testing.T) func(string) error {
	return func(u string) error {
		resp, err := http.Get(u)
		if err != nil {
			return err
		}
		resp.Body.Close()
		return nil
	}
}

func loginOpts(f *fakeAS, st *Store, t *testing.T) LoginOptions {
	return LoginOptions{Upstream: "docs", URL: f.MCPURL(), Store: st, Out: io.Discard, Open: browser(t), Timeout: 10 * time.Second}
}

func seed(t *testing.T, st *Store, tf contracts.TokenFile) {
	t.Helper()
	tf.Version = "1"
	if tf.Upstream == "" {
		tf.Upstream = "docs"
	}
	if err := st.Update(func(x *contracts.TokenFile) error { *x = tf; return nil }); err != nil {
		t.Fatal(err)
	}
}

func apply(c contracts.UpstreamCredential) (string, error) {
	h := http.Header{}
	err := c.Apply(context.Background(), h)
	return h.Get("Authorization"), err
}

func seedFor(f *fakeAS, exp time.Duration) contracts.TokenFile {
	f.Seed("rt-seed")
	return contracts.TokenFile{
		Resource: f.MCPURL(), Issuer: f.issuer(), TokenEndpoint: f.URL + "/as/token", ClientID: "dcr-client",
		AccessToken: "at-seed", ExpiresAt: time.Now().Add(exp).UTC().Format(time.RFC3339), RefreshToken: "rt-seed",
	}
}

func TestDiscovery(t *testing.T) {
	cases := []struct {
		name string
		mod  func(*fakeAS)
	}{
		{"challenge", func(f *fakeAS) { f.Challenge, f.Scope = true, "docs.read" }},
		{"well-known", func(f *fakeAS) {}},
		{"path-aware", func(f *fakeAS) { f.IssuerPath = "/tenant" }},
		{"openid-fallback-with-path", func(f *fakeAS) {
			f.IssuerPath, f.MetaPath = "/tenant", "/.well-known/openid-configuration/tenant"
		}},
		{"openid-appended-to-issuer-path", func(f *fakeAS) {
			f.IssuerPath, f.MetaPath = "/tenant", "/tenant/.well-known/openid-configuration"
		}},
		{"root-fallback", func(f *fakeAS) {
			f.IssuerPath, f.MetaPath = "/tenant", "/.well-known/openid-configuration"
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFakeAS(t)
			c.mod(f)
			d, err := discover(t.Context(), newClient(), f.MCPURL(), "")
			if err != nil {
				t.Fatal(err)
			}
			if d.TokenEndpoint != f.URL+"/as/token" || d.RegEndpoint != f.URL+"/as/register" || d.Resource != f.MCPURL() {
				t.Errorf("%+v", d)
			}
			if f.Challenge && d.ScopeHint != "docs.read" {
				t.Errorf("scope hint %q", d.ScopeHint)
			}
		})
	}
}

func TestDiscoveryRejects(t *testing.T) {
	f := newFakeAS(t)
	f.Methods = []string{"plain"}
	if _, err := discover(t.Context(), newClient(), f.MCPURL(), ""); err == nil || !strings.Contains(err.Error(), "does not support PKCE S256") {
		t.Errorf("no S256: %v", err)
	}
	f = newFakeAS(t)
	f.AuthURLOver = "http://example.com/authorize"
	if _, err := discover(t.Context(), newClient(), f.MCPURL(), ""); err == nil || !strings.Contains(err.Error(), "must be https") {
		t.Errorf("http endpoint: %v", err)
	}
}

func TestRegistrationOnce(t *testing.T) {
	f := newFakeAS(t)
	st := storeIn(t)
	for range 2 {
		if err := Login(t.Context(), loginOpts(f, st, t)); err != nil {
			t.Fatal(err)
		}
	}
	if n := f.Registrations.Load(); n != 1 {
		t.Errorf("registrations = %d", n)
	}
	f.NoReg = true
	o := loginOpts(f, storeIn(t), t)
	if err := Login(t.Context(), o); err == nil || !strings.Contains(err.Error(), "requires a configured client_id") {
		t.Errorf("no registration endpoint: %v", err)
	}
	o.Auth.ClientID = "preset"
	if err := Login(t.Context(), o); err != nil {
		t.Fatal(err)
	}
	if tf, _ := o.Store.Load("docs"); tf.ClientID != "preset" || tf.ClientSecret != "" {
		t.Errorf("%+v", tf)
	}
}

func TestLoginEndToEnd(t *testing.T) {
	f := newFakeAS(t)
	f.RegSecret = "dcr-secret"
	st := storeIn(t)
	var out bytes.Buffer
	o := loginOpts(f, st, t)
	o.Out = &out
	if err := Login(t.Context(), o); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "open this URL to log in to docs:\n"+f.URL+"/as/authorize?") {
		t.Errorf("output %q", out.String())
	}
	tf, err := st.Load("docs")
	if err != nil {
		t.Fatal(err)
	}
	if tf.AccessToken != "at-1" || tf.RefreshToken != "rt-1" || tf.ClientID != "dcr-client" || tf.ClientSecret != "dcr-secret" ||
		tf.Resource != f.MCPURL() || tf.TokenEndpoint != f.URL+"/as/token" || tf.Scope != "read write" {
		t.Errorf("%+v", tf)
	}
	if exp, err := time.Parse(time.RFC3339, tf.ExpiresAt); err != nil || time.Until(exp) < 59*time.Minute {
		t.Errorf("expires_at %q", tf.ExpiresAt)
	}
	if fi, _ := os.Stat(st.Path); fi.Mode().Perm() != 0o600 {
		t.Errorf("file mode %v", fi.Mode())
	}
	if fi, _ := os.Stat(filepath.Dir(st.Path)); fi.Mode().Perm() != 0o700 {
		t.Errorf("dir mode %v", fi.Mode())
	}
	ents, _ := os.ReadDir(filepath.Dir(st.Path))
	for _, e := range ents {
		if e.Name() != "docs.json" && e.Name() != "docs.json.lock" {
			t.Errorf("stray file %s", e.Name())
		}
	}
	// The DCR secret authenticates the refresh.
	seed(t, st, func() contracts.TokenFile {
		x := *tf
		x.ExpiresAt = time.Now().Add(10 * time.Second).UTC().Format(time.RFC3339)
		return x
	}())
	if _, err := apply(testCred(f.MCPURL(), st, "")); err != nil {
		t.Fatal(err)
	}
	if b := f.LastBasic.Load(); b != "dcr-client:dcr-secret" {
		t.Errorf("refresh basic auth %v", b)
	}
}

func TestLoginFailures(t *testing.T) {
	t.Run("tampered verifier", func(t *testing.T) {
		f := newFakeAS(t)
		f.BadChall = true
		err := Login(t.Context(), loginOpts(f, storeIn(t), t))
		if err == nil || !strings.Contains(err.Error(), "invalid_grant") {
			t.Fatalf("%v", err)
		}
		if f.CodeGrants.Load() != 1 {
			t.Error("fake never saw the exchange")
		}
		v, c := f.GotVerifier.Load().(string), f.GotCode.Load().(string)
		if v == "" || c == "" || strings.Contains(err.Error(), v) || strings.Contains(err.Error(), c) {
			t.Errorf("verifier %q or code %q in error text: %v", v, c, err)
		}
	})
	t.Run("wrong state", func(t *testing.T) {
		f := newFakeAS(t)
		f.WrongState = true
		st := storeIn(t)
		err := Login(t.Context(), loginOpts(f, st, t))
		if err == nil || !strings.Contains(err.Error(), "state mismatch") || f.CodeGrants.Load() != 0 {
			t.Fatalf("%v", err)
		}
		if _, err := os.Stat(st.Path); err == nil {
			t.Error("token file written")
		}
	})
	t.Run("denied", func(t *testing.T) {
		f := newFakeAS(t)
		f.DenyWith = "access_denied"
		if err := Login(t.Context(), loginOpts(f, storeIn(t), t)); err == nil || !strings.Contains(err.Error(), "authorization refused: access_denied") {
			t.Fatalf("%v", err)
		}
	})
	t.Run("timeout", func(t *testing.T) {
		f := newFakeAS(t)
		o := loginOpts(f, storeIn(t), t)
		o.Open, o.Timeout = nil, 100*time.Millisecond
		if err := Login(t.Context(), o); err == nil || !strings.Contains(err.Error(), "no callback") {
			t.Fatalf("%v", err)
		}
	})
}

func TestPRMResourceCheck(t *testing.T) {
	f := newFakeAS(t)
	f.PRMResource = f.URL // origin-only resource matches /mcp
	if err := Login(t.Context(), loginOpts(f, storeIn(t), t)); err != nil {
		t.Fatalf("origin-only resource: %v", err)
	}
	f = newFakeAS(t)
	f.PRMResource = "https://evil.example/"
	var out bytes.Buffer
	o := loginOpts(f, storeIn(t), t)
	o.Out = &out
	err := Login(t.Context(), o)
	if err == nil || !strings.Contains(err.Error(), "names https://evil.example/, not "+f.MCPURL()) {
		t.Fatalf("%v", err)
	}
	if out.Len() != 0 || f.Registrations.Load() != 0 {
		t.Errorf("progress before the check: %q", out.String())
	}
	f.ExpectRes = f.MCPURL() // a configured resource bypasses the check
	o = loginOpts(f, storeIn(t), t)
	o.Auth.Resource = f.MCPURL()
	if err := Login(t.Context(), o); err != nil {
		t.Fatalf("configured resource: %v", err)
	}
	for _, bad := range []string{"https://host/mcp2", "http://host/mcp", "https://host:8443/mcp", "https://other/mcp"} {
		if checkResource(bad, "https://host/mcp") == nil {
			t.Errorf("%s accepted", bad)
		}
	}
	if checkResource("https://host/mcp/", "https://host/mcp/sub") != nil {
		t.Error("prefix with slash rejected")
	}
}

func TestRefreshSurvivesCancel(t *testing.T) {
	f := newFakeAS(t)
	f.RefreshDelay = 300 * time.Millisecond
	st := storeIn(t)
	seed(t, st, seedFor(f, -time.Hour))
	c := testCred(f.MCPURL(), st, "")
	ctx, cancel := context.WithCancel(t.Context())
	go func() { time.Sleep(100 * time.Millisecond); cancel() }()
	c.Apply(ctx, http.Header{}) // outcome is irrelevant; the rotated token must be saved
	tf, err := st.Load("docs")
	if err != nil || tf.RefreshToken != "rt-1" {
		t.Fatalf("file after cancel: %+v %v", tf, err)
	}
	if got, err := apply(c); err != nil || got != "Bearer at-1" || f.InvalidGrants.Load() != 0 {
		t.Errorf("next apply: %q %v invalid_grant=%d", got, err, f.InvalidGrants.Load())
	}
}

func TestRefreshRotation(t *testing.T) {
	f := newFakeAS(t)
	st := storeIn(t)
	seed(t, st, seedFor(f, 30*time.Second))
	c := testCred(f.MCPURL(), st, "")
	got, err := apply(c)
	if err != nil || got != "Bearer at-1" {
		t.Fatalf("%q %v", got, err)
	}
	tf, _ := st.Load("docs")
	if tf.RefreshToken != "rt-1" || tf.AccessToken != "at-1" {
		t.Errorf("%+v", tf)
	}
	if got, err = apply(c); err != nil || got != "Bearer at-1" || f.Refreshes.Load() != 1 {
		t.Errorf("second apply: %q %v refreshes=%d", got, err, f.Refreshes.Load())
	}
}

// Without a refresh token, a token inside the refresh window is used until it expires.
func TestNoRefreshTokenUsesUnexpired(t *testing.T) {
	f := newFakeAS(t)
	st := storeIn(t)
	tf := seedFor(f, 45*time.Second)
	tf.RefreshToken = ""
	seed(t, st, tf)
	c := testCred(f.MCPURL(), st, "")
	if got, err := apply(c); err != nil || got != "Bearer at-seed" {
		t.Fatalf("unexpired: %q %v", got, err)
	}
	tf.ExpiresAt = time.Now().Add(-time.Second).UTC().Format(time.RFC3339)
	seed(t, st, tf)
	if _, err := apply(c); !loginRequired(err) {
		t.Errorf("expired: %v", err)
	}
	if n := f.Hits.Load(); n != 0 {
		t.Errorf("token endpoint hits = %d", n)
	}
}

func TestTwoProcesses(t *testing.T) {
	f := newFakeAS(t)
	st := storeIn(t)
	seed(t, st, seedFor(f, -time.Hour))
	creds := []contracts.UpstreamCredential{
		testCred(f.MCPURL(), &Store{Path: st.Path}, ""), testCred(f.MCPURL(), &Store{Path: st.Path}, ""),
	}
	var wg sync.WaitGroup
	res := make([]string, 10)
	errs := make([]error, 10)
	for i := range 10 {
		wg.Add(1)
		go func() { defer wg.Done(); res[i], errs[i] = apply(creds[i%2]) }()
	}
	wg.Wait()
	for i := range res {
		if errs[i] != nil || res[i] != "Bearer at-1" {
			t.Errorf("%d: %q %v", i, res[i], errs[i])
		}
	}
	if f.Refreshes.Load() != 1 || f.InvalidGrants.Load() != 0 {
		t.Errorf("refreshes=%d invalid_grant=%d", f.Refreshes.Load(), f.InvalidGrants.Load())
	}
}

func TestRevoked(t *testing.T) {
	f := newFakeAS(t)
	st := storeIn(t)
	seed(t, st, seedFor(f, -time.Hour))
	f.Revoke()
	c := testCred(f.MCPURL(), st, "")
	_, err := apply(c)
	if err == nil || !strings.Contains(err.Error(), "run agentgw login docs") {
		t.Fatalf("%v", err)
	}
	if strings.Contains(err.Error(), "rt-seed") || strings.Contains(err.Error(), "client_id") {
		t.Errorf("leak: %v", err)
	}
	if _, err2 := apply(c); err2 == nil || err2.Error() != err.Error() || f.Refreshes.Load() != 1 {
		t.Errorf("second apply: %v refreshes=%d", err2, f.Refreshes.Load())
	}
	// A new login rewrites the file.
	nt := seedFor(f, time.Hour)
	nt.AccessToken = "at-new"
	seed(t, st, nt)
	later := time.Now().Add(time.Minute)
	os.Chtimes(st.Path, later, later)
	if got, err := apply(c); err != nil || got != "Bearer at-new" {
		t.Errorf("after login: %q %v", got, err)
	}
}

func TestRefreshFailureIsRetried(t *testing.T) {
	f := newFakeAS(t)
	st := storeIn(t)
	tf := seedFor(f, -time.Hour)
	tf.TokenEndpoint = f.URL + "/nope" // 404 on every refresh
	seed(t, st, tf)
	c := testCred(f.MCPURL(), st, "")
	for range 2 {
		if _, err := apply(c); err == nil || !strings.Contains(err.Error(), "token refresh failed: HTTP 404") {
			t.Fatalf("%v", err)
		}
	}
}

func TestMissingAndForeignFile(t *testing.T) {
	st := storeIn(t)
	c := testCred("https://a.example/mcp", st, "")
	if _, err := apply(c); err == nil || !strings.Contains(err.Error(), "login required: run agentgw login docs") {
		t.Errorf("missing: %v", err)
	}
	seed(t, st, contracts.TokenFile{Upstream: "other", AccessToken: "x", ExpiresAt: time.Now().Add(time.Hour).UTC().Format(time.RFC3339)})
	if _, err := apply(c); err == nil || !strings.Contains(err.Error(), st.Path) {
		t.Errorf("foreign: %v", err)
	}
	if _, err := st.Load("docs"); err == nil {
		t.Error("Load accepted a file for another upstream")
	}
	os.WriteFile(st.Path, []byte(`{"version":"2","upstream":"docs"}`), 0o600)
	if _, err := st.Load("docs"); err == nil {
		t.Error("Load accepted version 2")
	}
	if _, err := (&Store{Path: filepath.Join(t.TempDir(), "x")}).Load("docs"); !os.IsNotExist(err) {
		t.Errorf("absent: %v", err)
	}
}

// TestE2EOAuthCredentialThroughProxy drives the harness MCP server through proxy.HTTP
// with the refreshing credential: the client's Authorization never reaches the upstream.
func TestE2EOAuthCredentialThroughProxy(t *testing.T) {
	f := newFakeAS(t)
	st := storeIn(t)
	seed(t, st, seedFor(f, 3600*time.Second))
	up := harness.StartServer(t, harness.Options{HTTP: true, Tools: harness.DefaultTools(t)})
	target, _ := neturl.Parse(up.URL)
	var mu sync.Mutex
	var seen []string
	rp := httputil.NewSingleHostReverseProxy(target)
	rec := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, strings.Join(r.Header.Values("Authorization"), ","))
		mu.Unlock()
		rp.ServeHTTP(w, r)
	}))
	t.Cleanup(rec.Close)

	addr := freeAddr(t)
	cred := testCred(f.MCPURL(), st, "")
	go proxy.HTTP(t.Context(), addr, []proxy.Route{{Name: "docs", Path: "/mcp/docs", URL: rec.URL, Credential: cred}}, passthrough{})
	waitFor(t, addr)

	call := func() string {
		body := `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{},"io.modelcontextprotocol/clientInfo":{"name":"x","version":"0"}}}}`
		req, _ := http.NewRequestWithContext(t.Context(), "POST", "http://"+addr+"/mcp/docs", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		req.Header.Set("Mcp-Protocol-Version", "2026-07-28")
		req.Header.Set("Mcp-Method", "tools/list")
		req.Header.Set("Authorization", "Bearer client-token")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return string(b)
	}
	if b := call(); !strings.Contains(b, `"tools"`) {
		t.Fatalf("call failed: %s", b)
	}
	// Near-expiry: the next call refreshes.
	near := seedFor(f, 30*time.Second)
	near.AccessToken = "at-near"
	seed(t, st, near)
	later := time.Now().Add(time.Minute)
	os.Chtimes(st.Path, later, later)
	if b := call(); !strings.Contains(b, `"tools"`) {
		t.Fatalf("call failed: %s", b)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 2 || seen[0] != "Bearer at-seed" || seen[1] != "Bearer at-1" {
		t.Errorf("upstream saw %q", seen)
	}
	b, _ := json.Marshal(seen)
	if strings.Contains(string(b), "client-token") {
		t.Error("client token reached the upstream")
	}
}

func TestPinnedIssuer(t *testing.T) {
	a, b := newFakeAS(t), newFakeAS(t)
	a.PRMAuthSrv = b.URL // the upstream's PRM points elsewhere
	st := storeIn(t)
	o := loginOpts(a, st, t)
	o.Auth = contracts.UpstreamAuth{ClientID: "cid", Issuer: a.URL}
	o.Secret = "s3"
	if err := Login(t.Context(), o); err != nil {
		t.Fatal(err)
	}
	if n := b.Hits.Load(); n != 0 {
		t.Errorf("AS-B saw %d requests", n)
	}
	if got := a.LastBasic.Load(); got != "cid:s3" {
		t.Errorf("exchange basic auth %v", got)
	}
	tf, err := st.Load("docs")
	if err != nil {
		t.Fatal(err)
	}
	if tf.TokenEndpoint != a.URL+"/as/token" {
		t.Errorf("token endpoint %q", tf.TokenEndpoint)
	}
	tf.ExpiresAt = time.Now().Add(10 * time.Second).UTC().Format(time.RFC3339)
	seed(t, st, *tf)
	a.Seed(tf.RefreshToken)
	if _, err := apply(testCred(a.MCPURL(), st, "s3")); err != nil {
		t.Fatal(err)
	}
	if a.Refreshes.Load() != 1 || b.Hits.Load() != 0 {
		t.Errorf("refreshes at A %d, hits at B %d", a.Refreshes.Load(), b.Hits.Load())
	}
}

func TestPinnedIssuerWithoutPRM(t *testing.T) {
	f := newFakeAS(t)
	f.NoPRM = true
	st := storeIn(t)
	o := loginOpts(f, st, t)
	o.Auth = contracts.UpstreamAuth{Issuer: f.URL}
	if err := Login(t.Context(), o); err != nil {
		t.Fatal(err)
	}
	if tf, err := st.Load("docs"); err != nil || tf.Resource != f.MCPURL() {
		t.Errorf("%+v %v", tf, err)
	}
}

func TestIssuerMismatch(t *testing.T) {
	for _, pinned := range []bool{false, true} {
		f := newFakeAS(t)
		f.IssuerPath = "/tenantA"
		f.MetaPath = "/.well-known/openid-configuration"
		f.MetaIssuer = f.URL
		o := loginOpts(f, storeIn(t), t)
		if pinned {
			o.Auth.Issuer = f.URL + "/tenantA"
		}
		err := Login(t.Context(), o)
		if err == nil || !strings.Contains(err.Error(), "authorization server metadata is for "+f.URL+", not "+f.URL+"/tenantA") {
			t.Errorf("pinned=%v: %v", pinned, err)
		}
		if f.Authorizes.Load() != 0 {
			t.Errorf("pinned=%v: authorization endpoint reached", pinned)
		}
	}
	// A missing issuer is a mismatch.
	f := newFakeAS(t)
	f.MetaIssuer = "-"
	if err := Login(t.Context(), loginOpts(f, storeIn(t), t)); err == nil || !strings.Contains(err.Error(), "metadata is for -") {
		t.Errorf("%v", err)
	}
}

func TestIssuerTrailingSlash(t *testing.T) {
	f := newFakeAS(t)
	f.MetaIssuer = f.URL + "/" // metadata has the slash, the PRM does not
	if err := Login(t.Context(), loginOpts(f, storeIn(t), t)); err != nil {
		t.Errorf("metadata slash: %v", err)
	}
	g := newFakeAS(t)
	g.PRMAuthSrv = g.URL + "/" // the PRM has the slash, the metadata does not
	if err := Login(t.Context(), loginOpts(g, storeIn(t), t)); err != nil {
		t.Errorf("prm slash: %v", err)
	}
	h := newFakeAS(t)
	o := loginOpts(h, storeIn(t), t)
	o.Auth.Issuer = h.URL + "/"
	if err := Login(t.Context(), o); err != nil {
		t.Errorf("pinned slash: %v", err)
	}
}

func TestSecretNeedsIssuer(t *testing.T) {
	f := newFakeAS(t)
	o := loginOpts(f, storeIn(t), t)
	o.Secret = "s3"
	if err := Login(t.Context(), o); err == nil || err.Error() != "issuer is required with a client secret" {
		t.Errorf("%v", err)
	}
	if n := f.Hits.Load(); n != 0 {
		t.Errorf("fake saw %d requests", n)
	}
}

func testCred(url string, st *Store, secret string) contracts.UpstreamCredential {
	return NewCredential(CredentialOptions{Upstream: "docs", URL: url, Secret: secret, Store: st})
}
