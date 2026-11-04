package e2e

import (
	"bytes"
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
	"syscall"
	"testing"
	"time"

	"github.com/midspan-dev/agentgw/internal/harness"
	"github.com/midspan-dev/agentgw/pkg/contracts"
)

// recorder is an upstream front that captures every request's headers and
// reverse-proxies to the harness HTTP server.
type recorder struct {
	*httptest.Server
	path string
	mu   sync.Mutex
	hdrs []http.Header
}

func newRecorder(t *testing.T) *recorder {
	t.Helper()
	target := harness.StartServer(t, harness.Options{HTTP: true, Tools: harness.DefaultTools(t)})
	tu, err := url.Parse(target.URL)
	if err != nil {
		t.Fatal(err)
	}
	rp := &httputil.ReverseProxy{FlushInterval: -1, Director: func(r *http.Request) {
		r.URL.Scheme, r.URL.Host = tu.Scheme, tu.Host
	}}
	r := &recorder{path: tu.Path}
	r.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.mu.Lock()
		r.hdrs = append(r.hdrs, req.Header.Clone())
		r.mu.Unlock()
		rp.ServeHTTP(w, req)
	}))
	t.Cleanup(r.Close)
	return r
}

func (r *recorder) url() string { return r.URL + r.path }

func (r *recorder) seen() []http.Header {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]http.Header(nil), r.hdrs...)
}

// serveEnv starts `agentgw serve` with the given upstream map and extra env,
// and returns the gateway and its MCP endpoint once it listens.
func serveEnv(t *testing.T, upstream map[string]any, env ...string) (*gw, string) {
	t.Helper()
	addr := freeAddr(t)
	g := setup(t, upstream, addr, "10m")
	cmd := exec.Command(bin, "serve", "--config", g.cfg)
	cmd.Env = append(os.Environ(), env...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cmd.Process.Signal(syscall.SIGTERM)
		cmd.Wait()
	})
	for i := 0; ; i++ {
		c, err := net.Dial("tcp", addr)
		if err == nil {
			c.Close()
			break
		}
		if i == 100 {
			t.Fatalf("serve did not listen on %s\n%s", addr, stderr.String())
		}
		time.Sleep(50 * time.Millisecond)
	}
	return g, "http://" + addr + "/mcp"
}

// post sends one JSON-RPC message with the client's own Authorization and
// returns the response body and Mcp-Session-Id; an SSE body is reduced to its
// last data line.
func post(t *testing.T, url, session, body string) (string, string) {
	t.Helper()
	req, _ := http.NewRequest("POST", url, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Authorization", "Bearer client-token")
	if session != "" {
		req.Header.Set("Mcp-Session-Id", session)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	out := string(b)
	for _, l := range strings.Split(out, "\n") {
		if d, ok := strings.CutPrefix(l, "data: "); ok {
			out = d
		}
	}
	return out, resp.Header.Get("Mcp-Session-Id")
}

// echoCalls handshakes, then calls echo with n=1..count and returns each raw response.
func echoCalls(t *testing.T, url string, count int) []string {
	t.Helper()
	_, sid := post(t, url, "", `{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"raw","version":"1"}}}`)
	post(t, url, sid, `{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	var out []string
	for i := 1; i <= count; i++ {
		b, _ := post(t, url, sid, fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"tools/call","params":{"name":"echo","arguments":{"n":%d}}}`, i, i))
		out = append(out, b)
	}
	return out
}

func wantEchoes(t *testing.T, got []string) {
	t.Helper()
	for i, b := range got {
		var r struct {
			Result struct {
				IsError bool
				Content []struct{ Text string }
			}
		}
		if err := json.Unmarshal([]byte(b), &r); err != nil || r.Result.IsError || len(r.Result.Content) != 1 ||
			r.Result.Content[0].Text != fmt.Sprintf(`{"n":%d}`, i+1) {
			t.Fatalf("call %d: %v %s", i+1, err, b)
		}
	}
}

func TestE2EServeHeaderCredential(t *testing.T) {
	for _, src := range []string{"env", "file"} {
		t.Run(src, func(t *testing.T) {
			rec := newRecorder(t)
			auth := map[string]any{"kind": "header", "header": "X-Api-Key"}
			var env []string
			if src == "env" {
				auth["secret_env"] = "TEST_KEY"
				env = []string{"TEST_KEY=upstream-key"}
			} else {
				f := filepath.Join(t.TempDir(), "key")
				write(t, f, []byte("upstream-key\n"))
				auth["secret_file"] = f
			}
			g, url := serveEnv(t, map[string]any{"name": "harness", "url": rec.url(), "path": "/mcp", "auth": auth}, env...)
			wantEchoes(t, echoCalls(t, url, 5))
			seen := rec.seen()
			if len(seen) == 0 {
				t.Fatal("upstream saw no requests")
			}
			for i, h := range seen {
				if h.Get("X-Api-Key") != "upstream-key" || len(h.Values("Authorization")) != 0 {
					t.Fatalf("request %d headers: %v", i, h)
				}
			}
			g.check("allow")
		})
	}
}

func TestE2EServeClientCredentials(t *testing.T) {
	var fetches, status = 0, http.StatusOK
	var mu sync.Mutex
	tok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		fetches++
		if id, sec, ok := r.BasicAuth(); !ok || id != "id" || sec != "secret" {
			http.Error(w, "bad client auth", http.StatusUnauthorized)
			return
		}
		if status != http.StatusOK {
			http.Error(w, "down", status)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"access_token":"tok-1","token_type":"Bearer","expires_in":3600}`)
	}))
	defer tok.Close()
	up := func(rec *recorder) map[string]any {
		return map[string]any{"name": "harness", "url": rec.url(), "path": "/mcp", "auth": map[string]any{
			"kind": "client_credentials", "token_url": tok.URL, "client_id": "id", "secret_env": "TEST_SECRET"}}
	}

	rec := newRecorder(t)
	g, url := serveEnv(t, up(rec), "TEST_SECRET=secret")
	wantEchoes(t, echoCalls(t, url, 5))
	seen := rec.seen()
	if len(seen) == 0 {
		t.Fatal("upstream saw no requests")
	}
	for i, h := range seen {
		if h.Get("Authorization") != "Bearer tok-1" || len(h.Values("Authorization")) != 1 {
			t.Fatalf("request %d headers: %v", i, h)
		}
	}
	mu.Lock()
	if fetches != 1 {
		t.Fatalf("token endpoint hit %d times, want 1", fetches)
	}
	status = http.StatusInternalServerError
	mu.Unlock()
	g.check("allow")

	// Second gateway, token endpoint failing: fail closed.
	rec2 := newRecorder(t)
	g2, url2 := serveEnv(t, up(rec2), "TEST_SECRET=secret")
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{"n":1}}}`
	got, _ := post(t, url2, "", body)
	if !strings.Contains(got, `"error"`) || strings.Contains(got, `"result"`) {
		t.Fatalf("want JSON-RPC error, got %s", got)
	}
	if !strings.Contains(got, "token endpoint") {
		t.Fatalf("error does not name the token endpoint: %s", got)
	}
	mu.Lock()
	if fetches != 2 {
		t.Fatalf("token endpoint hit %d times, want 2", fetches)
	}
	mu.Unlock()
	if n := len(rec2.seen()); n != 0 {
		t.Fatalf("upstream saw %d requests, want 0", n)
	}
	if es := g2.entries(); len(es) != 1 || es[0].Outcome != contracts.EntryError {
		t.Fatalf("want exactly one error entry, got %+v", es)
	}
	if out := g2.cli("verify"); !strings.HasPrefix(out, "ok: ") {
		t.Fatalf("verify: %q", out)
	}
}

func TestE2EServeAuthSecretUnset(t *testing.T) {
	addr := freeAddr(t)
	g := setup(t, map[string]any{"name": "harness", "url": "http://127.0.0.1:1/mcp", "path": "/mcp",
		"auth": map[string]any{"kind": "header", "header": "X-Api-Key", "secret_env": "TEST_UNSET_KEY"}}, addr, "10m")
	cmd := exec.Command(bin, "serve", "--config", g.cfg)
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "TEST_UNSET_KEY=") {
			cmd.Env = append(cmd.Env, kv)
		}
	}
	out, err := cmd.CombinedOutput()
	if err == nil || !strings.Contains(string(out), "TEST_UNSET_KEY") || !strings.Contains(string(out), "upstream harness: ") {
		t.Fatalf("want non-zero exit naming TEST_UNSET_KEY, got %v %s", err, out)
	}
	if c, err := net.Dial("tcp", addr); err == nil {
		c.Close()
		t.Fatal("gateway listened")
	}
}
