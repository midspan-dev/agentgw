package oauth

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	neturl "net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/midspan-dev/agentgw/internal/harness"
	"github.com/midspan-dev/agentgw/internal/proxy"
	"github.com/midspan-dev/agentgw/pkg/contracts"
)

func tfFor(f *fakeAS, resource, issuer string, exp time.Duration) contracts.TokenFile {
	tf := seedFor(f, exp)
	tf.Resource, tf.Issuer = resource, issuer
	return tf
}

func loginRequired(err error) bool {
	return err != nil && err.Error() == "upstream docs: login required: run agentgw login docs"
}

func TestBindingURLChanged(t *testing.T) {
	f := newFakeAS(t)
	st := storeIn(t)
	seed(t, st, tfFor(f, "https://a.example/mcp", f.issuer(), -time.Hour))
	before, _ := os.ReadFile(st.Path)
	c := testCred("https://b.example/mcp", st, "")
	if _, err := apply(c); !loginRequired(err) {
		t.Fatalf("%v", err)
	}
	if n := f.Hits.Load(); n != 0 {
		t.Errorf("token endpoint saw %d requests", n)
	}
	if after, _ := os.ReadFile(st.Path); !bytes.Equal(before, after) {
		t.Error("file changed")
	}
	// A new login while serving is picked up without restart.
	seed(t, st, tfFor(f, "https://b.example/mcp", f.issuer(), time.Hour))
	later := time.Now().Add(time.Minute)
	os.Chtimes(st.Path, later, later)
	if got, err := apply(c); err != nil || got != "Bearer at-seed" {
		t.Fatalf("%q %v", got, err)
	}
}

func TestBindingSharedPath(t *testing.T) {
	f := newFakeAS(t)
	st := storeIn(t)
	seed(t, st, tfFor(f, "https://a.example/mcp", f.issuer(), time.Hour))
	if _, err := apply(testCred("https://a.example/mcp", st, "")); err != nil {
		t.Errorf("first: %v", err)
	}
	if _, err := apply(testCred("https://b.example/mcp", st, "")); !loginRequired(err) {
		t.Errorf("second: %v", err)
	}
}

func TestBindingPathRule(t *testing.T) {
	f := newFakeAS(t)
	cases := []struct {
		resource, url, authRes string
		ok                     bool
	}{
		{"https://a.example", "https://a.example/mcp", "", true},
		{"https://a.example", "https://a.example/", "", true},
		{"https://a.example/mcp", "https://a.example/mcp/v2", "", true},
		{"https://a.example/mcp", "https://a.example/mcpx", "", false},
		{"https://a.example/mcp", "https://a.example:8443/mcp", "", false},
		{"https://a.example/mcp", "https://a.example/mcp", "https://a.example/other", false},
		{"https://a.example/other", "https://a.example/mcp", "https://a.example/other", true},
	}
	for _, c := range cases {
		st := storeIn(t)
		seed(t, st, tfFor(f, c.resource, f.issuer(), time.Hour))
		cr := NewCredential(CredentialOptions{Upstream: "docs", URL: c.url, Auth: contracts.UpstreamAuth{Resource: c.authRes}, Store: st})
		_, err := apply(cr)
		if c.ok != (err == nil) || (!c.ok && !loginRequired(err)) {
			t.Errorf("%+v: %v", c, err)
		}
	}
}

func TestBindingIssuer(t *testing.T) {
	cases := []struct {
		pinned, issuer string
		ok             bool
	}{
		{"https://as-a.example", "https://as-b.example", false},
		{"https://as-a.example", "https://as-a.example", true},
		{"https://as-a.example/", "https://as-a.example", true},
		{"https://as-a.example", "https://as-a.example/", true},
		{"", "https://as-b.example", true},
	}
	for _, c := range cases {
		f := newFakeAS(t) // fresh per case: the fake answers invalid_grant to a reused refresh token
		st := storeIn(t)
		before := f.Hits.Load()
		seed(t, st, tfFor(f, f.MCPURL(), c.issuer, -time.Hour)) // expired: a passing file refreshes at the fake
		cr := NewCredential(CredentialOptions{Upstream: "docs", URL: f.MCPURL(), Auth: contracts.UpstreamAuth{Issuer: c.pinned}, Store: st})
		_, err := apply(cr)
		if c.ok && err != nil || !c.ok && !loginRequired(err) {
			t.Errorf("%+v: %v", c, err)
		}
		if !c.ok && f.Hits.Load() != before {
			t.Errorf("%+v: token endpoint contacted", c)
		}
	}
}

func TestBindingClientID(t *testing.T) {
	cases := []struct {
		configured string
		ok         bool
	}{
		{"", true},
		{"dcr-client", true},
		{"replacement", false},
	}
	for _, exp := range []time.Duration{time.Hour, -time.Hour} { // fresh, then a token that must refresh
		for _, c := range cases {
			f := newFakeAS(t)
			st := storeIn(t)
			seed(t, st, seedFor(f, exp))
			before := f.Hits.Load()
			cr := NewCredential(CredentialOptions{Upstream: "docs", URL: f.MCPURL(), Auth: contracts.UpstreamAuth{ClientID: c.configured}, Store: st})
			got, err := apply(cr)
			if c.ok && (err != nil || got == "") || !c.ok && (!loginRequired(err) || got != "") {
				t.Errorf("exp %v, %+v: %q %v", exp, c, got, err)
			}
			if !c.ok && f.Hits.Load() != before {
				t.Errorf("exp %v, %+v: token endpoint contacted", exp, c)
			}
		}
	}
}

func TestBindingLoginRoundTrip(t *testing.T) {
	f := newFakeAS(t)
	st := storeIn(t)
	if err := Login(t.Context(), loginOpts(f, st, t)); err != nil {
		t.Fatal(err)
	}
	tf, err := st.Load("docs")
	if err != nil || tf.Issuer != f.issuer() {
		t.Fatalf("%+v %v", tf, err)
	}
	cr := NewCredential(CredentialOptions{Upstream: "docs", URL: f.MCPURL(), Auth: contracts.UpstreamAuth{Issuer: f.issuer()}, Store: st})
	if got, err := apply(cr); err != nil || got != "Bearer at-1" {
		t.Fatalf("%q %v", got, err)
	}
}

func TestLoadRefusesNoIssuer(t *testing.T) {
	st := storeIn(t)
	os.MkdirAll(filepath.Dir(st.Path), 0o700)
	os.WriteFile(st.Path, []byte(`{"version":"1","upstream":"docs"}`), 0o600)
	if _, err := st.Load("docs"); err == nil {
		t.Error("Load accepted a file without issuer")
	}
	b, _ := json.Marshal(map[string]string{"version": "1", "upstream": "docs", "issuer": "https://x"})
	os.WriteFile(st.Path, b, 0o600)
	if _, err := st.Load("docs"); err != nil {
		t.Error(err)
	}
}

// The refresh path checks the raw file, which Store.Load has not vetted.
func TestBindingRefusesNoIssuer(t *testing.T) {
	cr := NewCredential(CredentialOptions{Upstream: "docs", URL: "https://a.example/mcp", Store: storeIn(t)}).(*credential)
	if cr.bound(&contracts.TokenFile{Upstream: "docs", Resource: "https://a.example/mcp"}) {
		t.Error("bound accepted a file without issuer")
	}
}

// A client registered with one authorization server is never offered to another.
func TestLoginNewIssuerRegistersAgain(t *testing.T) {
	f := newFakeAS(t)
	st := storeIn(t)
	old := tfFor(f, f.MCPURL(), "https://as-old.example", time.Hour)
	old.ClientID, old.ClientSecret = "old-client", "old-secret"
	seed(t, st, old)
	if err := Login(t.Context(), loginOpts(f, st, t)); err != nil {
		t.Fatal(err)
	}
	if n := f.Registrations.Load(); n != 1 {
		t.Errorf("registrations = %d", n)
	}
	if b, _ := f.LastBasic.Load().(string); strings.Contains(b, "old-") {
		t.Errorf("old client sent to the new issuer: %q", b)
	}
	if tf, err := st.Load("docs"); err != nil || tf.ClientID != "dcr-client" || tf.Issuer != f.issuer() {
		t.Errorf("%+v %v", tf, err)
	}
}

// A route whose credential URL differs from the file's resource never reaches the upstream.
func TestE2EOAuthBindingThroughProxy(t *testing.T) {
	f := newFakeAS(t)
	st := storeIn(t)
	seed(t, st, seedFor(f, time.Hour))
	up := harness.StartServer(t, harness.Options{HTTP: true, Tools: harness.DefaultTools(t)})
	target, _ := neturl.Parse(up.URL)
	var n atomic.Int64
	rp := httputil.NewSingleHostReverseProxy(target)
	rec := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { n.Add(1); rp.ServeHTTP(w, r) }))
	t.Cleanup(rec.Close)

	addr := freeAddr(t)
	cred := testCred("https://elsewhere.example/mcp", st, "")
	go proxy.HTTP(t.Context(), addr, []proxy.Route{{Name: "docs", Path: "/mcp/docs", URL: rec.URL, Credential: cred}}, passthrough{})
	waitFor(t, addr)

	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"x","arguments":{},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{},"io.modelcontextprotocol/clientInfo":{"name":"x","version":"0"}}}}`
	req, _ := http.NewRequestWithContext(t.Context(), "POST", "http://"+addr+"/mcp/docs", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Mcp-Protocol-Version", "2026-07-28")
	req.Header.Set("Mcp-Method", "tools/call")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(b), `"error"`) || !strings.Contains(string(b), "run agentgw login") {
		t.Errorf("reply: %s", b)
	}
	if n.Load() != 0 {
		t.Errorf("upstream saw %d requests", n.Load())
	}
}
