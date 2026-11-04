package proxy_test

// Gateway-held upstream credentials (docs/adr/0012): the client's
// Authorization never reaches the upstream, on passthrough or held calls.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	neturl "net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/midspan-dev/agentgw/internal/harness"
	"github.com/midspan-dev/agentgw/internal/proxy"
	"github.com/midspan-dev/agentgw/internal/proxy/httpcreds"
	"github.com/midspan-dev/agentgw/pkg/contracts"
)

// recordingUpstream captures the headers of every request and forwards to the harness server.
type recordingUpstream struct {
	*httptest.Server
	mu      sync.Mutex
	headers []http.Header
}

func newRecordingUpstream(t *testing.T) *recordingUpstream {
	up := harness.StartServer(t, harness.Options{HTTP: true, Tools: harness.DefaultTools(t)})
	target, _ := neturl.Parse(up.URL)
	r := &recordingUpstream{}
	rp := httputil.NewSingleHostReverseProxy(target)
	r.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.mu.Lock()
		r.headers = append(r.headers, req.Header.Clone())
		r.mu.Unlock()
		rp.ServeHTTP(w, req)
	}))
	t.Cleanup(r.Close)
	return r
}

func (r *recordingUpstream) seen() []http.Header {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]http.Header(nil), r.headers...)
}

func credProxy(t *testing.T, upURL string, c contracts.UpstreamCredential) string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	go proxy.HTTP(t.Context(), addr, []proxy.Route{{Name: "up", Path: "/mcp/up", URL: upURL, Credential: c}}, &fn{f: pass})
	for range 100 {
		if c, err := net.Dial("tcp", addr); err == nil {
			c.Close()
			return "http://" + addr + "/mcp/up"
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("proxy did not start")
	return ""
}

// credCall posts body with two client Authorization values under mixed-case names, written as given.
func credCall(t *testing.T, url, body string) (int, http.Header, string) {
	req, _ := http.NewRequestWithContext(t.Context(), "POST", url, strings.NewReader(body))
	req.Header = http.Header{
		"Content-Type": {"application/json"}, "Accept": {"application/json, text/event-stream"},
		"Mcp-Protocol-Version": {"2026-07-28"},
		"Authorization":        {"Bearer client-token"}, "authorization": {"dup"},
	}
	req.Header.Set("Mcp-Method", "tools/list")
	if strings.Contains(body, "tools/call") {
		req.Header.Set("Mcp-Method", "tools/call")
		req.Header.Set("Mcp-Name", "echo")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, resp.Header, string(b)
}

const (
	listBody = `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{` + meta + `}}`
	callBody = `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"echo","arguments":{"a":1},` + meta + `}}`
)

// wantOnlyAuth checks every upstream request carried exactly one Authorization, equal to want.
func wantOnlyAuth(t *testing.T, up *recordingUpstream, n int, want string) {
	t.Helper()
	got := up.seen()
	if len(got) != n {
		t.Fatalf("upstream saw %d requests, want %d", len(got), n)
	}
	for i, h := range got {
		var all []string
		for k, v := range h {
			if strings.EqualFold(k, "authorization") {
				all = append(all, v...)
			}
		}
		if len(all) != 1 || all[0] != want {
			t.Errorf("request %d: Authorization values %q, want only %q", i, all, want)
		}
	}
}

func TestE2EHeaderCredential(t *testing.T) {
	t.Setenv("UP_KEY", "upstream-key")
	cred, err := httpcreds.New(contracts.UpstreamAuth{Kind: "header", Header: "Authorization", Prefix: "Bearer ", SecretEnv: "UP_KEY"})
	if err != nil {
		t.Fatal(err)
	}
	up := newRecordingUpstream(t)
	// A spy in front of the gateway proves the client really sent both Authorization values.
	gw := credProxy(t, up.URL, cred)
	gwURL, _ := neturl.Parse(gw)
	var inbound atomic.Int64
	spy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := 0
		for k, v := range r.Header {
			if strings.EqualFold(k, "authorization") {
				n += len(v)
			}
		}
		if n == 2 {
			inbound.Add(1)
		}
		httputil.NewSingleHostReverseProxy(&neturl.URL{Scheme: "http", Host: gwURL.Host}).ServeHTTP(w, r)
	}))
	t.Cleanup(spy.Close)
	url := spy.URL + gwURL.Path
	_, h1, b1 := credCall(t, url, listBody)
	_, h2, b2 := credCall(t, url, callBody)
	if !strings.Contains(b1, `"tools"`) || !strings.Contains(b2, `"result"`) {
		t.Fatalf("calls failed: %s | %s", b1, b2)
	}
	if inbound.Load() != 2 {
		t.Errorf("two client Authorization values seen on %d of 2 requests", inbound.Load())
	}
	wantOnlyAuth(t, up, 2, "Bearer upstream-key")
	for _, h := range up.seen() {
		if strings.Contains(strings.Join(h.Values("Authorization"), ","), "client-token") {
			t.Error("client token reached the upstream")
		}
	}
	for _, s := range []string{b1, b2, strings.Join(h1.Values("Authorization"), ""), strings.Join(h2.Values("Authorization"), "")} {
		if strings.Contains(s, "upstream-key") || strings.Contains(s, "client-token") {
			t.Errorf("credential in client response: %s", s)
		}
	}
}

// A client must not be able to name the credential as hop-by-hop and have the proxy strip it.
func TestCredentialSurvivesConnectionHeader(t *testing.T) {
	t.Setenv("UP_KEY", "upstream-key")
	for _, c := range []struct{ name, header, prefix, want, method, body, connection string }{
		{"list", "Authorization", "Bearer ", "Bearer upstream-key", "POST", listBody, "Authorization"},
		{"list custom header", "X-Api-Key", "", "upstream-key", "POST", listBody, "X-Api-Key"},
		{"list among others", "Authorization", "Bearer ", "Bearer upstream-key", "POST", listBody, "keep-alive, X-Hop , authorization"},
		{"call", "Authorization", "Bearer ", "Bearer upstream-key", "POST", callBody, "Authorization, X-Hop"},
		{"stream", "Authorization", "Bearer ", "Bearer upstream-key", "GET", "", "Authorization"},
		{"delete", "Authorization", "Bearer ", "Bearer upstream-key", "DELETE", "", "Authorization"},
	} {
		t.Run(c.name, func(t *testing.T) {
			cred, err := httpcreds.New(contracts.UpstreamAuth{Kind: "header", Header: c.header, Prefix: c.prefix, SecretEnv: "UP_KEY"})
			if err != nil {
				t.Fatal(err)
			}
			up := newRecordingUpstream(t)
			req, _ := http.NewRequestWithContext(t.Context(), c.method, credProxy(t, up.URL, cred), strings.NewReader(c.body))
			req.Header = http.Header{
				"Content-Type": {"application/json"}, "Accept": {"application/json, text/event-stream"},
				"Mcp-Protocol-Version": {"2026-07-28"}, "Connection": {c.connection}, "X-Hop": {"client"},
			}
			if strings.Contains(c.body, "tools/call") {
				req.Header.Set("Mcp-Method", "tools/call")
				req.Header.Set("Mcp-Name", "echo")
			} else if c.body != "" {
				req.Header.Set("Mcp-Method", "tools/list")
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			seen := up.seen()
			if len(seen) == 0 {
				t.Fatalf("nothing reached the upstream (status %d)", resp.StatusCode)
			}
			for _, h := range seen {
				if got := h.Get(c.header); got != c.want {
					t.Errorf("%s = %q, want %q", c.header, got, c.want)
				}
				if got := h.Get("Connection"); got != "" {
					t.Errorf("Connection forwarded: %q", got)
				}
				if strings.Contains(c.connection, "X-Hop") && h.Get("X-Hop") != "" {
					t.Error("a header named by Connection was forwarded")
				}
			}
		})
	}
}

func TestE2EClientCredentialsCredential(t *testing.T) {
	var fetches atomic.Int64
	status := atomic.Int64{}
	status.Store(200)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetches.Add(1)
		w.WriteHeader(int(status.Load()))
		w.Write([]byte(`{"access_token":"minted","token_type":"Bearer","expires_in":3600}`))
	}))
	t.Cleanup(ts.Close)
	t.Setenv("CS", "shh")
	auth := contracts.UpstreamAuth{Kind: "client_credentials", TokenURL: ts.URL, ClientID: "id", SecretEnv: "CS"}
	cred, err := httpcreds.New(auth)
	if err != nil {
		t.Fatal(err)
	}
	up := newRecordingUpstream(t)
	url := credProxy(t, up.URL, cred)
	credCall(t, url, listBody)
	_, _, b := credCall(t, url, callBody)
	if !strings.Contains(b, `"result"`) || fetches.Load() != 1 {
		t.Fatalf("fetches=%d body=%s", fetches.Load(), b)
	}
	wantOnlyAuth(t, up, 2, "Bearer minted")

	// A failing token endpoint fails the held call closed: nothing reaches the upstream.
	status.Store(500)
	cred, _ = httpcreds.New(auth)
	up2 := newRecordingUpstream(t)
	_, _, b = credCall(t, credProxy(t, up2.URL, cred), callBody)
	for _, leak := range []string{"shh", "id:shh", base64.StdEncoding.EncodeToString([]byte("id:shh"))} {
		if strings.Contains(b, leak) {
			t.Errorf("response leaks %q: %s", leak, b)
		}
	}
	if !strings.Contains(b, `"error"`) || len(up2.seen()) != 0 {
		t.Errorf("body=%s upstream saw %d", b, len(up2.seen()))
	}
	// Passthrough fails closed with 502.
	code, _, b := credCall(t, credProxy(t, up2.URL, cred), listBody)
	if code != http.StatusBadGateway || !strings.Contains(b, `"code":-32603`) || len(up2.seen()) != 0 {
		t.Errorf("passthrough: %d %s, upstream saw %d", code, b, len(up2.seen()))
	}
}

// A credentialed upstream that redirects still gets no second request.
func TestHTTPCredentialRedirectNotFollowed(t *testing.T) {
	var hits atomic.Int64
	elsewhere := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	t.Cleanup(elsewhere.Close)
	front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, elsewhere.URL, http.StatusTemporaryRedirect)
	}))
	t.Cleanup(front.Close)
	t.Setenv("UP_KEY", "upstream-key")
	cred, _ := httpcreds.New(contracts.UpstreamAuth{Kind: "header", Header: "Authorization", SecretEnv: "UP_KEY"})
	url := credProxy(t, front.URL, cred)
	credCall(t, url, callBody)
	credCall(t, url, listBody)
	if hits.Load() != 0 {
		t.Errorf("redirect followed with credentials: %d hits", hits.Load())
	}
}

// A token fetch must not count as the upstream write beginning: a refused upstream is still not-sent.
func TestHTTPCredentialDialFailureIsNotSent(t *testing.T) {
	var fetches atomic.Int64
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetches.Add(1)
		w.Write([]byte(`{"access_token":"minted","token_type":"bearer"}`))
	}))
	t.Cleanup(ts.Close)
	t.Setenv("CS", "shh")
	cred, err := httpcreds.New(contracts.UpstreamAuth{Kind: "client_credentials", TokenURL: ts.URL, ClientID: "id", SecretEnv: "CS"})
	if err != nil {
		t.Fatal(err)
	}
	closed := httptest.NewServer(http.NotFoundHandler())
	closed.Close() // connection refused
	var got error
	rec := &fn{f: func(ctx context.Context, c *contracts.Call) (json.RawMessage, error) {
		_, got = c.Forward(ctx)
		return nil, &contracts.CallError{Err: contracts.ErrDenied}
	}}
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := ln.Addr().String()
	ln.Close()
	go proxy.HTTP(t.Context(), addr, []proxy.Route{{Name: "up", Path: "/mcp/up", URL: closed.URL, Credential: cred}}, rec)
	for range 100 {
		if c, err := net.Dial("tcp", addr); err == nil {
			c.Close()
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	credCall(t, "http://"+addr+"/mcp/up", callBody)
	if fetches.Load() != 1 || !errors.Is(got, contracts.ErrNotSent) {
		t.Errorf("fetches=%d err=%v, want one fetch and ErrNotSent", fetches.Load(), got)
	}
}
