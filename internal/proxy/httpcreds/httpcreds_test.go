package httpcreds

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/midspan-dev/agentgw/pkg/contracts"
)

func apply(t *testing.T, c contracts.UpstreamCredential) (http.Header, error) {
	h := http.Header{"Authorization": {"Bearer client"}}
	err := c.Apply(t.Context(), h)
	return h, err
}

func TestHeaderKind(t *testing.T) {
	t.Setenv("K", "sekret")
	c, err := New(contracts.UpstreamAuth{Kind: "header", Header: "X-Api-Key", SecretEnv: "K"})
	if err != nil {
		t.Fatal(err)
	}
	if h, _ := apply(t, c); h.Get("X-Api-Key") != "sekret" {
		t.Errorf("env: %v", h)
	}
	f := filepath.Join(t.TempDir(), "s")
	os.WriteFile(f, []byte("filekey\n"), 0o600)
	c, err = New(contracts.UpstreamAuth{Kind: "header", Header: "Authorization", Prefix: "Bearer ", SecretFile: f})
	if err != nil {
		t.Fatal(err)
	}
	if h, _ := apply(t, c); h.Get("Authorization") != "Bearer filekey" || len(h.Values("Authorization")) != 1 {
		t.Errorf("file: %v", h)
	}
}

func TestNewErrors(t *testing.T) {
	_, err := New(contracts.UpstreamAuth{Kind: "header", Header: "H", SecretEnv: "AGW_UNSET_VAR"})
	if err == nil || !strings.Contains(err.Error(), "AGW_UNSET_VAR") {
		t.Errorf("env: %v", err)
	}
	_, err = New(contracts.UpstreamAuth{Kind: "header", Header: "H", SecretFile: "/nonexistent/secret"})
	if err == nil || !strings.Contains(err.Error(), "/nonexistent/secret") {
		t.Errorf("file: %v", err)
	}
	empty := filepath.Join(t.TempDir(), "e")
	os.WriteFile(empty, nil, 0o600)
	if _, err = New(contracts.UpstreamAuth{Kind: "header", Header: "H", SecretFile: empty}); err == nil {
		t.Error("empty file accepted")
	}
}

type tokenSrv struct {
	*httptest.Server
	hits           atomic.Int64
	user, pass     string
	form           url.Values
	accept, ctype  string
	status         int
	body, location string
}

func newTokenSrv(t *testing.T, body string) *tokenSrv {
	ts := &tokenSrv{status: 200, body: body}
	ts.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ts.hits.Add(1)
		ts.user, ts.pass, _ = r.BasicAuth()
		r.ParseForm()
		ts.form, ts.accept, ts.ctype = r.PostForm, r.Header.Get("Accept"), r.Header.Get("Content-Type")
		if ts.location != "" {
			http.Redirect(w, r, ts.location, http.StatusFound)
			return
		}
		w.WriteHeader(ts.status)
		w.Write([]byte(ts.body))
	}))
	t.Cleanup(ts.Close)
	return ts
}

func cc(t *testing.T, ts *tokenSrv, mod func(*contracts.UpstreamAuth)) contracts.UpstreamCredential {
	t.Setenv("CS", "s3cr&t")
	a := contracts.UpstreamAuth{Kind: "client_credentials", TokenURL: ts.URL, ClientID: "id 1", SecretEnv: "CS"}
	if mod != nil {
		mod(&a)
	}
	c, err := New(a)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestClientCredentialsRequestAndCache(t *testing.T) {
	ts := newTokenSrv(t, `{"access_token":"tok","token_type":"Bearer","expires_in":3600}`)
	c := cc(t, ts, func(a *contracts.UpstreamAuth) { a.Scopes = []string{"a", "b"}; a.Resource = "https://r" })
	for range 3 {
		h, err := apply(t, c)
		if err != nil || h.Get("Authorization") != "Bearer tok" {
			t.Fatal(h, err)
		}
	}
	if ts.hits.Load() != 1 {
		t.Errorf("%d fetches", ts.hits.Load())
	}
	if ts.user != "id+1" || ts.pass != "s3cr%26t" || ts.accept != "application/json" || ts.ctype != "application/x-www-form-urlencoded" {
		t.Errorf("auth %q %q %q %q", ts.user, ts.pass, ts.accept, ts.ctype)
	}
	if ts.form.Get("grant_type") != "client_credentials" || ts.form.Get("scope") != "a b" || ts.form.Get("resource") != "https://r" {
		t.Errorf("form %v", ts.form)
	}
	ts2 := newTokenSrv(t, `{"access_token":"tok","token_type":"bearer"}`)
	apply(t, cc(t, ts2, nil))
	if _, ok := ts2.form["scope"]; ok {
		t.Errorf("scope sent unset: %v", ts2.form)
	}
	if _, ok := ts2.form["resource"]; ok {
		t.Errorf("resource sent unset: %v", ts2.form)
	}
	// No expires_in: never cached.
	apply(t, cc(t, ts2, nil))
	if ts2.hits.Load() != 2 {
		t.Errorf("no-expiry token cached? %d fetches", ts2.hits.Load())
	}
}

func TestClientCredentialsExpiry(t *testing.T) {
	ts := newTokenSrv(t, `{"access_token":"tok","token_type":"bearer","expires_in":1}`)
	c := cc(t, ts, nil)
	apply(t, c)
	apply(t, c)
	if ts.hits.Load() != 1 {
		t.Fatalf("%d fetches before expiry", ts.hits.Load())
	}
	// expires_in/2 = 500ms margin: past 500ms a refetch is due.
	time.Sleep(600 * time.Millisecond)
	apply(t, c)
	if ts.hits.Load() != 2 {
		t.Errorf("%d fetches after expiry", ts.hits.Load())
	}
}

func TestClientCredentialsErrors(t *testing.T) {
	for name, tc := range map[string]struct {
		status int
		body   string
	}{
		"500":       {500, `{"error":"server_error"}`},
		"echo":      {401, `{"error":"bad secret s3cr&t for id+1:s3cr%26t"}`},
		"not json":  {200, `<html>`},
		"no token":  {200, `{"token_type":"bearer"}`},
		"mac":       {200, `{"access_token":"tok","token_type":"mac"}`},
		"empty tok": {200, `{"access_token":"","token_type":"bearer"}`},
	} {
		t.Run(name, func(t *testing.T) {
			ts := newTokenSrv(t, tc.body)
			ts.status = tc.status
			_, err := apply(t, cc(t, ts, nil))
			if err == nil {
				t.Fatal("no error")
			}
			for _, leak := range []string{"s3cr&t", "s3cr%26t", "id+1:s3cr%26t", base64.StdEncoding.EncodeToString([]byte("id+1:s3cr%26t"))} {
				if strings.Contains(err.Error(), leak) {
					t.Errorf("err leaks %q: %v", leak, err)
				}
			}
			if name == "500" && err.Error() != "token endpoint: HTTP 500: server_error" {
				t.Errorf("err = %v", err)
			}
			if name == "echo" && err.Error() != "token endpoint: HTTP 401" {
				t.Errorf("err = %v", err)
			}
		})
	}
}

func TestClientCredentialsRedirectRefused(t *testing.T) {
	var hits atomic.Int64
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
	t.Cleanup(target.Close)
	ts := newTokenSrv(t, "")
	ts.location = target.URL
	if _, err := apply(t, cc(t, ts, nil)); err == nil {
		t.Error("redirect accepted")
	}
	if hits.Load() != 0 {
		t.Error("redirect followed")
	}
}
