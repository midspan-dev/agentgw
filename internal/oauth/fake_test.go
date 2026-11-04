package oauth

// fakeAS is one httptest server that is both the protected resource (/mcp)
// and its authorization server. The oauth-wiring node copies this file.

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type fakeAS struct {
	*httptest.Server

	// Knobs, set before use.
	Challenge    bool          // PRM via the 401 challenge (else the well-known path)
	Scope        string        // challenge scope="..."
	IssuerPath   string        // authorization server issuer path, e.g. "/tenant"
	MetaPath     string        // where AS metadata is served; default oauth-authorization-server + IssuerPath
	Methods      []string      // code_challenge_methods_supported; nil omits the field
	AuthURLOver  string        // authorization_endpoint override
	NoReg        bool          // omit registration_endpoint
	RegSecret    string        // client_secret issued by registration
	ExpiresIn    int           // seconds; default 3600
	PRMResource  string        // PRM resource override; default the MCP URL
	ExpectRes    string        // resource the fake requires; default PRMResource, else the MCP URL
	RefreshDelay time.Duration // delays the refresh reply (the rotation still happens)
	GotVerifier  atomic.Value  // code_verifier of the last authorization_code exchange
	GotCode      atomic.Value
	BadChall     bool   // authorize stores a wrong challenge, so the exchange fails
	WrongState   bool   // authorize redirects back with a different state
	DenyWith     string // authorize redirects back with error=<DenyWith>
	PRMAuthSrv   string // PRM authorization_servers[0] override; default the issuer
	MetaIssuer   string // metadata issuer override; default the issuer
	NoPRM        bool   // /mcp answers 200 and no PRM is served

	Hits          atomic.Int64 // every request
	Authorizes    atomic.Int64 // requests to the authorization endpoint
	Registrations atomic.Int64
	CodeGrants    atomic.Int64
	Refreshes     atomic.Int64
	InvalidGrants atomic.Int64
	LastBasic     atomic.Value // string "id:secret" of the last token request, "" without Basic

	mu      sync.Mutex
	codes   map[string]codeInfo
	cur     string          // current refresh token
	old     map[string]bool // rotated-away refresh tokens
	revoked bool
	n       int
}

type codeInfo struct{ challenge, redirect, clientID string }

func newFakeAS(t *testing.T) *fakeAS {
	f := &fakeAS{codes: map[string]codeInfo{}, old: map[string]bool{}}
	f.Server = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.Close)
	return f
}

func (f *fakeAS) MCPURL() string { return f.URL + "/mcp" }

// Seed sets the refresh token the fake accepts.
func (f *fakeAS) Seed(rt string) { f.mu.Lock(); f.cur = rt; f.mu.Unlock() }

// Revoke makes every refresh answer invalid_grant.
func (f *fakeAS) Revoke() { f.mu.Lock(); f.revoked = true; f.mu.Unlock() }

func (f *fakeAS) prmResource() string {
	if f.PRMResource != "" {
		return f.PRMResource
	}
	return f.MCPURL()
}

func (f *fakeAS) res() string {
	if f.ExpectRes != "" {
		return f.ExpectRes
	}
	return f.prmResource()
}

func (f *fakeAS) issuer() string { return f.URL + f.IssuerPath }

func (f *fakeAS) serve(w http.ResponseWriter, r *http.Request) {
	js := func(v any) { w.Header().Set("Content-Type", "application/json"); json.NewEncoder(w).Encode(v) }
	f.Hits.Add(1)
	switch p := r.URL.Path; {
	case p == "/mcp":
		if f.NoPRM {
			return
		}
		if f.Challenge {
			c := `Bearer resource_metadata="` + f.URL + `/prm-custom"`
			if f.Scope != "" {
				c += `, scope="` + f.Scope + `"`
			}
			w.Header().Set("WWW-Authenticate", c)
		}
		w.WriteHeader(401)
	case f.NoPRM && (p == "/prm-custom" || p == "/.well-known/oauth-protected-resource/mcp" || p == "/.well-known/oauth-protected-resource"):
		http.NotFound(w, r)
	case (p == "/prm-custom" && f.Challenge) || (p == "/.well-known/oauth-protected-resource/mcp" && !f.Challenge):
		js(map[string]any{"resource": f.prmResource(), "authorization_servers": []string{firstNonEmpty(f.PRMAuthSrv, f.issuer())}, "scopes_supported": []string{"read", "write"}})
	case p == f.metaPath():
		m := map[string]any{"issuer": firstNonEmpty(f.MetaIssuer, f.issuer()), "authorization_endpoint": f.URL + "/as/authorize", "token_endpoint": f.URL + "/as/token"}
		if f.AuthURLOver != "" {
			m["authorization_endpoint"] = f.AuthURLOver
		}
		if !f.NoReg {
			m["registration_endpoint"] = f.URL + "/as/register"
		}
		if f.Methods != nil {
			m["code_challenge_methods_supported"] = f.Methods
		}
		js(m)
	case p == "/as/register":
		f.Registrations.Add(1)
		var req struct {
			Redirects []string `json:"redirect_uris"`
			Auth      string   `json:"token_endpoint_auth_method"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		if len(req.Redirects) != 1 || req.Auth != "none" {
			http.Error(w, "bad", 400)
			return
		}
		w.WriteHeader(201)
		js(map[string]any{"client_id": "dcr-client", "client_secret": f.RegSecret})
	case p == "/as/authorize":
		f.authorize(w, r)
	case p == "/as/token":
		f.token(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (f *fakeAS) metaPath() string {
	if f.MetaPath != "" {
		return f.MetaPath
	}
	return "/.well-known/oauth-authorization-server" + f.IssuerPath
}

func (f *fakeAS) authorize(w http.ResponseWriter, r *http.Request) {
	f.Authorizes.Add(1)
	q := r.URL.Query()
	redir, err := url.Parse(q.Get("redirect_uri"))
	if err != nil || redir.Hostname() != "127.0.0.1" || q.Get("code_challenge_method") != "S256" ||
		q.Get("response_type") != "code" || q.Get("resource") != f.res() || q.Get("state") == "" ||
		q.Get("client_id") == "" || q.Get("code_challenge") == "" {
		http.Error(w, "invalid authorize request", 400)
		return
	}
	code := rnd()
	ch := q.Get("code_challenge")
	if f.BadChall {
		ch = "tampered"
	}
	f.mu.Lock()
	f.codes[code] = codeInfo{ch, q.Get("redirect_uri"), q.Get("client_id")}
	f.mu.Unlock()
	rq := url.Values{"state": {q.Get("state")}}
	if f.WrongState {
		rq.Set("state", "evil")
	}
	if f.DenyWith != "" {
		rq.Set("error", f.DenyWith)
	} else {
		rq.Set("code", code)
	}
	http.Redirect(w, r, q.Get("redirect_uri")+"?"+rq.Encode(), http.StatusFound)
}

func rnd() string {
	b := make([]byte, 12)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func (f *fakeAS) token(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	if u, p, ok := r.BasicAuth(); ok {
		f.LastBasic.Store(u + ":" + p)
	} else {
		f.LastBasic.Store("")
	}
	fail := func(code string) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(400)
		// Echo the whole form in a non-standard field: the client must not pass it on.
		fmt.Fprintf(w, `{"error":%q,"error_description":%q}`, code, r.Form.Encode())
	}
	if r.PostForm.Get("resource") != f.res() {
		fail("invalid_target")
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.n++
	exp := f.ExpiresIn
	if exp == 0 {
		exp = 3600
	}
	issue := func() {
		f.cur = fmt.Sprintf("rt-%d", f.n)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": fmt.Sprintf("at-%d", f.n), "token_type": "Bearer",
			"expires_in": exp, "refresh_token": f.cur,
		})
	}
	switch r.PostForm.Get("grant_type") {
	case "authorization_code":
		f.CodeGrants.Add(1)
		f.GotVerifier.Store(r.PostForm.Get("code_verifier"))
		f.GotCode.Store(r.PostForm.Get("code"))
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
		issue() // rotated before the (possibly slow) reply is sent
		if f.RefreshDelay > 0 {
			f.mu.Unlock()
			time.Sleep(f.RefreshDelay)
			f.mu.Lock()
		}
	default:
		fail("unsupported_grant_type")
	}
}
