package oauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/midspan-dev/agentgw/pkg/contracts"
)

type LoginOptions struct {
	Upstream string // config name; written to TokenFile.Upstream
	URL      string // the upstream MCP endpoint
	Auth     contracts.UpstreamAuth
	Secret   string // client secret from secret_env/secret_file, "" for none
	Store    *Store
	Out      io.Writer              // the authorization URL and progress lines
	Open     func(url string) error // nil: print only; an error is printed, not fatal
	Timeout  time.Duration          // wait for the callback; 0 means 5m
}

func randB64() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

var errorValue = regexp.MustCompile(`^[a-z_]+$`)

// Login runs discovery, registration when needed and the loopback flow, then writes the store.
func Login(ctx context.Context, o LoginOptions) error {
	if o.Out == nil {
		o.Out = io.Discard
	}
	timeout := o.Timeout
	if timeout == 0 {
		timeout = 5 * time.Minute
	}
	if o.Secret != "" && o.Auth.Issuer == "" {
		return errors.New("issuer is required with a client secret")
	}
	hc := newClient()
	d, err := discover(ctx, hc, o.URL, o.Auth.Issuer)
	if err != nil {
		return err
	}
	if o.Auth.Resource == "" && d.Resource != "" {
		if err := checkResource(d.Resource, o.URL); err != nil {
			return err
		}
	}
	resource := firstNonEmpty(o.Auth.Resource, d.Resource, o.URL)
	scopes := o.Auth.Scopes
	if len(scopes) == 0 {
		scopes = strings.Fields(d.ScopeHint)
	}
	if len(scopes) == 0 {
		scopes = d.ScopesSupp
	}
	scope := strings.Join(scopes, " ")

	clientID, dcrSecret := o.Auth.ClientID, ""
	if clientID == "" {
		old, err := o.Store.Load(o.Upstream)
		switch {
		case err == nil && old.ClientID != "" && sameIssuer(old.Issuer, d.Issuer): // a client (and its secret) belongs to one AS
			clientID, dcrSecret = old.ClientID, old.ClientSecret
		case err != nil && !errors.Is(err, os.ErrNotExist):
			return err
		default:
			if clientID, dcrSecret, err = register(ctx, hc, d.RegEndpoint); err != nil {
				return err
			}
			fmt.Fprintf(o.Out, "registered a client with %s\n", o.Upstream)
		}
	}
	secret := firstNonEmpty(o.Secret, dcrSecret)

	state, err := randB64()
	if err != nil {
		return err
	}
	verifier, err := randB64()
	if err != nil {
		return err
	}
	sum := sha256.Sum256([]byte(verifier))

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	redirect := fmt.Sprintf("http://127.0.0.1:%d/callback", ln.Addr().(*net.TCPAddr).Port)
	type result struct {
		code string
		err  error
	}
	done := make(chan result, 1)
	var once sync.Once
	mux := http.NewServeMux()
	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		var res result
		switch {
		case q.Get("state") != state:
			res.err = errors.New("callback state mismatch")
		case q.Get("error") != "":
			res.err = errors.New("authorization refused")
			if e := q.Get("error"); errorValue.MatchString(e) {
				res.err = fmt.Errorf("authorization refused: %s", e)
			}
		case q.Get("code") == "":
			res.err = errors.New("callback carried no code")
		default:
			res.code = q.Get("code")
		}
		first := false
		once.Do(func() { first = true; done <- res })
		if !first || res.err != nil {
			http.Error(w, "login failed", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		io.WriteString(w, "<html><body>You can close this tab.</body></html>")
	})
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go srv.Serve(ln)
	defer srv.Close()

	q := url.Values{
		"response_type": {"code"}, "client_id": {clientID}, "redirect_uri": {redirect},
		"code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}, "code_challenge_method": {"S256"},
		"state": {state}, "resource": {resource},
	}
	if scope != "" {
		q.Set("scope", scope)
	}
	sep := "?"
	if strings.Contains(d.AuthEndpoint, "?") {
		sep = "&"
	}
	authURL := d.AuthEndpoint + sep + q.Encode()
	fmt.Fprintf(o.Out, "open this URL to log in to %s:\n%s\n", o.Upstream, authURL)
	if o.Open != nil {
		if err := o.Open(authURL); err != nil {
			fmt.Fprintf(o.Out, "could not open a browser: %v\n", err)
		}
	}

	wctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var res result
	select {
	case res = <-done:
	case <-wctx.Done():
		return fmt.Errorf("login: no callback received: %w", wctx.Err())
	}
	if res.err != nil {
		return res.err
	}

	tr, err := tokenPost(ctx, hc, d.TokenEndpoint, url.Values{
		"grant_type": {"authorization_code"}, "code": {res.code}, "redirect_uri": {redirect},
		"client_id": {clientID}, "code_verifier": {verifier}, "resource": {resource},
	}, clientID, secret)
	if err != nil {
		return err
	}
	return o.Store.Update(func(tf *contracts.TokenFile) error {
		*tf = contracts.TokenFile{
			Version: "1", Upstream: o.Upstream, Resource: resource, Issuer: d.Issuer, TokenEndpoint: d.TokenEndpoint,
			ClientID: clientID, ClientSecret: dcrSecret, AccessToken: tr.AccessToken,
			ExpiresAt: tr.expiresAt(), RefreshToken: tr.RefreshToken, Scope: firstNonEmpty(tr.Scope, scope),
		}
		return nil
	})
}

// checkResource enforces RFC 9728 3.3: the PRM resource must identify the upstream
// (same scheme and host, path equal to or a prefix of the upstream's).
func checkResource(res, upstream string) error {
	r, err1 := url.Parse(res)
	u, err2 := url.Parse(upstream)
	if err1 == nil && err2 == nil && strings.EqualFold(r.Scheme, u.Scheme) && strings.EqualFold(r.Host, u.Host) {
		rp := strings.TrimSuffix(r.Path, "/")
		if u.Path == rp || strings.HasPrefix(u.Path, rp+"/") {
			return nil
		}
	}
	return fmt.Errorf("protected resource metadata names %s, not %s", res, upstream)
}

func firstNonEmpty(s ...string) string {
	for _, v := range s {
		if v != "" {
			return v
		}
	}
	return ""
}
