// Package httpcreds builds the gateway-held credential for one URL upstream
// (docs/adr/0012) from a contracts.UpstreamAuth.
package httpcreds

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/midspan-dev/agentgw/pkg/contracts"
)

// New reads the secret once and returns the credential. Errors name the
// variable or path, never the value.
func New(a contracts.UpstreamAuth) (contracts.UpstreamCredential, error) {
	var secret string
	switch {
	case a.SecretEnv != "":
		secret = os.Getenv(a.SecretEnv)
		if secret == "" {
			return nil, fmt.Errorf("upstream auth: environment variable %s is unset or empty", a.SecretEnv)
		}
	case a.SecretFile != "":
		b, err := os.ReadFile(a.SecretFile)
		if err != nil {
			return nil, fmt.Errorf("upstream auth: secret file %s: %w", a.SecretFile, err)
		}
		secret = strings.TrimSuffix(string(b), "\n")
		if secret == "" {
			return nil, fmt.Errorf("upstream auth: secret file %s is empty", a.SecretFile)
		}
	default:
		return nil, errors.New("upstream auth: no secret_env or secret_file")
	}
	switch a.Kind {
	case contracts.AuthKindHeader:
		return &header{name: a.Header, value: a.Prefix + secret}, nil
	case contracts.AuthKindClientCredentials:
		return &clientCreds{a: a, secret: secret, hc: &http.Client{
			Timeout:       30 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		}}, nil
	}
	return nil, fmt.Errorf("upstream auth: unknown kind %q", a.Kind)
}

type header struct{ name, value string }

func (c *header) Apply(_ context.Context, h http.Header) error {
	h.Set(c.name, c.value)
	return nil
}

type clientCreds struct {
	a      contracts.UpstreamAuth
	secret string
	hc     *http.Client

	mu      sync.Mutex // held across check-and-fetch so concurrent callers share one fetch
	token   string
	refetch time.Time // fetch again at or after this instant
}

func (c *clientCreds) Apply(ctx context.Context, h http.Header) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token == "" || !time.Now().Before(c.refetch) {
		c.token = ""
		tok, ttl, err := c.fetch(ctx)
		if err != nil {
			return err
		}
		if ttl > 0 { // no expires_in: never cached
			c.token, c.refetch = tok, time.Now().Add(ttl-min(30*time.Second, ttl/2))
		}
		h.Set("Authorization", "Bearer "+tok)
		return nil
	}
	h.Set("Authorization", "Bearer "+c.token)
	return nil
}

// errorCodes are the token endpoint error codes passed on to the caller:
// RFC 6749 5.2 and 4.1.2.1 (server_error, temporarily_unavailable), RFC 8707 (invalid_target).
var errorCodes = map[string]bool{
	"invalid_request": true, "invalid_client": true, "invalid_grant": true,
	"unauthorized_client": true, "unsupported_grant_type": true, "invalid_scope": true,
	"invalid_target": true, "server_error": true, "temporarily_unavailable": true,
}

func (c *clientCreds) fetch(ctx context.Context) (string, time.Duration, error) {
	form := url.Values{"grant_type": {"client_credentials"}}
	if len(c.a.Scopes) > 0 {
		form.Set("scope", strings.Join(c.a.Scopes, " "))
	}
	if c.a.Resource != "" {
		form.Set("resource", c.a.Resource)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.a.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", 0, errors.New("token endpoint: bad request") // the url.Error text could carry the URL
	}
	req.SetBasicAuth(url.QueryEscape(c.a.ClientID), url.QueryEscape(c.secret))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := c.hc.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return "", 0, fmt.Errorf("token endpoint: %w", ctx.Err())
		}
		return "", 0, errors.New("token endpoint: request failed")
	}
	defer resp.Body.Close()
	var r struct {
		AccessToken string   `json:"access_token"`
		TokenType   string   `json:"token_type"`
		ExpiresIn   *float64 `json:"expires_in"`
		Error       string   `json:"error"`
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	jerr := json.Unmarshal(b, &r)
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		msg := fmt.Sprintf("token endpoint: HTTP %d", resp.StatusCode)
		if errorCodes[r.Error] { // anything else could echo the request, secret included
			msg += ": " + r.Error
		}
		return "", 0, errors.New(msg)
	}
	if jerr != nil || r.AccessToken == "" || !strings.EqualFold(r.TokenType, "bearer") {
		return "", 0, errors.New("token endpoint: invalid token response")
	}
	var ttl time.Duration
	if r.ExpiresIn != nil {
		ttl = time.Duration(*r.ExpiresIn * float64(time.Second))
	}
	return r.AccessToken, ttl, nil
}
