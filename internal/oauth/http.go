package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

func newClient() *http.Client {
	return &http.Client{
		Timeout:       30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// errorCodes are the token endpoint error codes passed on to the caller
// (same table as internal/proxy/httpcreds): anything else could echo the request.
var errorCodes = map[string]bool{
	"invalid_request": true, "invalid_client": true, "invalid_grant": true,
	"unauthorized_client": true, "unsupported_grant_type": true, "invalid_scope": true,
	"invalid_target": true, "server_error": true, "temporarily_unavailable": true,
}

type tokenError struct {
	Status int
	Code   string
	msg    string
}

func (e *tokenError) Error() string { return e.msg }

// detail is the short reason for "token refresh failed: <detail>".
func (e *tokenError) detail() string {
	switch {
	case e.Code != "":
		return e.Code
	case e.Status != 0:
		return fmt.Sprintf("HTTP %d", e.Status)
	}
	return e.msg
}

type tokenResp struct {
	AccessToken  string   `json:"access_token"`
	TokenType    string   `json:"token_type"`
	ExpiresIn    *float64 `json:"expires_in"`
	RefreshToken string   `json:"refresh_token"`
	Scope        string   `json:"scope"`
	Error        string   `json:"error"`
}

// expiresAt is RFC 3339 UTC; a missing expires_in means 3600 s.
func (r *tokenResp) expiresAt() string {
	ttl := 3600.0
	if r.ExpiresIn != nil {
		ttl = *r.ExpiresIn
	}
	return time.Now().Add(time.Duration(ttl * float64(time.Second))).UTC().Format(time.RFC3339)
}

// tokenPost sends a token request. Errors never carry the request or response body.
func tokenPost(ctx context.Context, hc *http.Client, endpoint string, form url.Values, clientID, secret string) (*tokenResp, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, &tokenError{msg: "token endpoint: bad request"}
	}
	if secret != "" {
		req.SetBasicAuth(url.QueryEscape(clientID), url.QueryEscape(secret))
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := hc.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("token endpoint: %w", ctx.Err())
		}
		return nil, &tokenError{msg: "token endpoint: request failed"}
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var r tokenResp
	jerr := json.Unmarshal(b, &r)
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		e := &tokenError{Status: resp.StatusCode, msg: fmt.Sprintf("token endpoint: HTTP %d", resp.StatusCode)}
		if errorCodes[r.Error] {
			e.Code = r.Error
			e.msg += ": " + r.Error
		}
		return nil, e
	}
	if jerr != nil || r.AccessToken == "" || !strings.EqualFold(r.TokenType, "bearer") {
		return nil, errors.New("token endpoint: invalid token response")
	}
	return &r, nil
}
