package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// register does RFC 7591 dynamic client registration as a public client.
func register(ctx context.Context, hc *http.Client, endpoint string) (id, secret string, err error) {
	if endpoint == "" {
		return "", "", errors.New("server requires a configured client_id")
	}
	body := `{"client_name":"agentgw","redirect_uris":["http://127.0.0.1/callback"],"grant_types":["authorization_code","refresh_token"],"response_types":["code"],"token_endpoint_auth_method":"none"}`
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(body))
	if err != nil {
		return "", "", errors.New("registration: bad request")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := hc.Do(req)
	if err != nil {
		return "", "", errors.New("registration: request failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode != 201 && resp.StatusCode != 200 {
		return "", "", fmt.Errorf("registration: HTTP %d", resp.StatusCode)
	}
	var r struct {
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if json.Unmarshal(b, &r) != nil || r.ClientID == "" {
		return "", "", errors.New("registration: invalid response")
	}
	return r.ClientID, r.ClientSecret, nil
}
