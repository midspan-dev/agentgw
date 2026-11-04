package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
)

type discovery struct {
	Issuer        string // AS metadata issuer, verified against the pinned or discovered one
	Resource      string // PRM resource, "" when absent
	ScopeHint     string // WWW-Authenticate scope
	ScopesSupp    []string
	AuthEndpoint  string
	TokenEndpoint string
	RegEndpoint   string
}

type prm struct {
	Resource   string   `json:"resource"`
	AuthServer []string `json:"authorization_servers"`
	Scopes     []string `json:"scopes_supported"`
}

type asMeta struct {
	Issuer  string   `json:"issuer"`
	Auth    string   `json:"authorization_endpoint"`
	Token   string   `json:"token_endpoint"`
	Reg     string   `json:"registration_endpoint"`
	Methods []string `json:"code_challenge_methods_supported"`
}

// checkURL requires https, except loopback hosts (tests).
func checkURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("invalid URL %q", raw)
	}
	switch {
	case u.Scheme == "https":
	case u.Scheme == "http" && slices.Contains([]string{"127.0.0.1", "localhost", "::1"}, u.Hostname()):
	default:
		return nil, fmt.Errorf("endpoint %q must be https", raw)
	}
	return u, nil
}

func get(ctx context.Context, hc *http.Client, u, accept string) (int, http.Header, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return 0, nil, nil, err
	}
	req.Header.Set("Accept", accept)
	resp, err := hc.Do(req)
	if err != nil {
		return 0, nil, nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, resp.Header, b, nil
}

var challengeParam = regexp.MustCompile(`(\w+)="([^"]*)"`)

func challengeParams(h http.Header) map[string]string {
	m := map[string]string{}
	for _, v := range h.Values("WWW-Authenticate") {
		if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(v)), "bearer") {
			continue
		}
		for _, p := range challengeParam.FindAllStringSubmatch(v, -1) {
			m[strings.ToLower(p[1])] = p[2]
		}
	}
	return m
}

// getMeta GETs u and decodes a 200 JSON body into v; ok is false for any other status.
func getMeta(ctx context.Context, hc *http.Client, u string, v any) (bool, error) {
	st, _, b, err := get(ctx, hc, u, "application/json")
	if err != nil {
		return false, err
	}
	if st != 200 {
		return false, nil
	}
	if err := json.Unmarshal(b, v); err != nil {
		return false, fmt.Errorf("metadata at %s: not JSON", u)
	}
	return true, nil
}

// discover finds the authorization server: pinned when non-empty, else the PRM's first.
func discover(ctx context.Context, hc *http.Client, resURL, pinned string) (*discovery, error) {
	ru, err := url.Parse(resURL)
	if err != nil || ru.Host == "" {
		return nil, fmt.Errorf("invalid upstream URL %q", resURL)
	}
	origin := ru.Scheme + "://" + ru.Host
	path := strings.TrimSuffix(ru.Path, "/")
	d := &discovery{}

	st, hdr, _, err := get(ctx, hc, resURL, "application/json, text/event-stream")
	if err != nil {
		return nil, fmt.Errorf("probing upstream: %w", err)
	}
	var cands []string
	if st == 401 {
		p := challengeParams(hdr)
		d.ScopeHint = p["scope"]
		if p["resource_metadata"] != "" {
			cands = append(cands, p["resource_metadata"])
		}
	}
	cands = append(cands, origin+"/.well-known/oauth-protected-resource"+path)
	if path != "" {
		cands = append(cands, origin+"/.well-known/oauth-protected-resource")
	}
	var p prm
	found := false
	for _, c := range cands {
		if _, err := checkURL(c); err != nil {
			return nil, err
		}
		if found, err = getMeta(ctx, hc, c, &p); err != nil {
			return nil, err
		} else if found {
			break
		}
	}
	issuer := pinned
	if pinned == "" {
		if !found || len(p.AuthServer) == 0 {
			return nil, errors.New("no protected resource metadata with an authorization server")
		}
		issuer = p.AuthServer[0]
	}
	if found {
		d.Resource, d.ScopesSupp = p.Resource, p.Scopes
	}

	iss, err := checkURL(issuer)
	if err != nil {
		return nil, err
	}
	issOrigin := iss.Scheme + "://" + iss.Host
	ip := strings.TrimSuffix(iss.Path, "/")
	urls := []string{issOrigin + "/.well-known/oauth-authorization-server" + ip, issOrigin + "/.well-known/openid-configuration" + ip}
	if ip != "" {
		// OIDC Discovery 1.0 section 4 appends the suffix to the issuer path; the MCP spec tries it third.
		urls = append(urls, issOrigin+ip+"/.well-known/openid-configuration",
			issOrigin+"/.well-known/oauth-authorization-server", issOrigin+"/.well-known/openid-configuration")
	}
	var m asMeta
	found = false
	for _, u := range urls {
		if found, err = getMeta(ctx, hc, u, &m); err != nil {
			return nil, err
		} else if found {
			break
		}
	}
	if !found {
		return nil, errors.New("no authorization server metadata")
	}
	if strings.TrimSuffix(m.Issuer, "/") != strings.TrimSuffix(issuer, "/") {
		return nil, fmt.Errorf("authorization server metadata is for %s, not %s", m.Issuer, issuer)
	}
	if m.Auth == "" || m.Token == "" {
		return nil, errors.New("authorization server metadata lacks authorization_endpoint or token_endpoint")
	}
	if m.Methods != nil && !slices.Contains(m.Methods, "S256") {
		return nil, errors.New("authorization server does not support PKCE S256")
	}
	for _, e := range []string{m.Auth, m.Token, m.Reg} {
		if e == "" {
			continue
		}
		if _, err := checkURL(e); err != nil {
			return nil, err
		}
	}
	d.Issuer = m.Issuer
	d.AuthEndpoint, d.TokenEndpoint, d.RegEndpoint = m.Auth, m.Token, m.Reg
	return d, nil
}
