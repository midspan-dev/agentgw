package contracts

// TokenFile mirrors contracts/schemas/token-file.schema.json: the tokens the
// gateway holds for one authorization_code upstream (docs/adr/0013). Written
// by `agentgw login` and on every refresh, mode 0600, replaced atomically, and
// serialised across processes by an exclusive flock on `<path>.lock`. It is
// self-contained (token endpoint and client identity included), so copying it
// to another machine moves the credential. It is bound to one upstream:
// Upstream, Resource and Issuer are checked against the config before use.
type TokenFile struct {
	Version       string `json:"version"`
	Upstream      string `json:"upstream"`       // the gateway refuses a file for another upstream
	// Resource is the RFC 8707 resource the tokens were issued for. At serve
	// time it must identify the upstream URL (same scheme, host and port; the
	// URL path equals it or extends it at a '/') or equal UpstreamAuth.Resource
	// when that is set; otherwise the file is refused (login required).
	Resource string `json:"resource"`
	// Issuer is the authorization server the tokens came from (the metadata
	// issuer at login). With UpstreamAuth.Issuer set, a file whose Issuer
	// differs is refused.
	Issuer        string `json:"issuer"`
	TokenEndpoint string `json:"token_endpoint"` // refresh uses it without rediscovery
	ClientID      string `json:"client_id"`
	// ClientSecret is set only when dynamic registration issued one; refresh
	// then authenticates with client_secret_basic.
	ClientSecret string `json:"client_secret,omitempty"`
	AccessToken  string `json:"access_token"`
	// ExpiresAt is RFC 3339 UTC. Refresh when fewer than 60 s remain.
	ExpiresAt string `json:"expires_at"`
	// RefreshToken is replaced on every refresh that rotates it. Empty means
	// the access token cannot be renewed: login again when it expires.
	RefreshToken string `json:"refresh_token,omitempty"`
	// Scope is the space-separated grant as the token response reported it
	// (or as requested when it did not).
	Scope string `json:"scope,omitempty"`
}
