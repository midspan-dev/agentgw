package oauth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/midspan-dev/agentgw/pkg/contracts"
)

type credential struct {
	name   string
	url    string
	auth   contracts.UpstreamAuth
	store  *Store
	secret string
	hc     *http.Client

	mu    sync.Mutex
	tf    *contracts.TokenFile
	stamp fileStamp
	dead  error // invalid_grant seen; sticks until the file changes
}

type fileStamp struct {
	mtime time.Time
	size  int64
}

// CredentialOptions identifies the upstream a credential serves; the token
// file is used only if it was issued for exactly this upstream.
type CredentialOptions struct {
	Upstream string // config name; must equal TokenFile.Upstream
	URL      string // the upstream MCP endpoint
	Auth     contracts.UpstreamAuth
	Secret   string // client secret from secret_env/secret_file, "" for none
	Store    *Store
}

// NewCredential returns the refreshing credential for one upstream. The file
// need not exist yet: Apply answers "login required" until a login writes it.
func NewCredential(o CredentialOptions) contracts.UpstreamCredential {
	return &credential{name: o.Upstream, url: o.URL, auth: o.Auth, store: o.Store, secret: o.Secret, hc: newClient()}
}

// bound reports whether tf was issued for this credential's upstream (ADR 0013 decision 5)
// and, when one is configured, to this client.
func (c *credential) bound(tf *contracts.TokenFile) bool {
	if c.auth.ClientID != "" && tf.ClientID != c.auth.ClientID {
		return false
	}
	if c.auth.Resource != "" {
		if tf.Resource != c.auth.Resource {
			return false
		}
	} else if checkResource(tf.Resource, c.url) != nil {
		return false
	}
	// An issuer-less file is malformed; Store.Load refuses it, but the refresh path reads the raw file.
	return tf.Issuer != "" && (c.auth.Issuer == "" || sameIssuer(tf.Issuer, c.auth.Issuer))
}

func sameIssuer(a, b string) bool {
	return strings.TrimSuffix(a, "/") == strings.TrimSuffix(b, "/")
}

func (c *credential) loginRequired() error {
	return fmt.Errorf("upstream %s: login required: run agentgw login %s", c.name, c.name)
}

func fresh(tf *contracts.TokenFile) bool {
	t, err := time.Parse(time.RFC3339, tf.ExpiresAt)
	return err == nil && tf.AccessToken != "" && time.Until(t) > 60*time.Second
}

func unexpired(tf *contracts.TokenFile) bool {
	t, err := time.Parse(time.RFC3339, tf.ExpiresAt)
	return err == nil && tf.AccessToken != "" && time.Now().Before(t)
}

var errUseFile = errors.New("use existing file")

func (c *credential) Apply(ctx context.Context, h http.Header) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	fi, err := os.Stat(c.store.Path)
	if errors.Is(err, os.ErrNotExist) {
		c.tf = nil
		return c.loginRequired()
	}
	if err != nil {
		return fmt.Errorf("upstream %s: token file: %w", c.name, err)
	}
	if st := (fileStamp{fi.ModTime(), fi.Size()}); c.tf == nil || st != c.stamp {
		tf, err := c.store.Load(c.name)
		if err != nil {
			c.tf = nil
			return err
		}
		c.tf, c.stamp, c.dead = tf, st, nil
		if !c.bound(tf) {
			c.dead = c.loginRequired()
		}
	}
	if c.dead != nil {
		return c.dead
	}
	if fresh(c.tf) {
		h.Set("Authorization", "Bearer "+c.tf.AccessToken)
		return nil
	}
	var got contracts.TokenFile
	err = c.store.Update(func(tf *contracts.TokenFile) error {
		if tf.Upstream != c.name {
			return fmt.Errorf("token file %s: belongs to upstream %q, not %q", c.store.Path, tf.Upstream, c.name)
		}
		if !c.bound(tf) { // replaced since we read it
			return c.loginRequired()
		}
		if fresh(tf) { // another process refreshed while we waited for the lock
			got = *tf
			return errUseFile
		}
		if tf.RefreshToken == "" {
			if unexpired(tf) { // nothing to renew it with: use it until it actually expires
				got = *tf
				return errUseFile
			}
			return c.loginRequired()
		}
		form := url.Values{
			"grant_type": {"refresh_token"}, "refresh_token": {tf.RefreshToken},
			"client_id": {tf.ClientID}, "resource": {tf.Resource},
		}
		if tf.Scope != "" {
			form.Set("scope", tf.Scope)
		}
		// Detached: the AS may rotate the token before a caller cancels; losing the reply would lose the new one.
		tr, err := tokenPost(context.WithoutCancel(ctx), c.hc, tf.TokenEndpoint, form, tf.ClientID, firstNonEmpty(c.secret, tf.ClientSecret))
		if err != nil {
			return err
		}
		tf.AccessToken, tf.ExpiresAt = tr.AccessToken, tr.expiresAt()
		if tr.RefreshToken != "" {
			tf.RefreshToken = tr.RefreshToken
		}
		got = *tf
		return nil
	})
	if err != nil && !errors.Is(err, errUseFile) {
		var te *tokenError
		if !errors.As(err, &te) {
			return err
		}
		if te.Code == "invalid_grant" || te.Code == "invalid_client" {
			c.dead = c.loginRequired()
			return c.dead
		}
		return fmt.Errorf("upstream %s: token refresh failed: %s", c.name, te.detail())
	}
	c.tf = nil // re-read on the next Apply, whatever the mtime
	h.Set("Authorization", "Bearer "+got.AccessToken)
	return nil
}
