// Package oauth is the OAuth 2.0 client for authorization_code upstreams
// (docs/adr/0013): discovery, registration, browser login, the token file
// store and a refreshing contracts.UpstreamCredential.
package oauth

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"github.com/midspan-dev/agentgw/pkg/contracts"
)

// Store is one token file and its lock file (<Path>.lock).
type Store struct{ Path string }

// Load reads the file; os.ErrNotExist when absent; an error naming the path
// when it is for another upstream than want, malformed, or version != "1".
func (s *Store) Load(want string) (*contracts.TokenFile, error) {
	b, err := os.ReadFile(s.Path)
	if err != nil {
		return nil, err
	}
	var tf contracts.TokenFile
	if err := json.Unmarshal(b, &tf); err != nil {
		return nil, fmt.Errorf("token file %s: malformed", s.Path)
	}
	if tf.Version != "1" {
		return nil, fmt.Errorf("token file %s: unsupported version %q", s.Path, tf.Version)
	}
	if tf.Upstream != want {
		return nil, fmt.Errorf("token file %s: belongs to upstream %q, not %q", s.Path, tf.Upstream, want)
	}
	if tf.Issuer == "" {
		return nil, fmt.Errorf("token file %s: malformed (no issuer)", s.Path)
	}
	return &tf, nil
}

// Update runs fn under an exclusive flock on <Path>.lock with the freshly
// re-read file (zero value, Version "1", when absent) and writes fn's result
// atomically. fn returning an error writes nothing.
func (s *Store) Update(fn func(*contracts.TokenFile) error) error {
	dir := filepath.Dir(s.Path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	lock, err := os.OpenFile(s.Path+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	defer lock.Close() // closing releases the flock
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	tf := contracts.TokenFile{Version: "1"}
	switch b, err := os.ReadFile(s.Path); {
	case err == nil:
		if err := json.Unmarshal(b, &tf); err != nil {
			return fmt.Errorf("token file %s: malformed", s.Path)
		}
	case !errors.Is(err, os.ErrNotExist):
		return err
	}
	if err := fn(&tf); err != nil {
		return err
	}
	out, err := json.MarshalIndent(&tf, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, filepath.Base(s.Path)+".tmp*")
	if err != nil {
		return err
	}
	_, werr := tmp.Write(out)
	cerr := errors.Join(werr, tmp.Chmod(0o600), tmp.Close())
	if cerr == nil {
		cerr = os.Rename(tmp.Name(), s.Path)
	}
	if cerr != nil {
		os.Remove(tmp.Name())
	}
	return cerr
}
