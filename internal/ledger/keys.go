package ledger

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
)

// GenerateKey writes a new Ed25519 private key to path (64 bytes, one line of
// lower-case hex, mode 0600) and returns its public key. It refuses to
// overwrite an existing file: replacing a ledger key orphans the ledger.
func GenerateKey(path string) (ed25519.PublicKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, err
	}
	_, err = f.WriteString(hex.EncodeToString(priv) + "\n")
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return pub, err
}

// LoadKey reads a key written by GenerateKey.
func LoadKey(path string) (ed25519.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	k, err := hex.DecodeString(strings.TrimSpace(string(b)))
	if err != nil || len(k) != ed25519.PrivateKeySize || !bytes.Equal(ed25519.NewKeyFromSeed(k[:32]), k) {
		return nil, fmt.Errorf("ledger: %s: not a 64-byte hex Ed25519 private key", path)
	}
	return ed25519.PrivateKey(k), nil
}
