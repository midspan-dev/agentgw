package ledger

import (
	"bufio"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"

	"github.com/gowebpki/jcs"
	"github.com/midspan-dev/agentgw/pkg/contracts"
)

// Verify streams a ledger and reports the first failure. It needs no SQLite
// and no config. Reasons: bad_json, bad_version, chain_break, wrong_signer,
// bad_signature, bad_checkpoint_range, bad_checkpoint_root.
func Verify(r io.Reader, pub ed25519.PublicKey) contracts.VerifyReport {
	rep := contracts.VerifyReport{}
	fail := func(line int, reason string) contracts.VerifyReport {
		rep.Line, rep.Reason = line, reason
		return rep
	}
	signer := hex.EncodeToString(pub)
	prev := contracts.ZeroHash
	var leaves [][32]byte
	var firstID, lastID string
	br := bufio.NewReader(r)
	for n := 1; ; n++ {
		line, err := br.ReadBytes('\n')
		if err != nil && err != io.EOF {
			return fail(n, "read_error") // never OK on a partial read
		}
		if len(line) == 0 && err != nil {
			break
		}
		line = trimNL(line)
		var m map[string]json.RawMessage
		var h struct {
			Version, Type, ID, PrevHash, Signer, Sig string
		}
		if !canonical(line) || json.Unmarshal(line, &m) != nil || m == nil {
			return fail(n, "bad_json")
		}
		for k, p := range map[string]*string{"version": &h.Version, "type": &h.Type, "id": &h.ID,
			"prev_hash": &h.PrevHash, "signer": &h.Signer, "sig": &h.Sig} {
			json.Unmarshal(m[k], p) // missing or non-string stays ""
		}
		if h.Type != contracts.LineTypeEntry && h.Type != contracts.LineTypeCheckpoint {
			return fail(n, "bad_json")
		}
		if h.Version != "1" {
			return fail(n, "bad_version")
		}
		if h.PrevHash != prev {
			return fail(n, "chain_break")
		}
		if h.Signer != signer {
			return fail(n, "wrong_signer")
		}
		sig, derr := hex.DecodeString(h.Sig)
		delete(m, "sig")
		body, _ := json.Marshal(m)
		msg, jerr := jcs.Transform(body)
		if derr != nil || jerr != nil || !ed25519.Verify(pub, msg, sig) {
			return fail(n, "bad_signature")
		}
		sum := sha256.Sum256(line)
		prev = hex.EncodeToString(sum[:])
		if h.Type == contracts.LineTypeEntry {
			if len(leaves) == 0 {
				firstID = h.ID
			}
			lastID = h.ID
			leaves = append(leaves, sum)
			rep.Entries++
			continue
		}
		var cp contracts.Checkpoint
		if json.Unmarshal(line, &cp) != nil {
			return fail(n, "bad_json")
		}
		if cp.Range.Count != len(leaves) || len(leaves) == 0 || cp.Range.FirstID != firstID || cp.Range.LastID != lastID {
			return fail(n, "bad_checkpoint_range")
		}
		if root := merkle(leaves); cp.Root != hex.EncodeToString(root[:]) {
			return fail(n, "bad_checkpoint_root")
		}
		leaves = nil
		rep.Checkpoints++
	}
	rep.OK = true
	return rep
}
