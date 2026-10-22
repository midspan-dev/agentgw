// Package ledger is the append-only, hash-chained, Ed25519-signed JSONL ledger
// (docs/adr/0004). The JSONL file is the source of truth; the SQLite index
// beside it is rebuilt from the file on every Open.
package ledger

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gowebpki/jcs"
	"github.com/midspan-dev/agentgw/pkg/contracts"
	"github.com/oklog/ulid/v2"
	_ "modernc.org/sqlite"
)

// Ledger implements contracts.Ledger.
type Ledger struct {
	mu      sync.Mutex
	cfg     contracts.LedgerConfig
	key     ed25519.PrivateKey
	signer  string
	red     *redactor
	f       *os.File
	db      *sql.DB
	entropy io.Reader

	size    int64                 // bytes of acknowledged lines in the file
	failed  atomic.Pointer[error] // mirror of broken for lock-free Err()
	stderr  io.Writer             // seam: the operator line goes here
	broken  error                 // sticky: the file could not be rolled back after a failed write
	syncFn  func(*os.File) error
	truncFn func(*os.File, int64) error // seams for tests

	lastHash string     // line hash of the last line
	leaves   [][32]byte // entry line hashes since the last checkpoint
	firstID  string
	lastID   string
	lines    int
}

var _ contracts.Ledger = (*Ledger)(nil)

// Open opens or creates the ledger at cfg.Path and its index at cfg.Path+".db".
func Open(cfg contracts.LedgerConfig, key ed25519.PrivateKey, redaction contracts.RedactionConfig) (*Ledger, error) {
	red, err := newRedactor(redaction)
	if err != nil {
		return nil, err
	}
	l := &Ledger{cfg: cfg, key: key, red: red, lastHash: contracts.ZeroHash,
		signer:  hex.EncodeToString(key.Public().(ed25519.PublicKey)),
		entropy: ulid.Monotonic(rand.Reader, 0),
		stderr:  os.Stderr, syncFn: (*os.File).Sync, truncFn: (*os.File).Truncate}
	if l.f, err = os.OpenFile(cfg.Path, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0o600); err != nil {
		return nil, err
	}
	if l.db, err = sql.Open("sqlite", cfg.Path+".db"); err != nil {
		l.f.Close()
		return nil, err
	}
	if err := l.recover(); err != nil {
		l.Close()
		return nil, err
	}
	return l, nil
}

// Close releases the file and the index.
func (l *Ledger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return errors.Join(l.f.Close(), l.db.Close())
}

// firstLinePrefix starts every entry line (JCS key order), and the first line
// of a ledger is always an entry; a test pins it to real Append output.
const firstLinePrefix = `{"action":{"args":`

// recover reads the file for chain state and rebuilds the index. A final
// segment without "\n" was never acknowledged (Append returns after the
// newline is fsynced), so it is cut off.
func (l *Ledger) recover() error {
	data, err := os.ReadFile(l.cfg.Path)
	if err != nil {
		return err
	}
	// Validate the complete lines before touching the file, so a non-ledger
	// file is never cut; the unterminated tail goes only after they pass.
	fileSize := int64(len(data))
	tail := data[bytes.LastIndexByte(data, '\n')+1:]
	data = data[:len(data)-len(tail)]
	if len(data) == 0 && len(tail) > 0 && !bytes.HasPrefix(tail, []byte(firstLinePrefix)) && !bytes.HasPrefix([]byte(firstLinePrefix), tail) {
		return fmt.Errorf("ledger: %s is not a ledger (no complete line, does not start like an entry)", l.cfg.Path)
	}
	l.size = int64(len(data))
	tx, err := l.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, q := range []string{
		`DROP TABLE IF EXISTS entries`,
		`CREATE TABLE entries (id TEXT PRIMARY KEY, line INTEGER, ts TEXT, call_id TEXT, agent_id TEXT, server TEXT, tool TEXT, outcome TEXT)`,
	} {
		if _, err := tx.Exec(q); err != nil {
			return err
		}
	}
	for len(data) > 0 {
		i := bytes.IndexByte(data, '\n')
		line := data[:i]
		data = data[i+1:]
		l.lines++
		if !canonical(line) {
			return fmt.Errorf("ledger: line %d: not canonical JSON", l.lines)
		}
		var h struct {
			Type string `json:"type"`
			ID   string `json:"id"`
		}
		if err := json.Unmarshal(line, &h); err != nil {
			return fmt.Errorf("ledger: line %d: %w", l.lines, err)
		}
		sum := sha256.Sum256(line)
		l.lastHash = hex.EncodeToString(sum[:])
		switch h.Type {
		case contracts.LineTypeCheckpoint:
			l.leaves, l.firstID, l.lastID = nil, "", ""
		case contracts.LineTypeEntry:
			var e contracts.Entry
			if err := json.Unmarshal(line, &e); err != nil {
				return fmt.Errorf("ledger: line %d: %w", l.lines, err)
			}
			l.noteEntry(sum, h.ID)
			if err := indexEntry(tx, l.lines, &e); err != nil {
				return err
			}
		}
	}
	if l.size < fileSize {
		if err := l.f.Truncate(l.size); err != nil {
			return err
		}
		if err := l.f.Sync(); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// canonical reports whether line is exactly its own JCS form (this also
// rejects duplicate keys), so every parser reads the same document.
func canonical(line []byte) bool {
	c, err := jcs.Transform(line)
	return err == nil && bytes.Equal(c, line)
}

func trimNL(b []byte) []byte {
	if n := len(b); n > 0 && b[n-1] == '\n' {
		return b[:n-1]
	}
	return b
}

func (l *Ledger) noteEntry(sum [32]byte, id string) {
	if len(l.leaves) == 0 {
		l.firstID = id
	}
	l.lastID = id
	l.leaves = append(l.leaves, sum)
}

func indexEntry(x interface {
	Exec(string, ...any) (sql.Result, error)
}, line int, e *contracts.Entry) error {
	_, err := x.Exec(`INSERT INTO entries VALUES (?,?,?,?,?,?,?,?)`, e.ID, line, e.Ts.Format(time.RFC3339Nano),
		e.CallID, e.Principal.AgentID, e.Action.Server, e.Action.Tool, string(e.Outcome))
	return err
}

func hashHex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// canonHash is SHA-256 of JCS(raw).
func canonHash(raw []byte) (string, error) {
	c, err := jcs.Transform(raw)
	if err != nil {
		return "", err
	}
	return hashHex(c), nil
}

// seal signs v (a struct with a "sig" member and signer already set) and
// returns its final JCS line plus the signature. Signature input is
// JCS(v without sig); map[string]RawMessage keeps numbers byte-exact.
func seal(v any, key ed25519.PrivateKey) (line []byte, sig string, err error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, "", err
	}
	m := map[string]json.RawMessage{}
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, "", err
	}
	delete(m, "sig")
	if b, err = json.Marshal(m); err != nil {
		return nil, "", err
	}
	msg, err := jcs.Transform(b)
	if err != nil {
		return nil, "", err
	}
	sig = hex.EncodeToString(ed25519.Sign(key, msg))
	m["sig"], _ = json.Marshal(sig)
	if b, err = json.Marshal(m); err != nil {
		return nil, "", err
	}
	line, err = jcs.Transform(b)
	return line, sig, err
}

// write appends line+"\n" durably and advances chain state. On failure the
// file is truncated back so that nothing was written; if that fails too the
// ledger refuses all further writes.
func (l *Ledger) write(line []byte) error {
	if l.broken != nil {
		return l.broken
	}
	buf := append(line[:len(line):len(line)], '\n')
	_, err := l.f.Write(buf)
	if err == nil {
		err = l.syncFn(l.f)
	}
	if err != nil {
		terr := l.truncFn(l.f, l.size)
		if terr == nil {
			terr = l.syncFn(l.f) // make the rollback durable
		}
		if terr != nil {
			l.broken = fmt.Errorf("ledger: unrecoverable write failure: %w (rollback: %v)", err, terr)
			l.failed.Store(&l.broken)
			fmt.Fprintf(l.stderr, "agentgw ledger: unrecoverable write failure, refusing all calls: %v\n", l.broken)
		}
		return err
	}
	l.size += int64(len(buf))
	l.lines++
	l.lastHash = hashHex(line)
	return nil
}

func (l *Ledger) newID() string {
	return ulid.MustNew(ulid.Timestamp(time.Now()), l.entropy).String()
}

// Append implements contracts.Ledger.
func (l *Ledger) Append(ctx context.Context, e *contracts.Entry) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(e.Action.Args) == 0 {
		e.Action.Args = json.RawMessage(`{}`)
	}
	argsHash, err := canonHash(e.Action.Args)
	if err != nil {
		return fmt.Errorf("ledger: args: %w", err)
	}
	var irHash string
	var ir json.RawMessage
	if c := string(e.Action.InputResponses); c != "" && c != "null" {
		if irHash, err = canonHash(e.Action.InputResponses); err != nil {
			return fmt.Errorf("ledger: input_responses: %w", err)
		}
		ir = l.red.redact(e.Action.InputResponses)
	}
	var resultHash string
	content := json.RawMessage("null")
	if c := string(e.Result.Content); c != "" && c != "null" {
		stripped := StripEnvelope(e.Result.Content)
		if resultHash, err = canonHash(stripped); err != nil {
			return fmt.Errorf("ledger: result: %w", err)
		}
		content = l.red.redact(stripped)
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	if l.broken != nil {
		return l.broken
	}
	e.Version, e.Type, e.ID = "1", contracts.LineTypeEntry, l.newID()
	if e.Ts.IsZero() {
		e.Ts = time.Now()
	}
	e.Ts = e.Ts.UTC()
	e.PrevHash, e.Action.ArgsHash, e.Result.ResultHash = l.lastHash, argsHash, resultHash
	e.Action.Args, e.Result.Content = l.red.redact(e.Action.Args), content
	e.Result.Error = l.red.redactText(e.Result.Error) // patterns only: error text has no field names
	e.Action.InputResponses, e.Action.InputResponsesHash = ir, irHash
	e.Signer = l.signer
	line, sig, err := seal(e, l.key)
	if err != nil {
		return err
	}
	if err := l.write(line); err != nil {
		return err
	}
	e.Sig = sig
	l.noteEntry(sha256.Sum256(line), e.ID)
	indexEntry(l.db, l.lines, e) // shortcut: index errors are dropped (file is truth, rebuilt on Open), upgrade if queries are served live
	if n := l.cfg.CheckpointEvery; n > 0 && len(l.leaves) >= n {
		// shortcut: checkpoint errors are discarded here (no logger), upgrade when the pipeline wants them surfaced
		l.checkpoint() // the entry is durable; a failed checkpoint is rolled back (or sticky) and retried by the next one
	}
	return nil
}

// Checkpoint implements contracts.Ledger.
func (l *Ledger) Checkpoint(ctx context.Context) (*contracts.Checkpoint, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.checkpoint()
}

func (l *Ledger) checkpoint() (*contracts.Checkpoint, error) {
	if l.broken != nil {
		return nil, l.broken
	}
	if len(l.leaves) == 0 {
		return nil, nil
	}
	root := merkle(l.leaves)
	cp := &contracts.Checkpoint{Version: "1", Type: contracts.LineTypeCheckpoint, ID: l.newID(),
		Ts: time.Now().UTC(), PrevHash: l.lastHash,
		Range: contracts.CheckpointRange{FirstID: l.firstID, LastID: l.lastID, Count: len(l.leaves)},
		Root:  hex.EncodeToString(root[:]), Signer: l.signer}
	line, sig, err := seal(cp, l.key)
	if err != nil {
		return nil, err
	}
	if err := l.write(line); err != nil {
		return nil, err
	}
	cp.Sig = sig
	l.leaves, l.firstID, l.lastID = nil, "", ""
	return cp, nil
}

// merkle: adjacent pairs hashed left-to-right, odd node carried up, one leaf is the root.
func merkle(level [][32]byte) [32]byte {
	for len(level) > 1 {
		var next [][32]byte
		for i := 0; i < len(level); i += 2 {
			if i+1 == len(level) {
				next = append(next, level[i])
				break
			}
			next = append(next, sha256.Sum256(append(level[i][:len(level[i]):len(level[i])], level[i+1][:]...)))
		}
		level = next
	}
	return level[0]
}

// Verify implements contracts.Ledger.
func (l *Ledger) Verify(ctx context.Context) (*contracts.VerifyReport, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	f, err := os.Open(l.cfg.Path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	rep := Verify(f, l.key.Public().(ed25519.PublicKey))
	return &rep, nil
}

// Redact implements contracts.Ledger.
func (l *Ledger) Redact(raw json.RawMessage) json.RawMessage { return l.red.redact(raw) }

// Err implements contracts.Ledger: nil while healthy, then the sticky write error forever.
func (l *Ledger) Err() error {
	if p := l.failed.Load(); p != nil {
		return *p
	}
	return nil
}
