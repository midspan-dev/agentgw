// Package approval holds tool calls for human approval and records signed decisions.
package approval

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/gowebpki/jcs"
	"github.com/midspan-dev/agentgw/pkg/contracts"
	"github.com/oklog/ulid/v2"
	_ "modernc.org/sqlite"
)

var (
	// ErrNotPending: the id is unknown, already decided, or expired.
	ErrNotPending = errors.New("approval: not pending")
	// ErrArgsHashMismatch: the human's args hash is not the request's.
	ErrArgsHashMismatch = errors.New("approval: args hash mismatch")
	// ErrBadGrant: the requested grant scope or expiry is invalid.
	ErrBadGrant = errors.New("approval: invalid grant")
)

const pollInterval = 250 * time.Millisecond

const schema = `
CREATE TABLE IF NOT EXISTS approvals (
  id TEXT PRIMARY KEY, request TEXT NOT NULL, created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL, status TEXT NOT NULL, decision TEXT);
CREATE TABLE IF NOT EXISTS grants (id TEXT PRIMARY KEY, agent_id TEXT NOT NULL, grant_json TEXT NOT NULL);`

// Store is a SQLite-backed contracts.Approver.
type Store struct {
	db   *sql.DB
	priv ed25519.PrivateKey
	now  func() time.Time
}

var _ contracts.Approver = (*Store)(nil)

// GenerateToken writes a new Ed25519 private key to path (hex, one line, 0600).
func GenerateToken(path string) error {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	return os.WriteFile(path, []byte(hex.EncodeToString(priv)+"\n"), 0o600)
}

// Open opens (creating if needed) the state database and loads the approver token.
func Open(statePath, tokenPath string) (*Store, error) {
	raw, err := os.ReadFile(tokenPath)
	if err != nil {
		return nil, fmt.Errorf("approval: read token: %w", err)
	}
	b, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(b) != ed25519.PrivateKeySize {
		return nil, errors.New("approval: token must be a 64-byte hex Ed25519 private key")
	}
	// immediate tx lock so concurrent CLI processes serialise decisions.
	db, err := sql.Open("sqlite", "file:"+statePath+"?_txlock=immediate&_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)")
	if err != nil {
		return nil, err
	}
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, err
	}
	return &Store{db: db, priv: ed25519.PrivateKey(b), now: time.Now}, nil
}

// Close closes the state database.
func (s *Store) Close() error { return s.db.Close() }

func ts(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

func (s *Store) Request(ctx context.Context, req contracts.ApprovalRequest) (string, error) {
	rb, err := json.Marshal(req)
	if err != nil {
		return "", err
	}
	id := ulid.Make().String()
	now := s.now().UTC()
	exp := now.Add(time.Duration(req.Spec.TimeoutSeconds) * time.Second)
	_, err = s.db.ExecContext(ctx, `INSERT INTO approvals (id, request, created_at, expires_at, status) VALUES (?,?,?,?,'pending')`,
		id, string(rb), ts(now), ts(exp))
	return id, err
}

type row struct {
	id           string
	req          contracts.ApprovalRequest
	created, exp time.Time
	status       string
	decision     sql.NullString
}

const cols = `id, request, created_at, expires_at, status, decision`

func scan(r interface{ Scan(...any) error }) (row, error) {
	var x row
	var req, c, e string
	if err := r.Scan(&x.id, &req, &c, &e, &x.status, &x.decision); err != nil {
		return x, err
	}
	if err := json.Unmarshal([]byte(req), &x.req); err != nil {
		return x, err
	}
	var err error
	if x.created, err = time.Parse(time.RFC3339Nano, c); err != nil {
		return x, err
	}
	x.exp, err = time.Parse(time.RFC3339Nano, e)
	return x, err
}

func (s *Store) Wait(ctx context.Context, id string, progress func(string)) (*contracts.ApprovalDecision, error) {
	var last time.Time
	for {
		x, err := scan(s.db.QueryRowContext(ctx, `SELECT `+cols+` FROM approvals WHERE id=?`, id))
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return nil, err
		}
		callErr := func(e error, reason string) error {
			return &contracts.CallError{Err: e, RuleID: x.req.RuleID, Reason: reason}
		}
		switch x.status {
		case "approved", "denied":
			var d contracts.ApprovalDecision
			if err := json.Unmarshal([]byte(x.decision.String), &d); err != nil {
				return nil, err
			}
			if x.status == "approved" {
				return &d, nil
			}
			return &d, callErr(contracts.ErrApprovalDenied, d.Reason)
		case "expired":
			return nil, callErr(contracts.ErrApprovalTimeout, "")
		}
		now := s.now()
		if !now.Before(x.exp) {
			// A decision may have landed since the read; the loop re-reads.
			if _, err := s.db.ExecContext(ctx, `UPDATE approvals SET status='expired' WHERE id=? AND status='pending'`, id); err != nil {
				return nil, err
			}
			continue
		}
		if now.Sub(last) >= 10*time.Second {
			last = now
			progress(fmt.Sprintf("waiting for approval %s, %ds left", id, int(x.exp.Sub(now).Round(time.Second)/time.Second)))
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(pollInterval):
		}
	}
}

func (s *Store) Grants(ctx context.Context, p contracts.Principal) ([]contracts.Grant, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT grant_json FROM grants WHERE agent_id=?`, p.AgentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []contracts.Grant{}
	now := s.now()
	for rows.Next() {
		var j string
		var g contracts.Grant
		if err := rows.Scan(&j); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(j), &g); err != nil {
			return nil, err
		}
		if g.Until.After(now) && (g.Scope == contracts.GrantScopeAgent || g.RunID == p.RunID) {
			out = append(out, g)
		}
	}
	return out, rows.Err()
}

// List returns undecided, unexpired approvals, oldest first.
func (s *Store) List(ctx context.Context) ([]contracts.PendingApproval, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+cols+` FROM approvals WHERE status='pending' ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []contracts.PendingApproval{}
	for rows.Next() {
		x, err := scan(rows)
		if err != nil {
			return nil, err
		}
		if s.now().Before(x.exp) {
			out = append(out, contracts.PendingApproval{ID: x.id, Request: x.req, CreatedAt: x.created, ExpiresAt: x.exp})
		}
	}
	return out, rows.Err()
}

// Approve approves id, bound to argsHash. scope "" issues no grant.
func (s *Store) Approve(ctx context.Context, id, argsHash string, scope contracts.GrantScope, until time.Time) error {
	return s.decide(ctx, id, argsHash, contracts.DecisionApproved, "", scope, until, nil)
}

// ApproveVia is Approve without a grant, recording the surface and human the
// decision came from (not covered by the signature).
func (s *Store) ApproveVia(ctx context.Context, id, argsHash string, via contracts.DecisionVia) error {
	return s.decide(ctx, id, argsHash, contracts.DecisionApproved, "", "", time.Time{}, &via)
}

// Deny denies id, bound to argsHash.
func (s *Store) Deny(ctx context.Context, id, argsHash, reason string) error {
	return s.decide(ctx, id, argsHash, contracts.DecisionDenied, reason, "", time.Time{}, nil)
}

// DenyVia is Deny recording the surface and human the decision came from.
func (s *Store) DenyVia(ctx context.Context, id, argsHash, reason string, via contracts.DecisionVia) error {
	return s.decide(ctx, id, argsHash, contracts.DecisionDenied, reason, "", time.Time{}, &via)
}

func (s *Store) decide(ctx context.Context, id, argsHash, decision, reason string, scope contracts.GrantScope, until time.Time, via *contracts.DecisionVia) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	x, err := scan(tx.QueryRowContext(ctx, `SELECT `+cols+` FROM approvals WHERE id=?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotPending
	}
	if err != nil {
		return err
	}
	if x.status != "pending" || !s.now().Before(x.exp) {
		return ErrNotPending
	}
	if argsHash != x.req.ArgsHash {
		return ErrArgsHashMismatch
	}
	now := s.now().UTC().Truncate(time.Second)
	d := contracts.ApprovalDecision{
		ApprovalID: id, CallID: x.req.CallID, ArgsHash: x.req.ArgsHash, Decision: decision,
		ApproverID: hex.EncodeToString(s.priv.Public().(ed25519.PublicKey)), Reason: reason, Ts: now, Via: via,
	}
	if scope != "" {
		g := contracts.Grant{ID: ulid.Make().String(), ApprovalID: id, Scope: scope, AgentID: x.req.Principal.AgentID,
			Server: x.req.Server, Tool: x.req.Tool, Until: until}
		switch scope {
		case contracts.GrantScopeRun:
			g.RunID = x.req.Principal.RunID
			if g.Until.IsZero() {
				g.Until = s.now().Add(24 * time.Hour)
			}
		case contracts.GrantScopeAgent:
			if until.IsZero() {
				return fmt.Errorf("%w: agent scope needs until", ErrBadGrant)
			}
		default:
			return fmt.Errorf("%w: scope %q", ErrBadGrant, scope)
		}
		g.Until = g.Until.UTC()
		gb, _ := json.Marshal(g)
		if _, err := tx.ExecContext(ctx, `INSERT INTO grants (id, agent_id, grant_json) VALUES (?,?,?)`, g.ID, g.AgentID, string(gb)); err != nil {
			return err
		}
		d.Grant = &g
	}
	payload, err := json.Marshal(map[string]string{"approval_id": id, "args_hash": d.ArgsHash, "decision": decision, "ts": now.Format(time.RFC3339)})
	if err != nil {
		return err
	}
	canon, err := jcs.Transform(payload)
	if err != nil {
		return err
	}
	d.ApproverSig = hex.EncodeToString(ed25519.Sign(s.priv, canon))
	db, err := json.Marshal(d)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE approvals SET status=?, decision=? WHERE id=?`, decision, string(db), id); err != nil {
		return err
	}
	return tx.Commit()
}
