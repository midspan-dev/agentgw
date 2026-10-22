package budget

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/midspan-dev/agentgw/pkg/contracts"
	"golang.org/x/text/unicode/norm"
	_ "modernc.org/sqlite"
)

// Store is a SQLite-backed contracts.Budget.
type Store struct {
	db       *sql.DB
	currency string // the single gateway currency, from the limits
	limits   []contracts.BudgetLimit
	now      func() time.Time
	lock     chan struct{} // Exclusive's store-wide lock
}

var _ contracts.Budget = (*Store)(nil)

const schema = `CREATE TABLE IF NOT EXISTS reservations (
	id TEXT PRIMARY KEY,
	agent TEXT NOT NULL, run_id TEXT NOT NULL, server TEXT NOT NULL, tool TEXT NOT NULL,
	micros INTEGER NOT NULL, currency TEXT NOT NULL,
	settled INTEGER NOT NULL DEFAULT 0,
	created INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS reservations_run ON reservations(run_id);
CREATE INDEX IF NOT EXISTS reservations_created ON reservations(created);`

// Open opens (creating if needed) the budget database at path.
func Open(path string, limits []contracts.BudgetLimit) (*Store, error) {
	limits = append([]contracts.BudgetLimit(nil), limits...)
	for i := range limits {
		limits[i].Agent, limits[i].Tool = norm.NFC.String(limits[i].Agent), norm.NFC.String(limits[i].Tool)
	}
	var cur string
	for _, l := range limits {
		switch l.Window {
		case contracts.WindowPerRun, contracts.WindowDaily, contracts.WindowMonthly:
		default:
			return nil, fmt.Errorf("budget: unknown window %q", l.Window)
		}
		if cur == "" {
			cur = l.Limit.Currency
		}
		if l.Limit.Currency == "" || l.Limit.Currency != cur {
			return nil, fmt.Errorf("budget: limits must share one non-empty currency, got %q and %q", cur, l.Limit.Currency)
		}
	}
	file := strings.NewReplacer("%", "%25", "?", "%3f", "#", "%23").Replace(path)
	db, err := sql.Open("sqlite", "file:"+file+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, err
	}
	// One connection serialises every transaction, which makes Reserve atomic.
	// shortcut: single-process counters only; multi-process needs BEGIN IMMEDIATE (out of scope).
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, err
	}
	return &Store{db: db, currency: cur, limits: limits, now: time.Now, lock: make(chan struct{}, 1)}, nil
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

var windows = []contracts.Window{contracts.WindowPerRun, contracts.WindowDaily, contracts.WindowMonthly}

// nfcScope normalises the matched identifiers so NFC and NFD spellings share limits.
func nfcScope(sc contracts.BudgetScope) contracts.BudgetScope {
	sc.AgentID, sc.Server, sc.Tool = norm.NFC.String(sc.AgentID), norm.NFC.String(sc.Server), norm.NFC.String(sc.Tool)
	return sc
}

func matches(l contracts.BudgetLimit, sc contracts.BudgetScope) bool {
	return glob(l.Agent, sc.AgentID) && glob(l.Tool, sc.Server+"."+sc.Tool)
}

// spent sums settled and open reservations that fall under limit l in its current window.
func (s *Store) spent(ctx context.Context, tx *sql.Tx, l contracts.BudgetLimit, sc contracts.BudgetScope) (int64, error) {
	now := s.now().UTC()
	q := `SELECT agent, server, tool, micros FROM reservations WHERE currency = ? AND `
	args := []any{l.Limit.Currency}
	switch l.Window {
	case contracts.WindowPerRun:
		q += `run_id = ?`
		args = append(args, sc.RunID)
	case contracts.WindowDaily:
		q += `created >= ?`
		args = append(args, time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC).UnixNano())
	case contracts.WindowMonthly:
		q += `created >= ?`
		args = append(args, time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC).UnixNano())
	default:
		return 0, fmt.Errorf("budget: unknown window %q", l.Window)
	}
	rows, err := tx.QueryContext(ctx, q, args...)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	var sum int64
	for rows.Next() {
		var agent, server, tool string
		var m int64
		if err := rows.Scan(&agent, &server, &tool, &m); err != nil {
			return 0, err
		}
		if glob(l.Agent, agent) && glob(l.Tool, server+"."+tool) {
			sum = satAdd(sum, m)
		}
	}
	return sum, rows.Err()
}

// check rejects negative amounts and any currency other than the gateway's.
func (s *Store) check(m contracts.Money) error {
	if m.Micros < 0 {
		return fmt.Errorf("budget: negative amount %d", m.Micros)
	}
	if m.Currency == "" || (s.currency != "" && m.Currency != s.currency) {
		return fmt.Errorf("budget: currency %q does not match gateway currency %q", m.Currency, s.currency)
	}
	return nil
}

func (s *Store) Reserve(ctx context.Context, sc contracts.BudgetScope, amount contracts.Money) (string, error) {
	sc = nfcScope(sc)
	if err := s.check(amount); err != nil {
		return "", err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	for _, w := range windows {
		for _, l := range s.limits {
			if l.Window != w || !matches(l, sc) {
				continue
			}
			sum, err := s.spent(ctx, tx, l, sc)
			if err != nil {
				return "", err
			}
			if sum > l.Limit.Micros || amount.Micros > l.Limit.Micros-sum {
				return "", &contracts.CallError{Err: contracts.ErrBudgetExceeded, Window: w, Reason: string(w) + " budget exceeded"}
			}
		}
	}
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	id := hex.EncodeToString(b[:])
	_, err = tx.ExecContext(ctx, `INSERT INTO reservations (id, agent, run_id, server, tool, micros, currency, created) VALUES (?,?,?,?,?,?,?,?)`,
		id, sc.AgentID, sc.RunID, sc.Server, sc.Tool, amount.Micros, amount.Currency, s.now().UTC().UnixNano())
	if err != nil {
		return "", err
	}
	return id, tx.Commit()
}

func one(res sql.Result, err error, id string) error {
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return fmt.Errorf("budget: reservation %q unknown or closed", id)
	}
	return nil
}

func (s *Store) Settle(ctx context.Context, id string, actual contracts.Money) error {
	if err := s.check(actual); err != nil {
		return err
	}
	res, err := s.db.ExecContext(ctx, `UPDATE reservations SET micros = ?, currency = ?, settled = 1 WHERE id = ? AND settled = 0`,
		actual.Micros, actual.Currency, id)
	return one(res, err, id)
}

func (s *Store) Release(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM reservations WHERE id = ? AND settled = 0`, id)
	return one(res, err, id)
}

func (s *Store) Remaining(ctx context.Context, sc contracts.BudgetScope) (map[contracts.Window]contracts.Money, error) {
	sc = nfcScope(sc)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	out := map[contracts.Window]contracts.Money{}
	for _, l := range s.limits {
		if !matches(l, sc) {
			continue
		}
		sum, err := s.spent(ctx, tx, l, sc)
		if err != nil {
			return nil, err
		}
		rem := max(l.Limit.Micros-sum, 0)
		if cur, ok := out[l.Window]; !ok || rem < cur.Micros {
			out[l.Window] = contracts.Money{Micros: rem, Currency: l.Limit.Currency}
		}
	}
	return out, nil
}

// Exclusive runs fn under the store-wide lock. Not reentrant.
// shortcut: single-process lock; multi-node budgets are control-plane (ADR 0003).
func (s *Store) Exclusive(ctx context.Context, fn func() error) error {
	select {
	case s.lock <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	defer func() { <-s.lock }()
	return fn()
}
