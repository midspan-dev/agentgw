package pipeline

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gowebpki/jcs"
	"github.com/midspan-dev/agentgw/internal/ledger"

	"github.com/midspan-dev/agentgw/pkg/contracts"
)

const pv = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"

type pricer struct {
	m   int64
	err error
}

func (p pricer) Estimate(context.Context, string, string, json.RawMessage) (contracts.Money, error) {
	return contracts.Money{Micros: p.m, Currency: "USD"}, p.err
}

type decider struct {
	out  contracts.DecisionOutput
	err  error
	in   contracts.DecisionInput
	hook func()
}

func (d *decider) Decide(_ context.Context, in contracts.DecisionInput) (contracts.DecisionOutput, error) {
	d.in = in
	if d.hook != nil {
		d.hook()
	}
	d.out.PolicyVersion = pv
	return d.out, d.err
}

type bud struct {
	reserved, settled, released int
	actual                      contracts.Money
	hook                        func()
	remHook                     func() // runs inside Remaining
	once                        sync.Once
	lock                        chan struct{}
	held                        atomic.Bool
}

func (b *bud) Exclusive(ctx context.Context, fn func() error) error {
	b.once.Do(func() { b.lock = make(chan struct{}, 1) })
	select {
	case b.lock <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	b.held.Store(true)
	defer func() { b.held.Store(false); <-b.lock }()
	return fn()
}

func (b *bud) Reserve(context.Context, contracts.BudgetScope, contracts.Money) (string, error) {
	b.reserved++
	if b.hook != nil {
		b.hook()
	}
	return "r1", nil
}
func (b *bud) Settle(_ context.Context, _ string, m contracts.Money) error {
	b.settled++
	b.actual = m
	return nil
}
func (b *bud) Release(context.Context, string) error { b.released++; return nil }
func (b *bud) Remaining(ctx context.Context, _ contracts.BudgetScope) (map[contracts.Window]contracts.Money, error) {
	if b.remHook != nil {
		b.remHook()
	}
	return map[contracts.Window]contracts.Money{}, ctx.Err()
}

type led struct {
	entries   []contracts.Entry
	err       error // sticky Err()
	appendErr error
	mu        sync.Mutex
}

func (l *led) Err() error { return l.err }
func (l *led) Append(ctx context.Context, e *contracts.Entry) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if l.appendErr != nil {
		return l.appendErr
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.entries = append(l.entries, *e)
	return nil
}
func (l *led) Checkpoint(context.Context) (*contracts.Checkpoint, error) { return nil, nil }
func (l *led) Verify(context.Context) (*contracts.VerifyReport, error)   { return nil, nil }
func (l *led) Redact(raw json.RawMessage) json.RawMessage                { return raw }

type approver struct {
	dec    *contracts.ApprovalDecision
	err    error
	wait   func(ctx context.Context) // optional hook
	onWait func()                    // runs inside Wait before returning dec/err
}

func (a *approver) Request(context.Context, contracts.ApprovalRequest) (string, error) {
	return "a1", nil
}
func (a *approver) Wait(ctx context.Context, _ string, _ func(string)) (*contracts.ApprovalDecision, error) {
	if a.wait != nil {
		a.wait(ctx)
		return nil, ctx.Err()
	}
	if a.onWait != nil {
		a.onWait()
	}
	return a.dec, a.err
}
func (a *approver) Grants(context.Context, contracts.Principal) ([]contracts.Grant, error) {
	return []contracts.Grant{}, nil
}

type fixture struct {
	d   *decider
	b   *bud
	l   *led
	a   *approver
	ic  contracts.Interceptor
	fwd int
}

func newFixture(out contracts.DecisionOutput, derr error, forward func() (json.RawMessage, error)) (*fixture, *contracts.Call) {
	f := &fixture{d: &decider{out: out, err: derr}, b: &bud{}, l: &led{}, a: &approver{}}
	f.ic = New(Deps{Principal: contracts.Principal{AgentID: "a", Owner: "o", RunID: "r", SessionID: "ignored"},
		Pricer: pricer{m: 7}, Decider: f.d, Budget: f.b, Ledger: f.l, Approver: f.a, Currency: "USD"})
	call := &contracts.Call{ID: "0123456789abcdef0123456789abcdef", Server: "s", Tool: "t", Args: json.RawMessage(`{"x":1}`),
		SessionID: "sess", InputResponses: json.RawMessage(`{"q":"yes"}`), RequestState: "st",
		Progress: func(string) {},
		Forward:  func(context.Context) (json.RawMessage, error) { f.fwd++; return forward() }}
	return f, call
}

func ok() (json.RawMessage, error) { return json.RawMessage(`{"content":[]}`), nil }

func TestAllowSettlesWithEstimateAndRecordsCall(t *testing.T) {
	f, call := newFixture(contracts.DecisionOutput{Outcome: contracts.OutcomeAllow, RuleID: "r"}, nil, ok)
	if _, err := f.ic.Intercept(context.Background(), call); err != nil {
		t.Fatal(err)
	}
	e := f.l.entries[0]
	if f.b.settled != 1 || f.b.actual.Micros != 7 || e.Cost.Actual.Micros != 7 || e.Outcome != contracts.EntryOK {
		t.Fatalf("settle/outcome: %+v %+v", f.b, e)
	}
	if e.Principal.SessionID != "sess" || f.d.in.Principal.SessionID != "sess" || e.Principal.RunID != "r" {
		t.Fatalf("principal: %+v", e.Principal)
	}
	if string(e.Action.InputResponses) != `{"q":"yes"}` || e.Action.RequestState != "st" || e.CallID != call.ID {
		t.Fatalf("action: %+v", e.Action)
	}
	if f.d.in.Context.EstimatedCost.Micros != 7 || f.d.in.Context.Time.IsZero() || f.d.in.Context.Grants == nil {
		t.Fatalf("context: %+v", f.d.in.Context)
	}
}

func TestCostFromResultWins(t *testing.T) {
	f, call := newFixture(contracts.DecisionOutput{Outcome: contracts.OutcomeAllow, RuleID: "r"}, nil, func() (json.RawMessage, error) {
		return json.RawMessage(`{"content":[],"_meta":{"cost":{"amount":0.5,"currency":"USD"}}}`), nil
	})
	f.ic.Intercept(context.Background(), call)
	if f.b.actual.Micros != 500000 {
		t.Fatalf("actual %+v", f.b.actual)
	}
}

func TestDecideErrorIsDeny(t *testing.T) {
	f, call := newFixture(contracts.DecisionOutput{}, errors.New("boom"), ok)
	_, err := f.ic.Intercept(context.Background(), call)
	var ce *contracts.CallError
	if !errors.As(err, &ce) || !errors.Is(err, contracts.ErrDenied) || ce.RuleID != contracts.RuleEvaluationError ||
		ce.Reason != "policy evaluation failed: boom" || ce.CallID != call.ID {
		t.Fatalf("err %#v", err)
	}
	e := f.l.entries[0]
	if e.Decision.Outcome != contracts.OutcomeDeny || e.Decision.RuleID != contracts.RuleEvaluationError ||
		e.Decision.PolicyVersion != pv || e.Outcome != contracts.EntryDenied || e.Result.Error != ce.Error() {
		t.Fatalf("entry %+v", e)
	}
	if f.fwd != 0 || f.b.reserved != 0 {
		t.Fatal("forwarded or reserved after a Decide error")
	}
}

func TestForwardNotSentReleases(t *testing.T) {
	f, call := newFixture(contracts.DecisionOutput{Outcome: contracts.OutcomeAllow, RuleID: "r"}, nil, func() (json.RawMessage, error) {
		return nil, fmt.Errorf("dial tcp: connection refused: %w", contracts.ErrNotSent)
	})
	_, err := f.ic.Intercept(context.Background(), call)
	var ce *contracts.CallError
	if !errors.As(err, &ce) || ce.CallID != call.ID || ce.Outcome() != contracts.EntryError || !errors.Is(err, contracts.ErrNotSent) {
		t.Fatalf("err %#v", err)
	}
	e := f.l.entries[0]
	if f.b.released != 1 || f.b.settled != 0 || e.Outcome != contracts.EntryError ||
		e.Result.Error != "dial tcp: connection refused: agentgw: request not sent upstream" || e.Cost.Actual.Micros != 0 {
		t.Fatalf("budget %+v entry %+v", f.b, e)
	}
}

// Any other Forward error, a cancel after the write included, may have run
// upstream: settle at the estimate, never refund (gap-006).
func TestForwardErrorMayHaveRunSettlesEstimate(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		text string
	}{
		{"upstream error", errors.New("upstream redirect (307) refused"), "upstream may have run: upstream redirect (307) refused"},
		{"cancel after send", context.Canceled, "upstream may have run: context canceled"},
	} {
		f, call := newFixture(contracts.DecisionOutput{Outcome: contracts.OutcomeAllow, RuleID: "r"}, nil, func() (json.RawMessage, error) {
			return nil, tc.err
		})
		res, err := f.ic.Intercept(context.Background(), call)
		if res != nil || !errors.Is(err, tc.err) || err.Error() != tc.text {
			t.Fatalf("%s: res %s err %v", tc.name, res, err)
		}
		e := f.l.entries[0]
		if f.b.released != 0 || f.b.settled != 1 || f.b.actual.Micros != 7 || e.Cost.Actual.Micros != 7 ||
			e.Outcome != contracts.EntryError || e.Result.Error != tc.text {
			t.Fatalf("%s: budget %+v entry %+v", tc.name, f.b, e)
		}
	}
}

func TestPricerErrorIsDenyWithItsReason(t *testing.T) {
	f, call := newFixture(contracts.DecisionOutput{Outcome: contracts.OutcomeAllow, RuleID: "r"}, nil, ok)
	f.ic = New(Deps{Principal: contracts.Principal{AgentID: "a", Owner: "o", RunID: "r"},
		Pricer:  pricer{err: errors.New(`unpriceable argument amount: "12abc" is not a number`)},
		Decider: f.d, Budget: f.b, Ledger: f.l, Approver: f.a, Currency: "USD"})
	_, err := f.ic.Intercept(context.Background(), call)
	var ce *contracts.CallError
	if !errors.As(err, &ce) || !errors.Is(err, contracts.ErrDenied) || ce.RuleID != contracts.RuleEvaluationError ||
		ce.Reason != `unpriceable argument amount: "12abc" is not a number` {
		t.Fatalf("err %v", err)
	}
	e := f.l.entries[0]
	if e.Outcome != contracts.EntryDenied || e.Decision.RuleID != contracts.RuleEvaluationError || e.Decision.PolicyVersion != pv ||
		e.Result.Error != ce.Error() || f.fwd != 0 || f.b.reserved != 0 {
		t.Fatalf("entry %+v fwd %d", e, f.fwd)
	}
}

// Remaining -> Grants -> Decide -> Reserve run inside Budget.Exclusive, so
// two pipeline instances sharing a Budget never decide concurrently, even
// for different tools (gap-006b).
func TestBudgetLockSharedAcrossInstances(t *testing.T) {
	f, _ := newFixture(contracts.DecisionOutput{Outcome: contracts.OutcomeAllow, RuleID: "r"}, nil, ok)
	other := New(Deps{Principal: contracts.Principal{AgentID: "a", Owner: "o", RunID: "r"},
		Pricer: pricer{m: 7}, Decider: f.d, Budget: f.b, Ledger: f.l, Approver: f.a, Currency: "USD"})
	var mu sync.Mutex
	in, maxIn := 0, 0
	f.d.hook = func() {
		if !f.b.held.Load() {
			t.Error("Decide ran outside Budget.Exclusive")
		}
		mu.Lock()
		in++
		maxIn = max(maxIn, in)
		mu.Unlock()
		time.Sleep(5 * time.Millisecond)
		mu.Lock()
		in--
		mu.Unlock()
	}
	var wg sync.WaitGroup
	for i := range 10 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, c := newFixture(contracts.DecisionOutput{}, nil, ok)
			c.Tool = fmt.Sprintf("t%d", i)
			ic := f.ic
			if i%2 == 1 {
				ic = other
			}
			ic.Intercept(context.Background(), c)
		}()
	}
	wg.Wait()
	if maxIn != 1 {
		t.Fatalf("%d Decides ran concurrently on one Budget", maxIn)
	}
	if f.b.reserved != 10 {
		t.Fatalf("reserved %d, want 10", f.b.reserved)
	}
}

// The lock is not held across Approver.Wait or Forward; the post-approval
// Reserve takes it again.
func TestBudgetLockNotHeldAcrossWaitOrForward(t *testing.T) {
	need := contracts.DecisionOutput{Outcome: contracts.OutcomeRequireApproval, RuleID: "r", Approval: &contracts.ApprovalSpec{TimeoutSeconds: 5}}
	var f *fixture
	f, call := newFixture(need, nil, func() (json.RawMessage, error) {
		if f.b.held.Load() {
			t.Error("Budget lock held across Forward")
		}
		return ok()
	})
	f.a.dec = &contracts.ApprovalDecision{Decision: contracts.DecisionApproved, CallID: call.ID, ArgsHash: argsHash(t, `{"x":1}`)}
	f.a.onWait = func() {
		if f.b.held.Load() {
			t.Error("Budget lock held across Approver.Wait")
		}
	}
	f.b.hook = func() {
		if !f.b.held.Load() {
			t.Error("post-approval Reserve ran outside Budget.Exclusive")
		}
	}
	if _, err := f.ic.Intercept(context.Background(), call); err != nil {
		t.Fatal(err)
	}
	if f.fwd != 1 || f.b.reserved != 1 {
		t.Fatalf("fwd %d reserved %d", f.fwd, f.b.reserved)
	}
}

// A client that gives up while waiting for the lock is recorded as outcome
// error with decision deny/evaluation-error (the Decider's policy_version)
// and the ctx error is returned, never a deny result.
func TestCancelWhileWaitingForBudgetLock(t *testing.T) {
	f, call := newFixture(contracts.DecisionOutput{Outcome: contracts.OutcomeAllow, RuleID: "r"}, nil, ok)
	release := make(chan struct{})
	held := make(chan struct{})
	go f.b.Exclusive(context.Background(), func() error { close(held); <-release; return nil })
	<-held
	defer close(release)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err := f.ic.Intercept(ctx, call)
	if !errors.Is(err, context.DeadlineExceeded) || errors.Is(err, contracts.ErrDenied) {
		t.Fatalf("err %v", err)
	}
	e := f.l.entries[0]
	if e.Outcome != contracts.EntryError || e.Decision.Outcome != contracts.OutcomeDeny || e.Decision.RuleID != contracts.RuleEvaluationError ||
		e.Decision.PolicyVersion != pv || e.Result.Error != "context deadline exceeded" || f.fwd != 0 || f.b.reserved != 0 {
		t.Fatalf("entry %+v fwd %d reserved %d", e, f.fwd, f.b.reserved)
	}
	if string(f.d.in.Action.Args) != `{}` {
		t.Fatalf("version-only Decide saw args %s", f.d.in.Action.Args)
	}
}

// A cancel while waiting for the second (post-approval) lock keeps the real
// decision and the approval, outcome error.
func TestCancelWhileWaitingForPostApprovalLock(t *testing.T) {
	need := contracts.DecisionOutput{Outcome: contracts.OutcomeRequireApproval, RuleID: "r", Approval: &contracts.ApprovalSpec{TimeoutSeconds: 5}}
	f, call := newFixture(need, nil, ok)
	ctx, cancel := context.WithCancel(context.Background())
	release := make(chan struct{})
	defer close(release)
	f.a.dec = &contracts.ApprovalDecision{Decision: contracts.DecisionApproved, CallID: call.ID, ArgsHash: argsHash(t, `{"x":1}`)}
	f.a.onWait = func() { // another call takes the lock while this one waits for a human
		held := make(chan struct{})
		go f.b.Exclusive(context.Background(), func() error { close(held); <-release; return nil })
		<-held
		cancel()
	}
	_, err := f.ic.Intercept(ctx, call)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err %v", err)
	}
	e := f.l.entries[0]
	if e.Outcome != contracts.EntryError || e.Decision.Outcome != contracts.OutcomeRequireApproval || e.Decision.RuleID != "r" ||
		e.Decision.Approval == nil || f.fwd != 0 || f.b.reserved != 0 {
		t.Fatalf("entry %+v fwd %d reserved %d", e, f.fwd, f.b.reserved)
	}
}

func TestApprovalDeniedRecordsDecision(t *testing.T) {
	f, call := newFixture(contracts.DecisionOutput{Outcome: contracts.OutcomeRequireApproval, RuleID: "r",
		Approval: &contracts.ApprovalSpec{TimeoutSeconds: 5}}, nil, ok)
	f.a.dec = &contracts.ApprovalDecision{Decision: contracts.DecisionDenied, Reason: "no"}
	f.a.err = &contracts.CallError{Err: contracts.ErrApprovalDenied, RuleID: "r", Reason: "no"}
	_, err := f.ic.Intercept(context.Background(), call)
	if !errors.Is(err, contracts.ErrApprovalDenied) {
		t.Fatal(err)
	}
	e := f.l.entries[0]
	if e.Outcome != contracts.EntryApprovalDenied || e.Decision.Approval == nil || e.Result.Error != "agentgw: approval denied: no" || f.fwd != 0 {
		t.Fatalf("entry %+v", e)
	}
}

func TestCancelWhileHeldStillRecords(t *testing.T) {
	f, call := newFixture(contracts.DecisionOutput{Outcome: contracts.OutcomeRequireApproval, RuleID: "r",
		Approval: &contracts.ApprovalSpec{TimeoutSeconds: 5}}, nil, ok)
	ctx, cancel := context.WithCancel(context.Background())
	f.a.wait = func(ctx context.Context) { cancel(); <-ctx.Done() }
	_, err := f.ic.Intercept(ctx, call)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err %v", err)
	}
	if len(f.l.entries) != 1 || f.l.entries[0].Outcome != contracts.EntryError || f.fwd != 0 {
		t.Fatalf("entries %+v", f.l.entries)
	}
}

func argsHash(t *testing.T, raw string) string {
	c, err := jcs.Transform([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(c)
	return hex.EncodeToString(sum[:])
}

func TestApprovedDecisionMustBeBoundToCall(t *testing.T) {
	need := contracts.DecisionOutput{Outcome: contracts.OutcomeRequireApproval, RuleID: "r",
		Approval: &contracts.ApprovalSpec{TimeoutSeconds: 5}}
	for _, tc := range []struct {
		name, callID, hash string
		forwarded          bool
	}{
		{"bound", "0123456789abcdef0123456789abcdef", argsHash(t, `{"x":1}`), true},
		{"other call", "ffffffffffffffffffffffffffffffff", argsHash(t, `{"x":1}`), false},
		{"other args", "0123456789abcdef0123456789abcdef", argsHash(t, `{"x":2}`), false},
	} {
		f, call := newFixture(need, nil, ok)
		f.a.dec = &contracts.ApprovalDecision{Decision: contracts.DecisionApproved, CallID: tc.callID, ArgsHash: tc.hash}
		_, err := f.ic.Intercept(context.Background(), call)
		if (f.fwd == 1) != tc.forwarded || (err == nil) != tc.forwarded {
			t.Errorf("%s: forwarded=%d err=%v", tc.name, f.fwd, err)
		}
		if len(f.l.entries) != 1 || f.l.entries[0].Decision.Approval == nil {
			t.Errorf("%s: entries %+v", tc.name, f.l.entries)
		}
	}
}

func TestCancelBeforeDecideIsNotADeny(t *testing.T) {
	f, call := newFixture(contracts.DecisionOutput{Outcome: contracts.OutcomeAllow, RuleID: "allow-all"}, nil, ok)
	ctx, cancel := context.WithCancel(context.Background())
	f.b.remHook = cancel // the client goes away inside the lock; Remaining fails with context.Canceled
	_, err := f.ic.Intercept(ctx, call)
	if !errors.Is(err, context.Canceled) || errors.Is(err, contracts.ErrDenied) {
		t.Fatalf("err %v", err)
	}
	e := f.l.entries[0]
	if e.Outcome != contracts.EntryError || e.Decision.RuleID == contracts.RuleEvaluationError || f.fwd != 0 {
		t.Fatalf("entry %+v forwarded %d", e, f.fwd)
	}
}

// Inputs the ledger cannot canonicalise must never reach the upstream; with a
// real ledger, unhashable inputResponses still leave an entry.
func TestUncanonicalInputsNeverForwarded(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	for _, tc := range []struct {
		name, args, ir, label string
		entries               int
	}{
		{"args", `{"a":1e400}`, "", "args", 1},
		{"inputResponses", `{"amount":5}`, `{"a":1e400}`, "input_responses", 1},
	} {
		path := filepath.Join(t.TempDir(), "l.jsonl")
		l, err := ledger.Open(contracts.LedgerConfig{Path: path, CheckpointEvery: 100}, key, contracts.RedactionConfig{})
		if err != nil {
			t.Fatal(err)
		}
		f, call := newFixture(contracts.DecisionOutput{Outcome: contracts.OutcomeAllow, RuleID: "allow-all"}, nil, ok)
		f.ic = New(Deps{Principal: contracts.Principal{AgentID: "a", Owner: "o", RunID: "r"},
			Pricer: pricer{}, Decider: f.d, Budget: f.b, Ledger: l, Approver: f.a, Currency: "USD"})
		call.Args, call.InputResponses = json.RawMessage(tc.args), nil
		if tc.ir != "" {
			call.InputResponses = json.RawMessage(tc.ir)
		}
		_, err = f.ic.Intercept(context.Background(), call)
		l.Close()
		if !errors.Is(err, contracts.ErrDenied) || f.fwd != 0 || f.b.reserved != 0 {
			t.Fatalf("%s: err=%v forwarded=%d reserved=%d", tc.name, err, f.fwd, f.b.reserved)
		}
		b, _ := os.ReadFile(path)
		if n := strings.Count(string(b), "\n"); n != tc.entries {
			t.Fatalf("%s: %d ledger lines, want %d", tc.name, n, tc.entries)
		}
		if !strings.Contains(string(b), `"rule_id":"evaluation-error"`) || strings.Contains(string(b), `"input_responses":`) ||
			!strings.Contains(string(b), `"args":{}`) || !strings.Contains(string(b), "arguments not canonicalisable: "+tc.label+": numbers must be finite IEEE-754 doubles") {
			t.Fatalf("%s: entry %s", tc.name, b)
		}
	}
}

var errBroken = errors.New("disk gone")

// A sticky broken ledger refuses before any side effect, at each check point.
func TestLedgerUnavailable(t *testing.T) {
	allow := contracts.DecisionOutput{Outcome: contracts.OutcomeAllow, RuleID: "r"}
	for _, tc := range []struct {
		name               string
		arm                func(f *fixture)
		reserved, released int
	}{
		{"at start", func(f *fixture) { f.l.err = errBroken }, 0, 0},
		{"before reserve", func(f *fixture) { f.d.hook = func() { f.l.err = errBroken } }, 0, 0},
		{"before forward", func(f *fixture) { f.b.hook = func() { f.l.err = errBroken } }, 1, 1},
	} {
		f, call := newFixture(allow, nil, ok)
		tc.arm(f)
		_, err := f.ic.Intercept(context.Background(), call)
		var ce *contracts.CallError
		if !errors.As(err, &ce) || !errors.Is(err, contracts.ErrLedgerUnavailable) || ce.CallID != call.ID ||
			err.Error() != "agentgw: ledger unavailable, call not forwarded: disk gone" {
			t.Fatalf("%s: err %v", tc.name, err)
		}
		if f.fwd != 0 || len(f.l.entries) != 0 || f.b.reserved != tc.reserved || f.b.released != tc.released || f.b.settled != 0 {
			t.Fatalf("%s: fwd=%d entries=%d budget=%+v", tc.name, f.fwd, len(f.l.entries), f.b)
		}
	}
}

func TestAppendFailureAfterForwardIsNotRecorded(t *testing.T) {
	f, call := newFixture(contracts.DecisionOutput{Outcome: contracts.OutcomeAllow, RuleID: "r"}, nil, ok)
	f.l.appendErr = errors.New("ENOSPC")
	res, err := f.ic.Intercept(context.Background(), call)
	var ce *contracts.CallError
	if res != nil || !errors.As(err, &ce) || !errors.Is(err, contracts.ErrNotRecorded) || ce.CallID != call.ID ||
		err.Error() != "agentgw: upstream call completed but could not be recorded: ENOSPC" {
		t.Fatalf("res %s err %v", res, err)
	}
	if f.fwd != 1 || f.b.settled != 1 {
		t.Fatalf("fwd=%d budget=%+v", f.fwd, f.b)
	}

	// Before Forward the text must not claim the upstream ran.
	f, call = newFixture(contracts.DecisionOutput{Outcome: contracts.OutcomeDeny, RuleID: "r", Reason: "denied by rule r"}, nil, ok)
	f.l.appendErr = errors.New("ENOSPC")
	_, err = f.ic.Intercept(context.Background(), call)
	if errors.Is(err, contracts.ErrNotRecorded) || err == nil || !strings.HasPrefix(err.Error(), "ledger append failed: ") || f.fwd != 0 {
		t.Fatalf("pre-forward append failure: %v", err)
	}
}

// Keys an upstream could read either way (case variants, NFC variants, exact
// duplicates) are refused before pricing with the validator's reason and
// recorded with args {} (gap-006 ruling 1).
func TestCollidingKeysDenied(t *testing.T) {
	for _, tc := range []struct {
		name, args, ir, reason, recorded string
	}{
		{"case variant", `{"amount":5,"Amount":500}`, "", "argument keys collide: amount, Amount", `{}`},
		{"nested in inputResponses", `{"x":1}`, `{"a":[{"k":1,"K":2}]}`, "argument keys collide: k, K", `{}`},
	} {
		f, call := newFixture(contracts.DecisionOutput{Outcome: contracts.OutcomeAllow, RuleID: "allow-all"}, nil, ok)
		call.Args, call.InputResponses = json.RawMessage(tc.args), nil
		if tc.ir != "" {
			call.InputResponses = json.RawMessage(tc.ir)
		}
		_, err := f.ic.Intercept(context.Background(), call)
		var ce *contracts.CallError
		if !errors.As(err, &ce) || !errors.Is(err, contracts.ErrDenied) || ce.RuleID != contracts.RuleEvaluationError || ce.Reason != tc.reason {
			t.Fatalf("%s: err %v", tc.name, err)
		}
		e := f.l.entries[0]
		if f.fwd != 0 || f.b.reserved != 0 || e.Outcome != contracts.EntryDenied || e.Result.Error != ce.Error() {
			t.Fatalf("%s: fwd %d entry %+v", tc.name, f.fwd, e)
		}
		var got, want any
		json.Unmarshal(e.Action.Args, &got)
		json.Unmarshal([]byte(tc.recorded), &want)
		if fmt.Sprint(got) != fmt.Sprint(want) {
			t.Fatalf("%s: recorded args %s, want {}", tc.name, e.Action.Args)
		}
		if e.Action.InputResponses != nil {
			t.Fatalf("%s: input_responses recorded", tc.name)
		}
	}
}
