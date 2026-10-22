// Package pipeline is the gateway's request pipeline: one contracts.Interceptor
// that runs every tools/call through five stages in fixed order.
//
//  1. identify: Deps.Principal with SessionID from the Call.
//  2. price:    Pricer.Estimate, then the gateway-built DecisionContext
//     (clock, estimate, Budget.Remaining, Approver.Grants).
//  3. decide:   Decider.Decide; on require_approval, Approver.Request then
//     Approver.Wait (forwarding progress to the client).
//  4. reserve:  Budget.Reserve with the estimate. Remaining -> Grants -> Decide
//     -> Reserve run inside one Budget.Exclusive; on require_approval the lock
//     is let go for Request/Wait and the Reserve runs in a second Exclusive.
//  5. forward, settle, record: Call.Forward; Settle with
//     budget.CostFromResult -> estimate (zero for unpriced tools); on a Forward
//     error Release only if it wraps ErrNotSent, else Settle at the estimate
//     (the upstream may have run); Ledger.Append. Record is never skipped: every call id yields
//     exactly one entry, whatever happened before.
//
// Error mapping. Every returned error is a *contracts.CallError with CallID
// set; result.error in the entry is that error's Error() text.
//
//	stage    failure                          ledger outcome    returned CallError
//	any      Ledger.Err() non-nil (start,     nothing written   ErrLedgerUnavailable, reason = the ledger error
//	         before Reserve, before Forward)                    (nothing reserved or forwarded)
//	price    proxy.ValidateParams fails       denied ****       ErrDenied, evaluation-error (never forwarded)
//	price    args/inputResponses not JCS-able denied **         ErrDenied, evaluation-error (never forwarded)
//	price    Estimate error                   denied ***        ErrDenied, evaluation-error
//	price    Remaining/Grants error           denied *          ErrDenied, evaluation-error
//	decide   Decide error                     denied *          ErrDenied, evaluation-error
//	decide   ctx done (client went away)      error             Err: ctx error (proxy drops)
//	decide   ctx done waiting for the lock    error, decision   Err: ctx error (proxy drops)
//	                                          deny/evaluation-error
//	decide   deny                             denied            ErrDenied, DecisionOutput.Reason
//	decide   approval denied                  approval_denied   the Approver's (ErrApprovalDenied)
//	decide   approval timeout                 approval_timeout  the Approver's (ErrApprovalTimeout)
//	decide   Request/Wait other error         error             Err: the error
//	reserve  over a limit                     budget_exceeded   the Budget's (ErrBudgetExceeded)
//	reserve  other error                      error             Err: the error
//	forward  Forward error wrapping ErrNotSent error, released   Err: the error
//	forward  any other Forward error          error, settled    Err: "upstream may have run: <err>" (wraps it;
//	         (3xx, cancel after send, ...)    at the estimate   a ctx error is still dropped by the proxy)
//	record   Append error before Forward      nothing written   Err: "ledger append failed: ..."
//	record   Append error after Forward       nothing written   ErrNotRecorded, reason = the append error
//	                                                            (result withheld; Settle already ran)
//
//	* decision rule_id evaluation-error, reason "policy evaluation failed: <err>",
//	  policy_version from the Decider's output.
//	*** same, reason = the Pricer's error text ("unpriceable argument <field>: <why>").
//	** same, reason "arguments not canonicalisable: <err>", entry args {} and
//	  no input_responses (the raw bytes cannot be hashed).
//	**** same, reason "argument keys collide: <k1>, <k2>" for a collision, else
//	  "arguments not canonicalisable: args|input_responses: <validator error>";
//	  entry args {} and no input_responses, as **.
//
// A CallError whose Err is not a sentinel has Outcome() EntryError, which the
// proxy maps to JSON-RPC -32603; one wrapping context.Canceled is dropped.
// Client cancellation at any stage before forwarding is recorded as outcome
// error, never as a deny.
// result.error is CallError.Error() for refusals and the error text otherwise.
package pipeline

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/gowebpki/jcs"
	"github.com/midspan-dev/agentgw/internal/budget"
	"github.com/midspan-dev/agentgw/internal/proxy"
	"github.com/midspan-dev/agentgw/pkg/contracts"
)

// Deps is everything one pipeline instance uses. Principal.SessionID is
// ignored (it comes from each Call).
type Deps struct {
	Principal contracts.Principal
	Pricer    contracts.Pricer
	Decider   contracts.Decider
	Budget    contracts.Budget
	Ledger    contracts.Ledger
	Approver  contracts.Approver
	Currency  string
}

type pipeline struct{ d Deps }

// New returns an Interceptor over deps. It does no I/O and keeps no global
// state; call it again with a new Decider to apply a policy change. Instances
// sharing a Budget share its lock (Budget.Exclusive).
func New(deps Deps) contracts.Interceptor { return &pipeline{d: deps} }

func (p *pipeline) Intercept(ctx context.Context, call *contracts.Call) (json.RawMessage, error) {
	d := p.d
	// identify
	who := d.Principal
	who.SessionID = call.SessionID
	zero := contracts.Money{Currency: d.Currency}
	e := &contracts.Entry{
		CallID:    call.ID,
		Principal: who,
		Action: contracts.EntryAction{Server: call.Server, Tool: call.Tool, Args: call.Args,
			InputResponses: call.InputResponses, RequestState: call.RequestState},
		Cost: contracts.EntryCost{Estimated: zero, Actual: zero},
	}
	scope := contracts.BudgetScope{AgentID: who.AgentID, RunID: who.RunID, Server: call.Server, Tool: call.Tool}

	// unavailable refuses before any side effect when the ledger is stuck
	// broken; such a call cannot be recorded (gap-005).
	unavailable := func() error {
		if err := d.Ledger.Err(); err != nil {
			return &contracts.CallError{Err: contracts.ErrLedgerUnavailable, CallID: call.ID, Reason: err.Error()}
		}
		return nil
	}
	if err := unavailable(); err != nil {
		return nil, err
	}
	forwarded := false // the upstream call completed

	// record writes the entry with ctx's cancellation detached (a client that
	// went away still gets its entry) and returns err with CallID set.
	record := func(outcome contracts.EntryOutcome, content json.RawMessage, err error) (json.RawMessage, error) {
		e.Outcome, e.Result.Content = outcome, content
		if err != nil {
			e.Result.Error = err.Error()
		}
		if aerr := d.Ledger.Append(context.WithoutCancel(ctx), e); aerr != nil {
			if forwarded { // never hand back a result that is not on the record
				return nil, &contracts.CallError{Err: contracts.ErrNotRecorded, CallID: call.ID, Reason: aerr.Error()}
			}
			return nil, &contracts.CallError{Err: fmt.Errorf("ledger append failed: %w", aerr), CallID: call.ID}
		}
		if err != nil {
			var ce *contracts.CallError
			if !errors.As(err, &ce) {
				ce = &contracts.CallError{Err: err}
			}
			cp := *ce
			cp.CallID = call.ID
			return nil, &cp
		}
		return content, nil
	}

	// Inputs the gateway cannot safely interpret are never forwarded: deny
	// evaluation-error with the validator's reason (colliding keys, non-I-JSON
	// numbers) or "arguments not canonicalisable", recorded with args {} and
	// no input_responses.
	args := call.Args
	if len(args) == 0 {
		args = json.RawMessage(`{}`)
	}
	var argsHash string
	canon, cerr := jcs.Transform(args)
	if cerr != nil {
		cerr = fmt.Errorf("args: %w", cerr)
	} else {
		sum := sha256.Sum256(canon)
		argsHash = hex.EncodeToString(sum[:])
	}
	if ir := string(call.InputResponses); ir != "" && ir != "null" {
		if _, err := jcs.Transform(call.InputResponses); err != nil {
			cerr = errors.Join(cerr, fmt.Errorf("input_responses: %w", err))
		}
	}
	var bad string // refusal reason for unusable inputs
	if cerr != nil {
		bad = "arguments not canonicalisable: " + cerr.Error()
	}
	// Validated one member at a time so the reason names which one failed.
	// Collisions keep the validator's text; anything else is a canonicalisation
	// failure (gap-005 ruling 2).
	for _, m := range []struct {
		name     string
		args, ir json.RawMessage
	}{{"args", call.Args, nil}, {"input_responses", nil, call.InputResponses}} {
		if err := proxy.ValidateParams(m.args, m.ir); err != nil {
			if strings.HasPrefix(err.Error(), "argument keys collide: ") {
				bad = err.Error()
			} else {
				bad = "arguments not canonicalisable: " + m.name + ": " + err.Error()
			}
			break
		}
	}
	if bad != "" { // recorded as args {} per gap-006 ruling 1 and the brief
		args = json.RawMessage(`{}`)
		e.Action.Args, e.Action.InputResponses = args, nil
	}

	// price
	var est contracts.Money
	var perr error
	if bad == "" {
		est, perr = d.Pricer.Estimate(ctx, call.Server, call.Tool, call.Args)
	}
	if bad == "" && perr == nil {
		e.Cost.Estimated = est
	}
	in := contracts.DecisionInput{
		Version:   contracts.SchemaVersion,
		Principal: who,
		Action:    contracts.Action{Server: call.Server, Tool: call.Tool, Args: args},
		Context:   contracts.DecisionContext{Time: time.Now().UTC(), EstimatedCost: e.Cost.Estimated},
	}
	// Remaining -> Grants -> Decide -> Reserve run under the Budget's single
	// lock so a budget_remaining_below rule cannot be raced (gap-006b). The
	// lock is never held across Wait, Forward or a ledger write.
	var (
		out                   contracts.DecisionOutput
		ctxErr                error
		resID                 string
		reserveErr, ledgerErr error
	)
	reserve := func() { // inside Exclusive; Ledger.Err() immediately before Reserve
		if ledgerErr = unavailable(); ledgerErr == nil {
			resID, reserveErr = d.Budget.Reserve(ctx, scope, e.Cost.Estimated)
		}
	}
	decide := func() error {
		var rerr, gerr error
		if bad == "" && perr == nil {
			in.Context.BudgetRemaining, rerr = d.Budget.Remaining(ctx, scope)
		}
		if bad == "" && perr == nil && rerr == nil {
			in.Context.Grants, gerr = d.Approver.Grants(ctx, who)
		}
		// Decide runs even when the context failed, so the entry carries the
		// Decider's policy_version; its outcome is then discarded (fail closed).
		// A client that went away is not a policy deny: the entry keeps what
		// Decide answered, outcome error, and the ctx error goes back so the
		// proxy drops it.
		var derr error
		out, derr = d.Decider.Decide(ctx, in)
		ctxErr = ctx.Err()
		if ctxErr == nil {
			derr = errors.Join(perr, rerr, gerr, derr)
		}
		switch {
		case ctxErr == nil && bad != "":
			out.Outcome, out.RuleID = contracts.OutcomeDeny, contracts.RuleEvaluationError
			out.Reason = bad
		case ctxErr == nil && perr != nil: // the Pricer's own text, e.g. "unpriceable argument amount: ..."
			out.Outcome, out.RuleID = contracts.OutcomeDeny, contracts.RuleEvaluationError
			out.Reason = perr.Error()
		case derr != nil:
			out.Outcome, out.RuleID = contracts.OutcomeDeny, contracts.RuleEvaluationError
			out.Reason = "policy evaluation failed: " + derr.Error()
		}
		if ctxErr == nil && out.Outcome == contracts.OutcomeAllow {
			reserve()
		}
		return nil
	}
	// shortcut: single-process; multi-node budgets are control-plane (docs/adr/0003)
	if err := d.Budget.Exclusive(ctx, decide); err != nil {
		// ctx ended while waiting for the lock; decide never ran. Record it as
		// evaluation-error with the Decider's policy_version, outcome error.
		in.Action.Args = json.RawMessage(`{}`)
		v, _ := d.Decider.Decide(context.WithoutCancel(ctx), in)
		e.Decision = contracts.EntryDecision{Outcome: contracts.OutcomeDeny, RuleID: contracts.RuleEvaluationError,
			PolicyVersion: v.PolicyVersion}
		return record(contracts.EntryError, nil, err)
	}
	e.Decision = contracts.EntryDecision{Outcome: out.Outcome, RuleID: out.RuleID,
		PolicyVersion: out.PolicyVersion, GrantID: out.GrantID}
	if ctxErr != nil {
		return record(contracts.EntryError, nil, ctxErr)
	}

	switch out.Outcome {
	case contracts.OutcomeAllow:
	case contracts.OutcomeRequireApproval:
		if out.Approval == nil {
			return record(contracts.EntryError, nil, errors.New("pipeline: require_approval without an approval spec"))
		}
		id, err := d.Approver.Request(ctx, contracts.ApprovalRequest{
			CallID: call.ID, Principal: who, Server: call.Server, Tool: call.Tool,
			ArgsHash: argsHash, Args: d.Ledger.Redact(args),
			EstimatedCost: e.Cost.Estimated, RuleID: out.RuleID, Spec: *out.Approval,
		})
		if err != nil {
			return record(contracts.EntryError, nil, err)
		}
		dec, err := d.Approver.Wait(ctx, id, call.Progress)
		e.Decision.Approval = dec
		if err != nil {
			var ce *contracts.CallError
			if errors.As(err, &ce) {
				return record(ce.Outcome(), nil, err)
			}
			return record(contracts.EntryError, nil, err)
		}
		if dec == nil || dec.CallID != call.ID || dec.ArgsHash != argsHash { // defence in depth; the surface checks too
			return record(contracts.EntryError, nil, errors.New("pipeline: approval decision not bound to this call"))
		}
		// post-approval Reserve under the lock again; a cancel while waiting
		// keeps the real decision and approval, outcome error
		if err := d.Budget.Exclusive(ctx, func() error { reserve(); return nil }); err != nil {
			return record(contracts.EntryError, nil, err)
		}
	default: // deny, and any outcome this pipeline does not know
		return record(contracts.EntryDenied, nil,
			&contracts.CallError{Err: contracts.ErrDenied, RuleID: out.RuleID, Reason: out.Reason})
	}

	// reserve result
	if ledgerErr != nil {
		return nil, ledgerErr
	}
	if reserveErr != nil {
		var ce *contracts.CallError
		if errors.As(reserveErr, &ce) {
			return record(ce.Outcome(), nil, reserveErr)
		}
		return record(contracts.EntryError, nil, reserveErr)
	}

	// forward, settle, record
	if err := unavailable(); err != nil {
		d.Budget.Release(context.WithoutCancel(ctx), resID)
		return nil, err
	}
	res, err := call.Forward(ctx)
	if errors.Is(err, contracts.ErrNotSent) { // provably never left the gateway: refund
		// shortcut: a failed Release leaves the reservation counting against the budget (fails safe), not surfaced; upgrade when the gateway has a logger
		d.Budget.Release(context.WithoutCancel(ctx), resID)
		return record(contracts.EntryError, nil, err)
	}
	if err != nil { // the upstream may have run (cancel after send included): never refunded on doubt
		d.Budget.Settle(context.WithoutCancel(ctx), resID, e.Cost.Estimated)
		e.Cost.Actual = e.Cost.Estimated
		return record(contracts.EntryError, nil, fmt.Errorf("upstream may have run: %w", err))
	}
	actual, ok := budget.CostFromResult(res, d.Currency)
	if !ok {
		actual = e.Cost.Estimated
	}
	forwarded = true
	// shortcut: a failed Settle leaves the estimate reserved and is not surfaced; upgrade with a logger
	d.Budget.Settle(context.WithoutCancel(ctx), resID, actual)
	e.Cost.Actual = actual
	return record(contracts.EntryOK, res, nil)
}
