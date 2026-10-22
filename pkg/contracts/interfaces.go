package contracts

import (
	"context"
	"encoding/json"
	"time"
)

// Call is one MCP tools/call as the proxy hands it to the Interceptor.
type Call struct {
	// ID is assigned by the proxy before Intercept runs: 32 lower-case hex
	// characters from crypto/rand, unique across sessions. It becomes
	// Entry.CallID, ApprovalRequest.CallID and GatewayMeta.CallID.
	ID        string
	Server    string          // upstream name from config
	Tool      string          // tool name as the client sent it
	Args      json.RawMessage // the MCP arguments object; `{}` when absent, never nil
	SessionID string          // MCP session id; "" on stdio and in stateless HTTP (docs/adr/0008)

	// InputResponses and RequestState are the 2026-07-28 multi-round-trip
	// members of tools/call params (a retry after an input_required result).
	// Nil / "" when the call did not carry them. Forwarded as parsed; the
	// pipeline copies them into Entry.Action so the ledger records what the
	// human answered. Policy does not see them (contracts/policy-yaml.md).
	InputResponses json.RawMessage
	RequestState   string

	// Progress sends a progress notification to the client. Never nil: when
	// the client sent no progressToken it is a no-op. Safe from any goroutine
	// until Intercept returns.
	Progress func(msg string)

	// Forward performs the upstream call with Args and returns the raw
	// CallToolResult JSON. Call at most once. A tool-level isError result is
	// a successful return; transport and JSON-RPC failures are errors.
	// Forwarding rule (contracts/conventions.md): the upstream receives a request
	// re-serialised from the proxy's own strict parse of exactly the tools/call
	// params members {name, arguments, _meta, inputResponses, requestState};
	// any other member (including `task`) is rejected with -32602 before the
	// Interceptor runs. Never the client's bytes, so what the Interceptor saw
	// is what ran. The gateway never follows upstream redirects: a 3xx is an
	// error from Forward.
	// Error semantics (gap-006): an error wrapping ErrNotSent means the
	// request provably never left the gateway; the host releases the
	// reservation. Every other error, ctx.Err() after the write included,
	// means the upstream may have run: the host settles the estimate, records
	// outcome "error" with result.error "upstream may have run: <err>", and
	// does not return a result.
	Forward func(ctx context.Context) (json.RawMessage, error)
}

// Interceptor is the proxy's single hook. The proxy calls Intercept once per
// tools/call, concurrently across calls, and sends the returned result to the
// client verbatim. Error mapping (owned by the proxy):
//   - *CallError wrapping ErrDenied, ErrBudgetExceeded, ErrApprovalDenied or
//     ErrApprovalTimeout: a CallToolResult with isError=true, one text content
//     item holding CallError.Error(), and _meta.agentgw = GatewayMeta.
//   - context.Canceled / DeadlineExceeded: the request is dropped (client went away).
//   - *CallError wrapping ErrLedgerUnavailable or ErrNotRecorded, and
//     anything else: JSON-RPC error -32603 with the error text
//     (CallError.Error(), so the text names what happened upstream).
//
// Ledger rules every host (proxy pipeline, sdk-api, demo) follows: check
// Ledger.Err() before Reserve and before Forward and refuse with
// ErrLedgerUnavailable when it is non-nil; when Append fails after Forward,
// withhold the upstream result and return ErrNotRecorded (the side effect
// happened; the agent must not retry blindly). Before pricing, validate
// Args and InputResponses with the proxy's exported params validator (JCS
// canonicalisable, no colliding keys; contracts/conventions.md forwarding rule)
// and refuse with an error wrapping ErrDenied(RuleEvaluationError) if that
// fails, so every forwarded call can be recorded and priced on the key the
// upstream will read. Run Remaining -> Grants -> Decide -> Reserve inside
// one Budget.Exclusive call; on require_approval return from it before
// Approver.Request/Wait and run the post-approval Reserve inside a second
// Exclusive call. Never hold Exclusive across Wait or Forward. A per-scope
// or per-instance lock does not close the budget_remaining_below race
// (limits match by glob; hosts rebuild pipelines on policy change).
//
// A pass-through Interceptor is `return call.Forward(ctx)`.
//
// Interceptors that compose the other interfaces here (the pipeline) are
// library values, not process singletons: the Principal (AgentID, Owner,
// RunID) and every dependency are injected at construction, nothing is read
// from flags, env or package globals, construction does no I/O, and many
// independent instances may live in one process (a host building one
// isolated pipeline per visitor session, each with its own Decider, Ledger
// and Approver). Only SessionID comes from the Call.
type Interceptor interface {
	Intercept(ctx context.Context, call *Call) (json.RawMessage, error)
}

// Pricer estimates the cost of a call before it is made.
type Pricer interface {
	// Estimate returns the price-table estimate in the gateway currency.
	// Unpriced tools return zero, not an error. Errors: malformed args JSON,
	// or an arg_field value that is present but unpriceable (see the
	// config.schema.json prices description for the exact parsing rule);
	// the host denies such a call with RuleEvaluationError, reason
	// "unpriceable argument <field>: <why>". Never negative. Safe for
	// concurrent use.
	Estimate(ctx context.Context, server, tool string, args json.RawMessage) (Money, error)
}

// Decider evaluates policy. Deny is an outcome, never an error.
type Decider interface {
	// Decide is deterministic in its input: same DecisionInput, same
	// DecisionOutput. Errors are returned for inputs the engine cannot
	// evaluate (unknown version, malformed args) and for evaluation errors
	// reported by the engine (e.g. raw Cedar reading a context attribute
	// without a `has` guard); never for a plain deny. Callers fail closed: the
	// pipeline treats a Decide error as deny with rule_id RuleEvaluationError,
	// reason "policy evaluation failed: <err>", wrapped in a *CallError with
	// ErrDenied, and records the ledger entry like any other deny. Precedence
	// and the grant short-circuit are fixed by contracts/policy-yaml.md. Safe
	// for concurrent use.
	Decide(ctx context.Context, in DecisionInput) (DecisionOutput, error)
}

// BudgetScope keys a reservation. Limits match on AgentID and "<Server>.<Tool>";
// WindowPerRun counts by RunID.
type BudgetScope struct {
	AgentID string
	RunID   string
	Server  string
	Tool    string
}

// Budget is the atomic spend counter (docs/adr/0003). Lifecycle per call:
// Reserve, then exactly one of Settle or Release. Unsettled reservations count
// against every window until released. All methods are safe for concurrent use.
type Budget interface {
	// Reserve checks every limit that matches scope, in every window, against
	// settled spend plus open reservations, then records a reservation of
	// amount, all in one transaction. On overflow it returns a *CallError
	// wrapping ErrBudgetExceeded with Window set to the first window (order:
	// per_run, daily, monthly) that would overflow and nothing is recorded.
	// A zero amount still creates a reservation (so Settle can raise it).
	Reserve(ctx context.Context, scope BudgetScope, amount Money) (reservationID string, err error)
	// Settle replaces the reserved estimate with actual, even when actual is
	// larger than the estimate or than the remaining limit; the overshoot is
	// caught by the next Reserve. Unknown or already-closed id is an error.
	Settle(ctx context.Context, reservationID string, actual Money) error
	// Release drops the reservation as if it never happened. Unknown or
	// already-closed id is an error.
	Release(ctx context.Context, reservationID string) error
	// Remaining returns limit minus (settled + reserved) per window for the
	// tightest matching limit in each window, clamped at zero. Windows with
	// no matching limit are absent. Feeds DecisionContext.BudgetRemaining.
	Remaining(ctx context.Context, scope BudgetScope) (map[Window]Money, error)
	// Exclusive runs fn while holding this Budget's single store-wide lock
	// (gap-006b). Limits match by glob, so calls with different scopes share
	// limits; the only key that serialises every Remaining -> Decide ->
	// Reserve sequence against the same counters is the Budget itself, and
	// owning the lock here means every pipeline instance sharing a Budget
	// shares it without the host having to remember. Blocks until the lock is
	// free or ctx is done (then returns ctx.Err() without running fn);
	// otherwise returns fn's error. Not reentrant: fn must not call Exclusive,
	// Reserve, Settle, Release or Remaining on another goroutine and wait for
	// it. Single-process by design (docs/adr/0003).
	Exclusive(ctx context.Context, fn func() error) error
}

// Ledger is the append-only signed record (docs/adr/0004). Append is
// serialised internally; callers may use it concurrently.
type Ledger interface {
	// Append takes an Entry whose Action.Args and Result.Content hold the raw
	// payloads (Content exactly as Forward returned it) and whose ID, Ts (if
	// zero), PrevHash, ArgsHash, ResultHash, Signer and Sig are empty. It
	// strips the protocol envelope from Content (docs/adr/0008), hashes, then
	// replaces Args and Content with redacted copies, writes the JCS line with fsync, and returns. On
	// error nothing was written and e is unspecified. Result.Error is
	// redacted with the pattern rules (not the field rules) like any string
	// value; the fixed refusal texts contain only rule ids, window names and
	// sentinel text, so they are unchanged unless an operator pattern matches
	// a rule id. Record is never skipped by callers: every call id that is
	// forwarded yields exactly one entry, except a call whose Append fails
	// transiently after Forward, which the client is told about via
	// ErrNotRecorded.
	Append(ctx context.Context, e *Entry) error
	// Err reports the ledger's sticky failure: non-nil once a write failed in
	// a way the implementation could not roll back (the file may end in a
	// partial line), nil while healthy. It never clears; recovery is a restart
	// (Open re-reads and truncates to the last complete line). Cheap and safe
	// for concurrent use. Callers check it before any side effect (Reserve,
	// Forward) and refuse with ErrLedgerUnavailable. The implementation
	// writes one stderr line when it enters this state; that line is the
	// operator signal, since the refusals themselves cannot be recorded.
	Err() error
	// Checkpoint appends a checkpoint over every entry since the previous
	// checkpoint and returns it. With no new entries it returns (nil, nil).
	// Implementations also call this themselves every
	// LedgerConfig.CheckpointEvery entries.
	Checkpoint(ctx context.Context) (*Checkpoint, error)
	// Verify re-reads the ledger file from the start with the ledger's own
	// public key and reports the first failure. A non-nil error means the
	// file could not be read at all, not that it failed verification.
	Verify(ctx context.Context) (*VerifyReport, error)
	// Redact returns a copy of raw with the ledger's redaction rules applied.
	// Used by callers that show arguments to humans (approvals). Fails closed:
	// input that cannot be fully parsed (invalid JSON, nesting beyond the
	// implementation's depth limit) returns the JSON string "[REDACTED]"
	// (Redacted as a JSON string literal), never the raw bytes.
	Redact(raw json.RawMessage) json.RawMessage
}

// ApprovalRequest is what a human sees when asked to approve a call.
type ApprovalRequest struct {
	CallID        string
	Principal     Principal
	Server        string
	Tool          string
	ArgsHash      string          // hex SHA-256 of JCS(raw args); the decision is bound to it
	Args          json.RawMessage // redacted copy, display only
	EstimatedCost Money
	RuleID        string
	Spec          ApprovalSpec
}

// PendingApproval is an undecided request, as listed by the CLI.
type PendingApproval struct {
	ID        string
	Request   ApprovalRequest
	CreatedAt time.Time
	ExpiresAt time.Time // CreatedAt + Spec.TimeoutSeconds
}

// Approver holds calls for humans. Lifecycle: Request, then Wait; approvers
// resolve through the surface (CLI functions in internal/approval, Slack later).
type Approver interface {
	// Request persists a pending approval and returns its id. It does not block.
	Request(ctx context.Context, req ApprovalRequest) (approvalID string, err error)
	// Wait blocks until the approval is decided or times out. It calls
	// progress at least every 10 seconds while waiting. Returns:
	//   - approved: the decision, nil error
	//   - denied: the decision AND a *CallError wrapping ErrApprovalDenied
	//   - timeout: nil, *CallError wrapping ErrApprovalTimeout
	//   - ctx done: nil, ctx.Err()
	// A decision whose call id or args hash differs from the request is
	// rejected by the surface and never surfaces here.
	Wait(ctx context.Context, approvalID string, progress func(msg string)) (*ApprovalDecision, error)
	// Grants returns the grants active for p at the time of the call: scope
	// run grants with p.RunID, scope agent grants with p.AgentID, Until in the
	// future. Never nil on success.
	Grants(ctx context.Context, p Principal) ([]Grant, error)
}
