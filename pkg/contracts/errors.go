package contracts

import "errors"

// Sentinel errors. Implementations return them wrapped in a *CallError so the
// proxy can build the _meta.agentgw payload; callers test with errors.Is.
var (
	ErrDenied          = errors.New("agentgw: denied by policy")
	ErrBudgetExceeded  = errors.New("agentgw: budget exceeded")
	ErrApprovalTimeout = errors.New("agentgw: approval timed out")
	ErrApprovalDenied  = errors.New("agentgw: approval denied")

	// Infrastructure refusals (gap-005). Both are JSON-RPC -32603 at the
	// proxy, not tool errors: the agent cannot self-correct them.
	// ErrLedgerUnavailable: Ledger.Err() was non-nil, nothing was forwarded,
	// nothing could be recorded.
	ErrLedgerUnavailable = errors.New("agentgw: ledger unavailable, call not forwarded")
	// ErrNotRecorded: the upstream call completed but Append failed; the
	// result is withheld. The text says so to stop blind retries.
	ErrNotRecorded = errors.New("agentgw: upstream call completed but could not be recorded")

	// ErrNotSent is wrapped by Call.Forward only when the proxy is certain the
	// request never left the gateway (ctx done before the write began, or a
	// dial/TLS failure). Any other Forward error means the upstream may have
	// run, and the pipeline settles the estimate (gap-006).
	ErrNotSent = errors.New("agentgw: request not sent upstream")
)

// CallError carries a sentinel plus the facts the client is told. Fields a
// producer does not know are left empty; the pipeline fills CallID.
//
// Reason formats are fixed so Error() is deterministic and goldens can
// compare it (docs/adr/0008):
//   - ErrDenied: DecisionOutput.Reason verbatim ("denied by rule <id>" etc.,
//     see contracts/policy-yaml.md section 2)
//   - ErrBudgetExceeded: "<window> budget exceeded", e.g. "per_run budget exceeded"
//   - ErrApprovalDenied: the approver's reason text, possibly ""
//   - ErrApprovalTimeout: ""
//
// Error() is "<sentinel text>" when Reason is empty, else
// "<sentinel text>: <reason>"; it is the ledger's result.error for refusals.
type CallError struct {
	Err    error // one of the sentinels above
	CallID string
	RuleID string // policy rule, when the sentinel is ErrDenied or an approval error
	Reason string // human-readable, safe to show the agent
	Window Window // the overflowing window, when Err is ErrBudgetExceeded
}

func (e *CallError) Error() string {
	if e.Reason == "" {
		return e.Err.Error()
	}
	return e.Err.Error() + ": " + e.Reason
}

func (e *CallError) Unwrap() error { return e.Err }

// Outcome maps the sentinel to the ledger outcome. Unknown errors are EntryError.
func (e *CallError) Outcome() EntryOutcome {
	switch {
	case errors.Is(e.Err, ErrDenied):
		return EntryDenied
	case errors.Is(e.Err, ErrBudgetExceeded):
		return EntryBudgetExceeded
	case errors.Is(e.Err, ErrApprovalDenied):
		return EntryApprovalDenied
	case errors.Is(e.Err, ErrApprovalTimeout):
		return EntryApprovalTimeout
	}
	return EntryError
}

// GatewayMeta is the structured payload the proxy puts at
// CallToolResult._meta.agentgw when a call is refused. See contracts/cost-meta.md.
type GatewayMeta struct {
	Outcome EntryOutcome `json:"outcome"`
	Reason  string       `json:"reason"`
	RuleID  string       `json:"rule_id"`
	CallID  string       `json:"call_id"`
}
