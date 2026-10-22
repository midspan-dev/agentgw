package contracts

import (
	"encoding/json"
	"time"
)

// Principal identifies who is calling. See contracts/schemas/common.schema.json.
type Principal struct {
	AgentID   string `json:"agent_id"`
	Owner     string `json:"owner"`
	RunID     string `json:"run_id"`
	SessionID string `json:"session_id"`
}

// Outcome is a policy decision.
type Outcome string

const (
	OutcomeAllow           Outcome = "allow"
	OutcomeDeny            Outcome = "deny"
	OutcomeRequireApproval Outcome = "require_approval"
)

// Reserved rule ids used when no authored rule produced the outcome.
const (
	RuleDefaultDeny     = "default-deny"
	RuleUnknownAgent    = "unknown-agent"
	RuleEvaluationError = "evaluation-error" // Decide returned an error; the pipeline denied
)

// GrantScope says how long a grant lives.
type GrantScope string

const (
	GrantScopeRun   GrantScope = "run"   // dies with the run it was issued in
	GrantScopeAgent GrantScope = "agent" // every run of the agent until Until
)

// Grant is a standing approval. A call matches a grant when AgentID equals the
// principal's, Server and Tool equal the action's exactly, Until is after
// context time, and (for scope run) RunID equals the principal's.
type Grant struct {
	ID         string     `json:"id"`
	ApprovalID string     `json:"approval_id"`
	Scope      GrantScope `json:"scope"`
	AgentID    string     `json:"agent_id"`
	RunID      string     `json:"run_id"` // empty when Scope is GrantScopeAgent
	Server     string     `json:"server"`
	Tool       string     `json:"tool"`
	Until      time.Time  `json:"until"`
}

// Action is the tool call under decision.
type Action struct {
	Server string          `json:"server"`
	Tool   string          `json:"tool"`
	Args   json.RawMessage `json:"args"` // raw MCP arguments object; {} when absent
}

// DecisionContext is everything else a rule may look at.
type DecisionContext struct {
	Time            time.Time        `json:"time"`
	EstimatedCost   Money            `json:"estimated_cost"`
	BudgetRemaining map[Window]Money `json:"budget_remaining"` // windows with no limit are absent
	Grants          []Grant          `json:"grants"`           // never nil when marshalled
}

// DecisionInput mirrors contracts/schemas/decision-input.schema.json.
//
// Context is built by the gateway, never accepted from a caller: Time from
// the gateway clock, EstimatedCost from the Pricer, BudgetRemaining from
// Budget.Remaining, Grants from Approver.Grants. Principal.AgentID and Owner
// come from gateway config. An HTTP surface (/v1/decide) takes only Action,
// Principal.RunID and Principal.SessionID from the request body and ignores
// the rest; otherwise a caller could forge grants or remaining budget.
type DecisionInput struct {
	Version   string          `json:"version"`
	Principal Principal       `json:"principal"`
	Action    Action          `json:"action"`
	Context   DecisionContext `json:"context"`
}

// ApprovalSpec says how to obtain approval for a require_approval outcome.
type ApprovalSpec struct {
	Approvers      []string `json:"approvers"` // empty means any approver
	TimeoutSeconds int      `json:"timeout_seconds"`
}

// DecisionOutput mirrors contracts/schemas/decision-output.schema.json.
// Approval is non-nil exactly when Outcome is OutcomeRequireApproval.
type DecisionOutput struct {
	Version       string        `json:"version"`
	Outcome       Outcome       `json:"outcome"`
	RuleID        string        `json:"rule_id"`
	PolicyVersion string        `json:"policy_version"` // hex SHA-256 of the compiled Cedar
	Reason        string        `json:"reason"`
	GrantID       string        `json:"grant_id"` // set when a grant turned require_approval into allow
	Approval      *ApprovalSpec `json:"approval"`
}
