package contracts

// PolicyFile mirrors contracts/schemas/policy.schema.json: the YAML grammar
// documented in contracts/policy-yaml.md. Currency defaults to "USD".
type PolicyFile struct {
	Version  string         `json:"version" yaml:"version"`
	Currency string         `json:"currency,omitempty" yaml:"currency,omitempty"`
	Agents   []PolicyAgent  `json:"agents,omitempty" yaml:"agents,omitempty"`
	Budgets  []PolicyBudget `json:"budgets,omitempty" yaml:"budgets,omitempty"`
	Rules    []PolicyRule   `json:"rules" yaml:"rules"`
}

// PolicyAgent declares a known agent. A non-empty Agents list denies unknown
// agent ids with RuleUnknownAgent.
type PolicyAgent struct {
	ID    string `json:"id" yaml:"id"`
	Owner string `json:"owner" yaml:"owner"`
}

// PolicyBudget caps spend for calls matching both globs. Amounts are decimal
// numbers in PolicyFile.Currency units; an absent window is unlimited.
type PolicyBudget struct {
	Agent  string             `json:"agent" yaml:"agent"` // glob
	Tool   string             `json:"tool" yaml:"tool"`   // "<server>.<tool>" glob
	Limits map[Window]float64 `json:"limits" yaml:"limits"`
}

// PolicyRule is one rule. Agents nil means every agent; an empty Agents list
// is a compile error (schema minItems 1), never "no agent" and never "every
// agent". Approvers and Timeout
// are only meaningful with OutcomeRequireApproval; Timeout defaults to "10m".
type PolicyRule struct {
	ID        string    `json:"id" yaml:"id"`
	Effect    Outcome   `json:"effect" yaml:"effect"`
	Agents    []string  `json:"agents,omitempty" yaml:"agents,omitempty"`
	Tools     []string  `json:"tools" yaml:"tools"`
	When      *RuleWhen `json:"when,omitempty" yaml:"when,omitempty"`
	Approvers []string  `json:"approvers,omitempty" yaml:"approvers,omitempty"`
	Timeout   string    `json:"timeout,omitempty" yaml:"timeout,omitempty"`
}

// RuleWhen holds conditions that must all hold. EstimatedCostAbove is a pointer so
// "estimated_cost_above: 0" (any non-zero cost) is distinguishable from absent.
type RuleWhen struct {
	EstimatedCostAbove   *float64           `json:"estimated_cost_above,omitempty" yaml:"estimated_cost_above,omitempty"`
	BudgetRemainingBelow map[Window]float64 `json:"budget_remaining_below,omitempty" yaml:"budget_remaining_below,omitempty"`
}

// DefaultApprovalTimeout is PolicyRule.Timeout when omitted.
const DefaultApprovalTimeout = "10m"
