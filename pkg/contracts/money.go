package contracts

// Money is an amount in integer micro-units (1/1,000,000 of the currency unit).
// 5000 USD micros is $0.005. Never a float; see docs/adr/0007.
type Money struct {
	Micros   int64  `json:"micros" yaml:"micros"`
	Currency string `json:"currency" yaml:"currency"`
}

// MicrosPerUnit converts between major currency units and Micros.
const MicrosPerUnit = 1_000_000

// Window is a budget window.
type Window string

const (
	WindowPerRun  Window = "per_run" // keyed by Principal.RunID
	WindowDaily   Window = "daily"   // rolls over at 00:00 UTC
	WindowMonthly Window = "monthly" // rolls over on the 1st, 00:00 UTC
)

// BudgetLimit is one compiled limit from the policy file's budgets section:
// calls whose agent id and "<server>.<tool>" match both globs may not push
// spend in Window past Limit. The policy node produces these; the budgets node
// enforces them.
type BudgetLimit struct {
	Agent  string // glob over Principal.AgentID
	Tool   string // glob over "<server>.<tool>"
	Window Window
	Limit  Money
}
