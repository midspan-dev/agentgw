package contracts

// Config mirrors contracts/schemas/config.schema.json. YAML and JSON tags are
// identical so the file may be written in either.
type Config struct {
	Version    string          `json:"version" yaml:"version"`
	Agent      AgentIdentity   `json:"agent" yaml:"agent"`
	Currency   string          `json:"currency" yaml:"currency"`
	Listen     string          `json:"listen" yaml:"listen"`
	Upstreams  []Upstream      `json:"upstreams" yaml:"upstreams"`
	PolicyPath string          `json:"policy_path" yaml:"policy_path"`
	Prices     []Price         `json:"prices" yaml:"prices"`
	Redaction  RedactionConfig `json:"redaction" yaml:"redaction"`
	Approvals  ApprovalsConfig `json:"approvals" yaml:"approvals"`
	Ledger     LedgerConfig    `json:"ledger" yaml:"ledger"`
	KeyPath    string          `json:"key_path" yaml:"key_path"`
	StatePath  string          `json:"state_path" yaml:"state_path"`
}

// AgentIdentity is the agent this gateway fronts.
type AgentIdentity struct {
	ID    string `json:"id" yaml:"id"`
	Owner string `json:"owner" yaml:"owner"`
}

// Upstream is one MCP server behind the gateway. Exactly one of Command or
// URL is set; Path accompanies URL.
type Upstream struct {
	Name    string   `json:"name" yaml:"name"`
	Command []string `json:"command,omitempty" yaml:"command,omitempty"`
	URL     string   `json:"url,omitempty" yaml:"url,omitempty"`
	Path    string   `json:"path,omitempty" yaml:"path,omitempty"`
}

// Price is one price-table row. Estimate = PerCall + args[ArgField]*ArgMultiplier
// in Config.Currency units; the budgets node converts to Money with
// round-half-away-from-zero.
type Price struct {
	Server        string  `json:"server" yaml:"server"` // glob
	Tool          string  `json:"tool" yaml:"tool"`     // glob
	PerCall       float64 `json:"per_call" yaml:"per_call"`
	ArgField      string  `json:"arg_field" yaml:"arg_field"` // "" disables the multiplier
	ArgMultiplier float64 `json:"arg_multiplier" yaml:"arg_multiplier"`
}

// RedactionConfig adds to the ledger's built-in redaction rules.
type RedactionConfig struct {
	Fields   []string `json:"fields" yaml:"fields"`     // case-insensitive key names, any depth
	Patterns []string `json:"patterns" yaml:"patterns"` // RE2 regexps applied to string values
}

// ApprovalsConfig lists approval surfaces. Phase 1: CLI only.
type ApprovalsConfig struct {
	CLI CLIApprovals `json:"cli" yaml:"cli"`
}

// CLIApprovals configures the local approver token.
type CLIApprovals struct {
	TokenPath string `json:"token_path" yaml:"token_path"`
}

// LedgerConfig locates the ledger and sets checkpoint cadence.
type LedgerConfig struct {
	Path            string `json:"path" yaml:"path"`
	CheckpointEvery int    `json:"checkpoint_every" yaml:"checkpoint_every"`
}

// Redacted is the replacement string for redacted values.
const Redacted = "[REDACTED]"
