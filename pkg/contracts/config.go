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

// ApprovalsConfig lists approval surfaces. CLI is required; GitHub is optional
// (rev 9, docs/adr/0011): when present, `agentgw run` and `agentgw serve`
// start the comment poller. Configs without it are unchanged.
type ApprovalsConfig struct {
	CLI    CLIApprovals     `json:"cli" yaml:"cli"`
	GitHub *GitHubApprovals `json:"github,omitempty" yaml:"github,omitempty"`
}

// CLIApprovals configures the local approver token.
type CLIApprovals struct {
	TokenPath string `json:"token_path" yaml:"token_path"`
}

// GitHubApprovals configures approvals by GitHub issue or pull-request comment
// (docs/adr/0011). The token is read from the environment variable named by
// TokenEnv, never from this file. Decisions are signed with the CLI approver
// token (CLIApprovals.TokenPath), which the gateway holds; the commenter's
// login is recorded in ApprovalDecision.Via.
type GitHubApprovals struct {
	// Repo is "owner/name".
	Repo string `json:"repo" yaml:"repo"`
	// Issue is the issue or pull-request number the gateway comments on and
	// polls. 0 means take it from the GitHub Actions event file named by
	// $GITHUB_EVENT_PATH (.issue.number, else .pull_request.number); if
	// neither is present the gateway refuses to start.
	Issue int `json:"issue" yaml:"issue"`
	// MinPermission is the least repository role a commenter needs for a
	// reply to count: one of "triage", "write", "maintain", "admin" (GitHub
	// role_name order). Empty means "write".
	MinPermission string `json:"min_permission,omitempty" yaml:"min_permission,omitempty"`
	// PollInterval is a Go duration string (e.g. "15s"), the pause between
	// comment polls while at least one approval is pending; the gateway does
	// not poll while nothing is pending. Empty means "15s"; the minimum is "5s".
	PollInterval string `json:"poll_interval,omitempty" yaml:"poll_interval,omitempty"`
	// TokenEnv names the environment variable holding the GitHub token.
	// Empty means "GITHUB_TOKEN".
	TokenEnv string `json:"token_env,omitempty" yaml:"token_env,omitempty"`
}

// LedgerConfig locates the ledger and sets checkpoint cadence.
type LedgerConfig struct {
	Path            string `json:"path" yaml:"path"`
	CheckpointEvery int    `json:"checkpoint_every" yaml:"checkpoint_every"`
}

// Redacted is the replacement string for redacted values.
const Redacted = "[REDACTED]"
