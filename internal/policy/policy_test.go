package policy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/midspan-dev/agentgw/internal/harness"
	"github.com/midspan-dev/agentgw/pkg/contracts"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func collapse(s string) string { return strings.Join(strings.Fields(s), " ") }

var now = time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

type call struct {
	agent, tool string // tool is "<server>.<tool>"
	cost        float64
	remaining   map[contracts.Window]float64
	grants      []contracts.Grant
	args        string
}

func (c call) input() contracts.DecisionInput {
	if c.agent == "" {
		c.agent = "billing-bot"
	}
	server, tool, _ := strings.Cut(c.tool, ".")
	rem := map[contracts.Window]contracts.Money{}
	for w, v := range c.remaining {
		rem[w] = contracts.Money{Micros: micros(v), Currency: "USD"}
	}
	args := json.RawMessage(c.args)
	if c.args == "" {
		args = json.RawMessage(`{}`)
	}
	return contracts.DecisionInput{
		Version:   contracts.SchemaVersion,
		Principal: contracts.Principal{AgentID: c.agent, Owner: "alice@example.com", RunID: "r1"},
		Action:    contracts.Action{Server: server, Tool: tool, Args: args},
		Context: contracts.DecisionContext{Time: now, EstimatedCost: contracts.Money{Micros: micros(c.cost), Currency: "USD"},
			BudgetRemaining: rem, Grants: c.grants},
	}
}

type want struct {
	outcome contracts.Outcome
	rule    string
	grant   string
}

func grant(id string, scope contracts.GrantScope, run, tool string, until time.Time) contracts.Grant {
	return contracts.Grant{ID: id, ApprovalID: "ap", Scope: scope, AgentID: "billing-bot", RunID: run, Server: "stripe", Tool: tool, Until: until}
}

const (
	yaml51 = `
version: "1"
rules:
  - id: no-destructive
    effect: deny
    tools: ["*.delete_*"]
  - id: allow-all
    effect: allow
    tools: ["*"]
`
	cedar51 = `@id("no-destructive") @effect("deny") forbid ( principal, action == Action::"call", resource ) when { resource.full_name like "*.delete_*" };
@id("allow-all") @effect("allow") permit ( principal, action == Action::"call", resource ) when { resource.full_name like "*" };`

	yaml52 = `
version: "1"
rules:
  - id: refunds-need-approval
    effect: require_approval
    tools: ["stripe.refund"]
    when: { estimated_cost_above: 100 }
    approvers: ["alice@example.com"]
    timeout: 10m
  - id: allow-stripe
    effect: allow
    agents: ["billing-*"]
    tools: ["stripe.*"]
`
	cedar52 = `@id("refunds-need-approval") @effect("require_approval") permit ( principal, action == Action::"call", resource )
when { resource.full_name like "stripe.refund" }
when { context.estimated_cost_micros > 100000000 };
@id("allow-stripe") @effect("allow") permit ( principal, action == Action::"call", resource )
when { principal.agent_id like "billing-*" }
when { resource.full_name like "stripe.*" };`

	yaml53 = `
version: "1"
rules:
  - id: low-budget-approval
    effect: require_approval
    tools: ["*"]
    when:
      budget_remaining_below: { daily: 10 }
  - id: allow-all
    effect: allow
    tools: ["*"]
`
	cedar53 = `@id("low-budget-approval") @effect("require_approval") permit ( principal, action == Action::"call", resource )
when { resource.full_name like "*" }
when { context has remaining_daily_micros && context.remaining_daily_micros < 10000000 };
@id("allow-all") @effect("allow") permit ( principal, action == Action::"call", resource ) when { resource.full_name like "*" };`

	yaml54 = `
version: "1"
currency: USD
agents:
  - { id: billing-bot, owner: alice@example.com }
budgets:
  - { agent: "*", tool: "*", limits: { per_run: 5, daily: 50 } }
  - { agent: billing-bot, tool: "stripe.*", limits: { monthly: 500 } }
rules:
  - id: allow-all
    effect: allow
    tools: ["*"]
`
	cedar54 = `@id("unknown-agent") @effect("deny") forbid ( principal, action == Action::"call", resource )
unless { principal == Agent::"billing-bot" };
@id("allow-all") @effect("allow") permit ( principal, action == Action::"call", resource ) when { resource.full_name like "*" };`
)

func mustCompile(t *testing.T, y string) *Policy {
	t.Helper()
	p, err := Compile([]byte(y))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func check(t *testing.T, p *Policy, name string, c call, w want) contracts.DecisionOutput {
	t.Helper()
	got, err := p.Decide(context.Background(), c.input())
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	if got.Outcome != w.outcome || got.RuleID != w.rule || got.GrantID != w.grant {
		t.Errorf("%s: got %s/%s/%q, want %s/%s/%q", name, got.Outcome, got.RuleID, got.GrantID, w.outcome, w.rule, w.grant)
	}
	if (got.Approval != nil) != (got.Outcome == contracts.OutcomeRequireApproval) {
		t.Errorf("%s: approval %v for outcome %s", name, got.Approval, got.Outcome)
	}
	if got.PolicyVersion != p.Version() || got.Version != contracts.SchemaVersion {
		t.Errorf("%s: bad versions %+v", name, got)
	}
	return got
}

func TestSection5Examples(t *testing.T) {
	later := now.Add(time.Hour)
	d, a, ap, df := contracts.OutcomeDeny, contracts.OutcomeAllow, contracts.OutcomeRequireApproval, contracts.RuleDefaultDeny
	rem := func(v float64) map[contracts.Window]float64 {
		return map[contracts.Window]float64{contracts.WindowDaily: v}
	}
	p := mustCompile(t, yaml51)
	if collapse(p.Cedar()) != collapse(cedar51) {
		t.Errorf("5.1 cedar:\n%s", p.Cedar())
	}
	check(t, p, "5.1 delete", call{tool: "fs.delete_everything"}, want{d, "no-destructive", ""})
	check(t, p, "5.1 echo", call{tool: "fs.echo"}, want{a, "allow-all", ""})

	p = mustCompile(t, yaml52)
	if collapse(p.Cedar()) != collapse(cedar52) {
		t.Errorf("5.2 cedar:\n%s", p.Cedar())
	}
	got := check(t, p, "5.2 row1", call{tool: "stripe.refund", cost: 120.5}, want{ap, "refunds-need-approval", ""})
	if got.Approval.TimeoutSeconds != 600 || len(got.Approval.Approvers) != 1 || got.Approval.Approvers[0] != "alice@example.com" {
		t.Errorf("5.2 approval %+v", got.Approval)
	}
	if got.Reason != "rule refunds-need-approval requires approval" {
		t.Errorf("reason %q", got.Reason)
	}
	check(t, p, "5.2 row2", call{tool: "stripe.refund", cost: 100}, want{a, "allow-stripe", ""})
	check(t, p, "5.2 row3", call{tool: "stripe.refund", cost: 120.5, grants: []contracts.Grant{grant("g1", contracts.GrantScopeRun, "r1", "refund", later)}},
		want{a, "refunds-need-approval", "g1"})
	check(t, p, "5.2 row4", call{agent: "ops-bot", tool: "stripe.refund", cost: 120.5}, want{ap, "refunds-need-approval", ""})
	got = check(t, p, "5.2 row5", call{tool: "search.search", cost: 0.005}, want{d, df, ""})
	if got.Reason != "no rule allows search.search for billing-bot" {
		t.Errorf("reason %q", got.Reason)
	}

	p = mustCompile(t, yaml53)
	if collapse(p.Cedar()) != collapse(cedar53) {
		t.Errorf("5.3 cedar:\n%s", p.Cedar())
	}
	check(t, p, "5.3 4.00", call{tool: "x.y", remaining: rem(4)}, want{ap, "low-budget-approval", ""})
	check(t, p, "5.3 10.00", call{tool: "x.y", remaining: rem(10)}, want{a, "allow-all", ""})
	check(t, p, "5.3 none", call{tool: "x.y"}, want{a, "allow-all", ""})

	p = mustCompile(t, yaml54)
	if collapse(p.Cedar()) != collapse(cedar54) {
		t.Errorf("5.4 cedar:\n%s", p.Cedar())
	}
	check(t, p, "5.4 known", call{tool: "x.y"}, want{a, "allow-all", ""})
	got = check(t, p, "5.4 unknown", call{agent: "ops-bot", tool: "x.y"}, want{d, "unknown-agent", ""})
	if got.Reason != "agent ops-bot is not in the policy's agents list" {
		t.Errorf("reason %q", got.Reason)
	}
	usd := func(m int64) contracts.Money { return contracts.Money{Micros: m, Currency: "USD"} }
	wantLimits := []contracts.BudgetLimit{
		{Agent: "*", Tool: "*", Window: contracts.WindowPerRun, Limit: usd(5_000_000)},
		{Agent: "*", Tool: "*", Window: contracts.WindowDaily, Limit: usd(50_000_000)},
		{Agent: "billing-bot", Tool: "stripe.*", Window: contracts.WindowMonthly, Limit: usd(500_000_000)},
	}
	if l := p.Limits(); len(l) != 3 || l[0] != wantLimits[0] || l[1] != wantLimits[1] || l[2] != wantLimits[2] {
		t.Errorf("limits %+v", l)
	}

	p = mustCompile(t, "version: \"1\"\nrules: []\n")
	if p.Cedar() != "" {
		t.Errorf("5.5 cedar %q", p.Cedar())
	}
	check(t, p, "5.5", call{tool: "x.y"}, want{d, df, ""})
}

func TestDecideTable(t *testing.T) {
	d, a, ap, df := contracts.OutcomeDeny, contracts.OutcomeAllow, contracts.OutcomeRequireApproval, contracts.RuleDefaultDeny
	later, earlier := now.Add(time.Hour), now.Add(-time.Hour)
	p := mustCompile(t, `
version: "1"
agents:
  - { id: billing-bot, owner: a }
  - { id: ops-bot, owner: a }
rules:
  - id: deny-prod
    effect: deny
    agents: ["ops-*"]
    tools: ["prod.*"]
  - id: deny-delete
    effect: deny
    tools: ["*.delete_*", "*.drop"]
  - id: deny-delete-2
    effect: deny
    tools: ["*.delete_*"]
  - id: big-refund
    effect: require_approval
    tools: ["stripe.refund"]
    when: { estimated_cost_above: 0 }
    approvers: [a@b.c, d@e.f]
    timeout: 90s
  - id: low-budget
    effect: require_approval
    tools: ["*"]
    when: { budget_remaining_below: { per_run: 1, monthly: 100 } }
    timeout: 1h
  - id: allow-fs
    effect: allow
    tools: ["fs.*"]
  - id: allow-stripe
    effect: allow
    agents: ["billing-*"]
    tools: ["stripe.*"]
  - id: allow-quote
    effect: allow
    tools: ['q."uote\*']
  - id: allow-unicode
    effect: allow
    tools: ["u.café"]
`)
	rem := func(w contracts.Window, v float64) map[contracts.Window]float64 {
		return map[contracts.Window]float64{w: v}
	}
	both := func(pr, mo float64) map[contracts.Window]float64 {
		return map[contracts.Window]float64{contracts.WindowPerRun: pr, contracts.WindowMonthly: mo}
	}
	table := []struct {
		name string
		c    call
		w    want
	}{
		{"plain allow", call{tool: "fs.read"}, want{a, "allow-fs", ""}},
		{"glob empty run", call{tool: "fs."}, want{a, "allow-fs", ""}},
		{"glob case-sensitive", call{tool: "FS.read"}, want{d, df, ""}},
		{"glob star matches dot", call{tool: "fs.a.b"}, want{a, "allow-fs", ""}},
		{"deny leading star", call{tool: "fs.delete_all"}, want{d, "deny-delete", ""}},
		{"deny second pattern", call{tool: "fs.drop"}, want{d, "deny-delete", ""}},
		{"first deny in file order", call{tool: "x.delete_y"}, want{d, "deny-delete", ""}},
		{"deny beats approval and allow", call{tool: "stripe.delete_x", cost: 5}, want{d, "deny-delete", ""}},
		{"agent-scoped deny matches", call{agent: "ops-bot", tool: "prod.x"}, want{d, "deny-prod", ""}},
		{"agent-scoped deny skips others", call{tool: "prod.x"}, want{d, df, ""}},
		{"unknown agent beats allow", call{agent: "evil", tool: "fs.read"}, want{d, contracts.RuleUnknownAgent, ""}},
		{"unknown agent beats deny rule", call{agent: "evil", tool: "fs.delete_x"}, want{d, contracts.RuleUnknownAgent, ""}},
		{"agent glob not applied to allowlist", call{agent: "billing-*", tool: "fs.read"}, want{d, contracts.RuleUnknownAgent, ""}},
		{"approval over cost", call{tool: "stripe.refund", cost: 0.000001}, want{ap, "big-refund", ""}},
		{"cost equal to threshold falls through", call{tool: "stripe.refund", cost: 0}, want{a, "allow-stripe", ""}},
		{"approval beats allow", call{tool: "stripe.refund", cost: 1}, want{ap, "big-refund", ""}},
		{"budget below both", call{tool: "fs.read", remaining: both(0.5, 99.99)}, want{ap, "low-budget", ""}},
		{"budget below one of two (all must hold)", call{tool: "fs.read", remaining: both(0.5, 100)}, want{a, "allow-fs", ""}},
		{"budget below with other window absent", call{tool: "fs.read", remaining: rem(contracts.WindowPerRun, 0.5)}, want{a, "allow-fs", ""}},
		{"budget equal not below", call{tool: "fs.read", remaining: both(1, 0)}, want{a, "allow-fs", ""}},
		{"budget zero remaining", call{tool: "fs.read", remaining: both(0, 0)}, want{ap, "low-budget", ""}},
		{"budget absent windows", call{tool: "fs.read", remaining: rem(contracts.WindowDaily, 0)}, want{a, "allow-fs", ""}},
		{"budget no windows", call{tool: "fs.read"}, want{a, "allow-fs", ""}},
		{"first approval rule in file order", call{tool: "stripe.refund", cost: 1, remaining: both(0, 0)}, want{ap, "big-refund", ""}},
		{"run grant same run", call{tool: "stripe.refund", cost: 1, grants: []contracts.Grant{grant("g", contracts.GrantScopeRun, "r1", "refund", later)}}, want{a, "big-refund", "g"}},
		{"run grant other run", call{tool: "stripe.refund", cost: 1, grants: []contracts.Grant{grant("g", contracts.GrantScopeRun, "r2", "refund", later)}}, want{ap, "big-refund", ""}},
		{"agent grant any run", call{tool: "stripe.refund", cost: 1, grants: []contracts.Grant{grant("g", contracts.GrantScopeAgent, "", "refund", later)}}, want{a, "big-refund", "g"}},
		{"expired grant", call{tool: "stripe.refund", cost: 1, grants: []contracts.Grant{grant("g", contracts.GrantScopeAgent, "", "refund", earlier)}}, want{ap, "big-refund", ""}},
		{"grant until == now expired", call{tool: "stripe.refund", cost: 1, grants: []contracts.Grant{grant("g", contracts.GrantScopeAgent, "", "refund", now)}}, want{ap, "big-refund", ""}},
		{"grant wrong tool", call{tool: "stripe.refund", cost: 1, grants: []contracts.Grant{grant("g", contracts.GrantScopeAgent, "", "charge", later)}}, want{ap, "big-refund", ""}},
		{"second grant matches", call{tool: "stripe.refund", cost: 1, grants: []contracts.Grant{grant("g1", contracts.GrantScopeAgent, "", "charge", later), grant("g2", contracts.GrantScopeAgent, "", "refund", later)}}, want{a, "big-refund", "g2"}},
		{"grant cannot override deny", call{tool: "stripe.delete_x", cost: 1, grants: []contracts.Grant{grant("g", contracts.GrantScopeAgent, "", "delete_x", later)}}, want{d, "deny-delete", ""}},
		{"grant no effect without approval rule", call{tool: "fs.read", grants: []contracts.Grant{grant("g", contracts.GrantScopeAgent, "", "read", later)}}, want{a, "allow-fs", ""}},
		{"quote and backslash escaped (backslash literal, star wild)", call{tool: `q."uote\xyz`}, want{a, "allow-quote", ""}},
		{"backslash is required, not an escape for star", call{tool: `q."uote*`}, want{d, df, ""}},
		{"nfc: decomposed input matches composed pattern", call{tool: "u.café"}, want{a, "allow-unicode", ""}},
		{"no match default deny", call{tool: "nothing.here"}, want{d, df, ""}},
		{"empty args ok", call{tool: "fs.read", args: ""}, want{a, "allow-fs", ""}},
	}
	for _, tc := range table {
		got := check(t, p, tc.name, tc.c, tc.w)
		if tc.name == "approval over cost" && (got.Approval.TimeoutSeconds != 90 || len(got.Approval.Approvers) != 2) {
			t.Errorf("approval %+v", got.Approval)
		}
		if tc.name == "budget below both" && (got.Approval.TimeoutSeconds != 3600 || got.Approval.Approvers == nil || len(got.Approval.Approvers) != 0) {
			t.Errorf("approval %+v", got.Approval)
		}
	}
	if len(table) < 30 {
		t.Fatal("table too short")
	}

	// malformed args and wrong version are errors, not denies.
	in := call{tool: "fs.read", args: "{nope"}.input()
	if _, err := p.Decide(context.Background(), in); err == nil {
		t.Error("malformed args: want error")
	}
	in = call{tool: "fs.read"}.input()
	in.Version = "2"
	if _, err := p.Decide(context.Background(), in); err == nil {
		t.Error("bad version: want error")
	}
	// determinism
	a1, _ := p.Decide(context.Background(), call{tool: "stripe.refund", cost: 1}.input())
	a2, _ := p.Decide(context.Background(), call{tool: "stripe.refund", cost: 1}.input())
	if a1.RuleID != a2.RuleID || a1.PolicyVersion != a2.PolicyVersion {
		t.Error("not deterministic")
	}
}

func TestCompileErrors(t *testing.T) {
	cases := map[string]struct{ src, sub string }{
		"duplicate id":      {"version: \"1\"\nrules:\n  - {id: a, effect: allow, tools: [x]}\n  - {id: a, effect: deny, tools: [x]}\n", "line 4"},
		"reserved":          {"version: \"1\"\nrules:\n  - {id: default-deny, effect: allow, tools: [x]}\n", "reserved"},
		"reserved 2":        {"version: \"1\"\nrules:\n  - {id: unknown-agent, effect: allow, tools: [x]}\n", "reserved"},
		"approvers on deny": {"version: \"1\"\nrules:\n  - {id: a, effect: deny, tools: [x], approvers: [q]}\n", "require_approval"},
		"timeout on allow":  {"version: \"1\"\nrules:\n  - {id: a, effect: allow, tools: [x], timeout: 1m}\n", "require_approval"},
		"bad window":        {"version: \"1\"\nrules:\n  - id: a\n    effect: allow\n    tools: [x]\n    when: {budget_remaining_below: {weekly: 1}}\n", "weekly"},
		"bad budget window": {"version: \"1\"\nbudgets:\n  - {agent: '*', tool: '*', limits: {hourly: 1}}\nrules: []\n", "hourly"},
		"empty glob":        {"version: \"1\"\nrules:\n  - {id: a, effect: allow, tools: [\"\"]}\n", "bad glob"},
		"unknown field":     {"version: \"1\"\nrules:\n  - {id: a, effect: allow, tools: [x], bogus: 1}\n", "bogus"},
		"bad id":            {"version: \"1\"\nrules:\n  - {id: 'a b', effect: allow, tools: [x]}\n", "id must match"},
		"bad effect":        {"version: \"1\"\nrules:\n  - {id: a, effect: maybe, tools: [x]}\n", "effect"},
		"no rules key":      {"version: \"1\"\n", "rules"},
		"bad version":       {"version: \"2\"\nrules: []\n", "version"},
		"bad timeout":       {"version: \"1\"\nrules:\n  - {id: a, effect: require_approval, tools: [x], timeout: soon}\n", "timeout"},
		"inf":               {"version: \"1\"\nrules:\n  - {id: a, effect: deny, tools: [x], when: {budget_remaining_below: {daily: .inf}}}\n", "finite"},
		"nan":               {"version: \"1\"\nrules:\n  - {id: a, effect: deny, tools: [x], when: {estimated_cost_above: .nan}}\n", "finite"},
		"huge":              {"version: \"1\"\nrules:\n  - {id: a, effect: deny, tools: [x], when: {estimated_cost_above: 1e13}}\n", "line 3"},
		"neg":               {"version: \"1\"\nrules:\n  - {id: a, effect: deny, tools: [x], when: {estimated_cost_above: -1}}\n", "line 3"},
		"huge budget":       {"version: \"1\"\nbudgets:\n  - {agent: '*', tool: '*', limits: {daily: .nan, monthly: 1e13}}\nrules: []\n", "line 3"},
		"agents empty":      {"version: \"1\"\nrules:\n  - {id: a, effect: allow, agents: [], tools: ['*']}\n", "agents must be omitted or non-empty"},
		"agents null":       {"version: \"1\"\nrules:\n  - {id: a, effect: allow, agents: null, tools: ['*']}\n", "line 3"},
		"agents bare":       {"version: \"1\"\nrules:\n  - id: a\n    effect: allow\n    agents:\n    tools: ['*']\n", "line 3"},
		"reserved eval":     {"version: \"1\"\nrules:\n  - {id: evaluation-error, effect: allow, tools: [x]}\n", "reserved"},
		"two docs":          {"version: \"1\"\nrules: []\n---\nversion: \"1\"\nrules: []\n", "one YAML document"},
		"timeout 1h30m":     {"version: \"1\"\nrules:\n  - {id: a, effect: require_approval, tools: [x], timeout: 1h30m}\n", "timeout"},
		"timeout us":        {"version: \"1\"\nrules:\n  - {id: a, effect: require_approval, tools: [x], timeout: 5us}\n", "timeout"},
		"rules null":        {"version: \"1\"\nrules:\n", "rules"},
		"currency":          {"version: \"1\"\ncurrency: dollars\nrules: []\n", "currency"},
		"empty brb":         {"version: \"1\"\nrules:\n  - {id: a, effect: allow, tools: [x], when: {estimated_cost_above: 1, budget_remaining_below: {}}}\n", "budget_remaining_below"},
		"control char":      {"version: \"1\"\nrules:\n  - {id: a, effect: allow, tools: [\"a\\nb\"]}\n", "line 3"},
		"empty when":        {"version: \"1\"\nrules:\n  - {id: a, effect: allow, tools: [x], when: {}}\n", "when"},
	}
	for name, c := range cases {
		_, err := Compile([]byte(c.src))
		if err == nil || !strings.Contains(err.Error(), c.sub) {
			t.Errorf("%s: err %v, want substring %q", name, err, c.sub)
		}
	}
}

func TestMicrosRounding(t *testing.T) {
	if micros(100) != 100_000_000 || micros(0.005) != 5000 || micros(0.0000005) != 1 {
		t.Error("micros rounding")
	}
}

func TestLoadCedar(t *testing.T) {
	src := `@id("a") forbid (principal, action, resource) when { resource.full_name like "*.rm" };
@id("b") @effect("require_approval") permit (principal, action, resource);
permit (principal, action, resource);`
	p, err := LoadCedar([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Limits()) != 0 || p.Cedar() != src || len(p.Version()) != 64 {
		t.Error("accessors")
	}
	check(t, p, "forbid", call{tool: "x.rm"}, want{contracts.OutcomeDeny, "a", ""})
	check(t, p, "approval", call{tool: "x.y"}, want{contracts.OutcomeRequireApproval, "b", ""})
	if _, err := LoadCedar([]byte("@id(\"a\") permit (principal, action, resource);\n@id(\"a\") permit (principal, action, resource);")); err == nil {
		t.Error("duplicate ids: want error")
	}
	if _, err := LoadCedar([]byte("@effect(\"deny\") permit (principal, action, resource);")); err == nil {
		t.Error("bad effect: want error")
	}
}

// TestE2E_PolicyBehindHarness drives the harness: the server's tool handlers
// ask the policy and answer with the structured refusal.
func TestE2E_PolicyBehindHarness(t *testing.T) {
	p := mustCompile(t, yaml51)
	gate := func(tool string) mcp.ToolHandler {
		return func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			out, err := p.Decide(ctx, call{tool: "fs." + tool}.input())
			if err != nil {
				return nil, err
			}
			if out.Outcome != contracts.OutcomeAllow {
				ce := &contracts.CallError{Err: contracts.ErrDenied, RuleID: out.RuleID, Reason: out.Reason}
				return harness.Refuse(contracts.GatewayMeta{Outcome: ce.Outcome(), Reason: out.Reason, RuleID: out.RuleID}, ce.Error()), nil
			}
			return harness.Echo(ctx, req)
		}
	}
	target := harness.StartServer(t, harness.Options{Tools: []harness.Tool{
		{Name: "delete_everything", InputSchema: json.RawMessage(`{"type":"object"}`), Handler: gate("delete_everything")},
		{Name: "echo", InputSchema: json.RawMessage(`{"type":"object"}`), Handler: gate("echo")},
	}})
	c := harness.NewClient(t, target)

	res, err := c.Call("delete_everything", map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	m, ok := harness.MetaOf(res)
	if !res.IsError || !ok || m.Outcome != contracts.EntryDenied || m.RuleID != "no-destructive" || m.Reason != "denied by rule no-destructive" {
		t.Fatalf("deny: %+v meta %+v", res, m)
	}

	res, err = c.Call("echo", map[string]any{"a": 1})
	if err != nil || res.IsError {
		t.Fatalf("echo: %v %+v", err, res)
	}
}

func TestSchemaValidatorLoaded(t *testing.T) {
	mustCompile(t, yaml51)
	if validator == nil {
		t.Error("schema validation inactive")
	}
}

func TestDecideFailsClosedOnCedarError(t *testing.T) {
	p, err := LoadCedar([]byte(`@id("f") forbid(principal,action,resource) when { context.remaining_daily_micros < 5000000 };
@id("p") permit(principal,action,resource);`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Decide(context.Background(), call{tool: "x.y"}.input()); err == nil {
		t.Error("want evaluation error")
	}
}

func TestVersionIsSHA256(t *testing.T) {
	p := mustCompile(t, yaml51)
	sum := sha256.Sum256([]byte(p.Cedar()))
	if p.Version() != hex.EncodeToString(sum[:]) {
		t.Error("version is not sha256 of cedar")
	}
}
