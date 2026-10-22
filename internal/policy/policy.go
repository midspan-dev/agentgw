// Package policy compiles the policy YAML (contracts/policy-yaml.md) to Cedar
// and evaluates contracts.DecisionInput against it.
package policy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	cedar "github.com/cedar-policy/cedar-go"
	xast "github.com/cedar-policy/cedar-go/x/exp/ast"
	"github.com/cedar-policy/cedar-go/x/exp/schema"
	"github.com/cedar-policy/cedar-go/x/exp/schema/validate"
	"github.com/midspan-dev/agentgw/pkg/contracts"
	"golang.org/x/text/unicode/norm"
	"gopkg.in/yaml.v3"
)

// meta is what the evaluator needs to know about one Cedar policy.
type meta struct {
	idx        int
	id         string
	effect     contracts.Outcome
	approvers  []string
	timeoutSec int
}

// Policy is a compiled policy set. Immutable after construction; safe for concurrent use.
type Policy struct {
	cedar   string
	version string
	limits  []contracts.BudgetLimit
	set     cedar.PolicyMap
	metas   map[cedar.PolicyID]*meta
}

// Cedar returns the emitted (or, for LoadCedar, the given) Cedar text.
func (p *Policy) Cedar() string { return p.cedar }

// Version is the hex SHA-256 of Cedar(); it is the ledger's policy_version.
func (p *Policy) Version() string { return p.version }

// Limits returns the compiled budgets section, one per window, file order.
func (p *Policy) Limits() []contracts.BudgetLimit { return p.limits }

var idRe = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
var windows = []contracts.Window{contracts.WindowPerRun, contracts.WindowDaily, contracts.WindowMonthly}

func validWindow(w contracts.Window) bool {
	return w == contracts.WindowPerRun || w == contracts.WindowDaily || w == contracts.WindowMonthly
}

// LoadCedar builds a Policy from raw Cedar. Ids come from @id, @effect
// defaults to the Cedar effect, Limits is empty.
func LoadCedar(src []byte) (*Policy, error) { return newPolicy(string(src)) }

func newPolicy(text string) (*Policy, error) {
	list, err := cedar.NewPolicyListFromBytes("policy.cedar", []byte(text))
	if err != nil {
		return nil, fmt.Errorf("policy: cedar: %w", err)
	}
	sum := sha256.Sum256([]byte(text))
	p := &Policy{cedar: text, version: hex.EncodeToString(sum[:]),
		set: cedar.PolicyMap{}, metas: map[cedar.PolicyID]*meta{}}
	for i, pol := range list {
		id := string(pol.Annotations()["id"])
		if id == "" {
			id = fmt.Sprintf("policy%d", i)
		}
		if _, dup := p.metas[cedar.PolicyID(id)]; dup {
			return nil, fmt.Errorf("policy: line %d: duplicate policy id %q", pol.Position().Line, id)
		}
		m := &meta{idx: i, id: id, timeoutSec: 600}
		eff, has := pol.Annotations()["effect"]
		switch {
		case pol.Effect() == cedar.Forbid && (!has || eff == "deny"):
			m.effect = contracts.OutcomeDeny
		case pol.Effect() == cedar.Permit && (!has || eff == "allow"):
			m.effect = contracts.OutcomeAllow
		case pol.Effect() == cedar.Permit && eff == "require_approval":
			m.effect = contracts.OutcomeRequireApproval
		default:
			return nil, fmt.Errorf("policy: line %d: policy %q: @effect %q does not fit a %v policy", pol.Position().Line, id, eff, pol.Effect())
		}
		p.metas[cedar.PolicyID(id)] = m
		p.set[cedar.PolicyID(id)] = pol
	}
	return p, nil
}

// --- YAML compile ---

// Cedar schema of contracts/policy-yaml.md section 3.
const schemaText = `entity Agent = {
  "agent_id": String,
  "owner": String,
  "run_id": String,
  "session_id": String,
};
entity Tool = {
  "full_name": String,
  "server": String,
  "name": String,
};
action "call" appliesTo {
  principal: [Agent],
  resource: [Tool],
  context: {
    "estimated_cost_micros": Long,
    "remaining_per_run_micros"?: Long,
    "remaining_daily_micros"?: Long,
    "remaining_monthly_micros"?: Long,
  }
};
`

var (
	schemaOnce sync.Once
	validator  *validate.Validator // nil when cedar-go cannot load the schema; then parse-only
)

func loadValidator() {
	var s schema.Schema
	if s.UnmarshalCedar([]byte(schemaText)) != nil {
		return
	}
	r, err := s.Resolve()
	if err != nil {
		return
	}
	validator = validate.New(r)
}

// lit renders s as a Cedar string literal body (escapes " and \), after NFC.
func lit(s string) string {
	s = norm.NFC.String(s)
	s = strings.ReplaceAll(s, `\`, `\\`)
	return strings.ReplaceAll(s, `"`, `\"`)
}

func micros(f float64) int64 { return int64(math.Round(f * contracts.MicrosPerUnit)) }

// checkAmount rejects what the schema forbids (number >= 0) plus values whose micros overflow int64.
func checkAmount(f float64) error {
	if math.IsNaN(f) || math.IsInf(f, 0) || f < 0 || f > math.MaxInt64/contracts.MicrosPerUnit {
		return fmt.Errorf("amount %v must be a finite number between 0 and %d", f, int64(math.MaxInt64/contracts.MicrosPerUnit))
	}
	return nil
}

var currencyRe = regexp.MustCompile(`^[A-Z]{3}$`)
var timeoutRe = regexp.MustCompile(`^[0-9]+(ms|s|m|h)$`)

func seqNodes(root *yaml.Node, key string) (nodes []*yaml.Node, present bool) {
	if root.Kind == yaml.DocumentNode && len(root.Content) > 0 {
		root = root.Content[0]
	}
	if root.Kind != yaml.MappingNode {
		return nil, false
	}
	for i := 0; i+1 < len(root.Content); i += 2 {
		if root.Content[i].Value == key {
			if root.Content[i+1].Kind != yaml.SequenceNode {
				return nil, false
			}
			return root.Content[i+1].Content, true
		}
	}
	return nil, false
}

func seqLines(root *yaml.Node, key string) (lines []int, present bool) {
	nodes, present := seqNodes(root, key)
	for _, n := range nodes {
		lines = append(lines, n.Line)
	}
	return lines, present
}

// hasKey reports whether mapping node n contains key, even with a null value.
func hasKey(n *yaml.Node, key string) bool {
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			return true
		}
	}
	return false
}

func checkGlobs(what string, globs []string) error {
	for _, g := range globs {
		if g == "" || !utf8.ValidString(g) || strings.IndexFunc(g, unicode.IsControl) >= 0 {
			return fmt.Errorf("%s: bad glob %q", what, g)
		}
	}
	return nil
}

func orClause(field string, globs []string) string {
	parts := make([]string, len(globs))
	for i, g := range globs {
		parts[i] = field + ` like "` + lit(g) + `"`
	}
	return strings.Join(parts, " || ")
}

// Compile parses policy YAML (or JSON), checks it against the grammar, emits
// Cedar in the layout of policy-yaml.md section 4 and parses that.
func Compile(src []byte) (*Policy, error) {
	var root yaml.Node
	if err := yaml.Unmarshal(src, &root); err != nil {
		return nil, fmt.Errorf("policy: %w", err)
	}
	var pf contracts.PolicyFile
	dec := yaml.NewDecoder(bytes.NewReader(src))
	dec.KnownFields(true)
	if err := dec.Decode(&pf); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, errors.New("policy: empty file")
		}
		return nil, fmt.Errorf("policy: %w", err)
	}
	if err := dec.Decode(&yaml.Node{}); !errors.Is(err, io.EOF) {
		return nil, errors.New("policy: file must contain exactly one YAML document")
	}
	ruleLines, hasRules := seqLines(&root, "rules")
	ruleNodes, _ := seqNodes(&root, "rules")
	budgetLines, _ := seqLines(&root, "budgets")
	if pf.Version != contracts.SchemaVersion {
		return nil, fmt.Errorf("policy: version must be %q, got %q", contracts.SchemaVersion, pf.Version)
	}
	if !hasRules {
		return nil, errors.New("policy: rules is required (use [] for none)")
	}
	cur := pf.Currency
	if cur == "" {
		cur = "USD"
	}
	if !currencyRe.MatchString(cur) {
		return nil, fmt.Errorf("policy: currency %q must match %s", cur, currencyRe)
	}

	var b strings.Builder
	if len(pf.Agents) > 0 {
		ids := make([]string, len(pf.Agents))
		for i, a := range pf.Agents {
			if a.Owner == "" || checkGlobs("agent id", []string{a.ID}) != nil {
				return nil, fmt.Errorf("policy: agents[%d]: id and owner are required, id without control characters", i)
			}
			ids[i] = `principal == Agent::"` + lit(a.ID) + `"`
		}
		emit(&b, contracts.RuleUnknownAgent, "deny", "forbid", "unless", strings.Join(ids, " || "))
	}

	timeouts := map[string]int{}
	seen := map[string]bool{}
	for i, r := range pf.Rules {
		fail := func(f string, a ...any) error {
			return fmt.Errorf("policy: line %d: rule %q: %s", ruleLines[i], r.ID, fmt.Sprintf(f, a...))
		}
		switch {
		case !idRe.MatchString(r.ID):
			return nil, fail("id must match %s", idRe)
		case r.ID == contracts.RuleDefaultDeny || r.ID == contracts.RuleUnknownAgent || r.ID == contracts.RuleEvaluationError:
			return nil, fail("id is reserved")
		case seen[r.ID]:
			return nil, fail("duplicate id")
		case len(r.Tools) == 0:
			return nil, fail("tools is required")
		}
		seen[r.ID] = true
		kw := "permit"
		switch r.Effect {
		case contracts.OutcomeAllow, contracts.OutcomeRequireApproval:
		case contracts.OutcomeDeny:
			kw = "forbid"
		default:
			return nil, fail("unknown effect %q", r.Effect)
		}
		if r.Effect != contracts.OutcomeRequireApproval && (r.Approvers != nil || r.Timeout != "") {
			return nil, fail("approvers and timeout are only valid with effect require_approval")
		}
		if r.Timeout != "" {
			d, err := time.ParseDuration(r.Timeout)
			if err != nil || d <= 0 || !timeoutRe.MatchString(r.Timeout) {
				return nil, fail("bad timeout %q", r.Timeout)
			}
			timeouts[r.ID] = int((d + time.Second - 1) / time.Second)
		}
		if err := errors.Join(checkGlobs("agents", r.Agents), checkGlobs("tools", r.Tools)); err != nil {
			return nil, fail("%v", err)
		}
		if len(r.Agents) == 0 && hasKey(ruleNodes[i], "agents") { // covers [] and null
			return nil, fail("agents must be omitted or non-empty")
		}
		var clauses []string
		if len(r.Agents) > 0 {
			clauses = append(clauses, orClause("principal.agent_id", r.Agents))
		}
		clauses = append(clauses, orClause("resource.full_name", r.Tools))
		if w := r.When; w != nil {
			if w.EstimatedCostAbove == nil && len(w.BudgetRemainingBelow) == 0 {
				return nil, fail("when must not be empty")
			}
			if w.BudgetRemainingBelow != nil && len(w.BudgetRemainingBelow) == 0 {
				return nil, fail("budget_remaining_below must not be empty")
			}
			if a := w.EstimatedCostAbove; a != nil {
				if err := checkAmount(*a); err != nil {
					return nil, fail("estimated_cost_above: %v", err)
				}
				clauses = append(clauses, fmt.Sprintf("context.estimated_cost_micros > %d", micros(*a)))
			}
			for win, a := range w.BudgetRemainingBelow {
				if err := checkAmount(a); !validWindow(win) || err != nil {
					return nil, fail("bad budget_remaining_below entry %s: %v (finite number >= 0, known window)", win, a)
				}
			}
			for _, win := range windows {
				if a, ok := w.BudgetRemainingBelow[win]; ok {
					clauses = append(clauses, fmt.Sprintf("context has remaining_%s_micros && context.remaining_%s_micros < %d", win, win, micros(a)))
				}
			}
		}
		emit(&b, r.ID, string(r.Effect), kw, "when", clauses...)
	}

	var limits []contracts.BudgetLimit
	for i, bu := range pf.Budgets {
		if bu.Agent == "" || bu.Tool == "" || len(bu.Limits) == 0 {
			return nil, fmt.Errorf("policy: line %d: budgets[%d]: agent, tool and limits are required", budgetLines[i], i)
		}
		if err := checkGlobs("budget", []string{bu.Agent, bu.Tool}); err != nil {
			return nil, fmt.Errorf("policy: line %d: budgets[%d]: %v", budgetLines[i], i, err)
		}
		for w, a := range bu.Limits {
			if err := checkAmount(a); !validWindow(w) || err != nil {
				return nil, fmt.Errorf("policy: line %d: budgets[%d]: bad limit %s: %v", budgetLines[i], i, w, a)
			}
		}
		for _, w := range windows {
			if a, ok := bu.Limits[w]; ok {
				limits = append(limits, contracts.BudgetLimit{Agent: norm.NFC.String(bu.Agent), Tool: norm.NFC.String(bu.Tool),
					Window: w, Limit: contracts.Money{Micros: micros(a), Currency: cur}})
			}
		}
	}

	p, err := newPolicy(b.String())
	if err != nil {
		return nil, err
	}
	p.limits = limits
	for _, r := range pf.Rules {
		m := p.metas[cedar.PolicyID(r.ID)]
		m.approvers = r.Approvers
		if t, ok := timeouts[r.ID]; ok {
			m.timeoutSec = t
		}
	}
	schemaOnce.Do(loadValidator)
	if validator != nil {
		for id, pol := range p.set {
			if err := validator.Policy(string(id), (*xast.Policy)(pol.AST())); err != nil {
				return nil, fmt.Errorf("policy: rule %q fails schema validation: %w", id, err)
			}
		}
	}
	return p, nil
}

// emit writes one policy in the layout of policy-yaml.md section 4. kind is
// "when" or "unless"; each clause gets its own block.
func emit(b *strings.Builder, id, effect, kw, kind string, clauses ...string) {
	if b.Len() > 0 {
		b.WriteString("\n")
	}
	fmt.Fprintf(b, "@id(\"%s\")\n@effect(\"%s\")\n%s (\n  principal,\n  action == Action::\"call\",\n  resource\n)", id, effect, kw)
	for _, c := range clauses {
		fmt.Fprintf(b, "\n%s { %s }", kind, c)
	}
	b.WriteString(";\n")
}

// --- evaluation ---

var callAction = cedar.NewEntityUID("Action", "call")

// Decide implements contracts.Decider.
func (p *Policy) Decide(_ context.Context, in contracts.DecisionInput) (contracts.DecisionOutput, error) {
	out := contracts.DecisionOutput{Version: contracts.SchemaVersion, PolicyVersion: p.version}
	if in.Version != contracts.SchemaVersion {
		return out, fmt.Errorf("policy: unsupported decision input version %q", in.Version)
	}
	if len(in.Action.Args) > 0 && !json.Valid(in.Action.Args) {
		return out, errors.New("policy: malformed action args")
	}
	pr := in.Principal
	n := norm.NFC.String
	agent := cedar.NewEntityUID("Agent", cedar.String(n(pr.AgentID)))
	full := n(in.Action.Server + "." + in.Action.Tool)
	tool := cedar.NewEntityUID("Tool", cedar.String(full))
	ents := cedar.EntityMap{
		agent: {UID: agent, Parents: cedar.NewEntityUIDSet(), Attributes: cedar.NewRecord(cedar.RecordMap{
			"agent_id": cedar.String(n(pr.AgentID)), "owner": cedar.String(n(pr.Owner)),
			"run_id": cedar.String(n(pr.RunID)), "session_id": cedar.String(n(pr.SessionID))})},
		tool: {UID: tool, Parents: cedar.NewEntityUIDSet(), Attributes: cedar.NewRecord(cedar.RecordMap{
			"full_name": cedar.String(full), "server": cedar.String(n(in.Action.Server)), "name": cedar.String(n(in.Action.Tool))})},
	}
	ctx := cedar.RecordMap{"estimated_cost_micros": cedar.Long(in.Context.EstimatedCost.Micros)}
	for w, m := range in.Context.BudgetRemaining {
		if validWindow(w) {
			ctx[cedar.String("remaining_"+string(w)+"_micros")] = cedar.Long(m.Micros)
		}
	}
	dec, diag := cedar.Authorize(p.set, ents, cedar.Request{Principal: agent, Action: callAction, Resource: tool, Context: cedar.NewRecord(ctx)})

	if len(diag.Errors) > 0 {
		return out, fmt.Errorf("policy: evaluation error: %v", diag.Errors[0])
	}
	var forbid, approval, allow *meta
	pick := func(cur, m *meta) *meta {
		if cur == nil || m.idx < cur.idx {
			return m
		}
		return cur
	}
	for _, r := range diag.Reasons {
		m := p.metas[r.PolicyID]
		switch m.effect {
		case contracts.OutcomeDeny:
			forbid = pick(forbid, m)
		case contracts.OutcomeRequireApproval:
			approval = pick(approval, m)
		default:
			allow = pick(allow, m)
		}
	}
	switch {
	case dec == cedar.Deny && forbid != nil:
		out.Outcome, out.RuleID = contracts.OutcomeDeny, forbid.id
		if forbid.id == contracts.RuleUnknownAgent {
			out.Reason = fmt.Sprintf("agent %s is not in the policy's agents list", pr.AgentID)
		} else {
			out.Reason = "denied by rule " + forbid.id
		}
	case dec == cedar.Allow && approval != nil:
		out.RuleID = approval.id
		for i := range in.Context.Grants {
			g := &in.Context.Grants[i]
			if g.AgentID == pr.AgentID && g.Server == in.Action.Server && g.Tool == in.Action.Tool &&
				g.Until.After(in.Context.Time) && (g.Scope == contracts.GrantScopeAgent || g.RunID == pr.RunID) {
				out.Outcome, out.GrantID = contracts.OutcomeAllow, g.ID
				return out, nil
			}
		}
		out.Outcome = contracts.OutcomeRequireApproval
		out.Reason = "rule " + approval.id + " requires approval"
		appr := approval.approvers
		if appr == nil {
			appr = []string{}
		}
		out.Approval = &contracts.ApprovalSpec{Approvers: appr, TimeoutSeconds: approval.timeoutSec}
	case dec == cedar.Allow && allow != nil:
		out.Outcome, out.RuleID = contracts.OutcomeAllow, allow.id
	default:
		out.Outcome, out.RuleID = contracts.OutcomeDeny, contracts.RuleDefaultDeny
		out.Reason = fmt.Sprintf("no rule allows %s.%s for %s", in.Action.Server, in.Action.Tool, pr.AgentID)
	}
	return out, nil
}

var _ contracts.Decider = (*Policy)(nil)
