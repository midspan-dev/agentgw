# Policy YAML grammar (v1)

The policy file is YAML (or JSON) matching `schemas/policy.schema.json`. It
compiles to Cedar (docs/adr/0002). This document is the contract for the
`policy` node: every field, the evaluation order, and the exact Cedar each
construct emits. Users who want more than this grammar write Cedar directly
against the same entity model (section 5).

## 1. File shape

```yaml
version: "1"            # required, schema version
currency: USD           # optional, default USD; unit for every amount below
agents:                 # optional; non-empty = allowlist of agent ids
  - id: billing-bot     # exact id, not a glob
    owner: alice@example.com
budgets:                # optional; enforced by Budget.Reserve, not by Cedar
  - agent: "*"          # glob over agent id
    tool: "*"           # glob over "<server>.<tool>"
    limits:             # absent window = unlimited; 0 = block all spend
      per_run: 5
      daily: 50
rules:                  # required; may be empty (then everything is denied)
  - id: allow-search    # [A-Za-z0-9_-]+, unique; becomes Cedar policy id and ledger rule_id
    effect: allow       # allow | deny | require_approval
    agents: ["*"]       # optional globs, any may match; omitted = every agent; [] = compile error
    tools: ["*.search"] # required globs over "<server>.<tool>", any may match
    when:               # optional; all conditions must hold
      estimated_cost_above: 100            # estimated_cost > 100 units
      budget_remaining_below:          # budget_remaining[window] < amount
        daily: 10
    approvers: ["alice"]              # require_approval only; surface identities (GitHub logins); omitted = any approver
    timeout: 10m                      # require_approval only; Go duration; default 10m
```

Globs: `*` matches any run of characters (including empty, including `.`).
No `?`, no character classes. Matching is case-sensitive after NFC
normalisation of both pattern and input. A `tools` pattern matches the string
`<server>.<tool>`; server names contain no dots (`common.schema.json`
`server_name`), so `stripe.*` means every tool on `stripe` and `*.refund`
means `refund` on any server.

Policy sees `server`, `tool`, `agent_id`, estimated cost and remaining
budget, not argument values and not the multi-round-trip `inputResponses`.
A future argument-matching construct must consider both, and must have the
proxy reject case-variant duplicate keys and non-finite or oversized numbers
first, because tools may decode arguments case-insensitively (gap-004).

Amounts are decimal numbers in `currency` units. The compiler converts them to
integer micros (`contracts.Money`) with round-half-away-from-zero:
`100` -> `100000000`, `0.005` -> `5000`.

Reserved rule ids: `default-deny`, `unknown-agent`, `evaluation-error` (used by
the pipeline when `Decide` returns an error). Using them in `rules` is a
compile error. Compile errors name the YAML line.

## 2. Evaluation order

Given a `DecisionInput`, the Decider:

1. **Unknown agent.** If `agents` is non-empty and `principal.agent_id` is
   not listed: `deny`, `rule_id: unknown-agent`. (Emitted as a Cedar
   `forbid`, so Cedar reaches the same answer; the id is fixed either way.)
2. **Deny wins.** If any `deny` rule matches: `deny`, `rule_id` = the
   matching deny rule that appears first in the file.
3. **Approval beats allow.** Else if any `require_approval` rule matches:
   - if `context.grants` holds a grant with `agent_id == principal.agent_id`,
     `server == action.server`, `tool == action.tool`, `until > context.time`,
     and (`scope == agent` or `run_id == principal.run_id`): `allow`,
     `rule_id` = the rule, `grant_id` = the grant's id;
   - else `require_approval`, `rule_id` = the first such rule in file order,
     `approval` = `{approvers, timeout_seconds}` from that rule (defaults:
     `[]`, `600`).
   **Approvers (rev 10, gap-008, docs/adr/0011 decision 8).** An entry is
   the identity reported by the surface doing the approving; for GitHub
   comments that is the GitHub login, compared case-insensitively. There is
   no prefix syntax. An entry that is not a valid identity on a surface
   never matches there: an email address never matches a GitHub login
   (logins cannot contain `@`), so GitHub fails closed for it and the call
   can only be decided from the terminal, or it expires. An empty list
   means any approver who passes the surface's own checks (for GitHub, the
   repository role). The terminal (`agentgw approvals`, `agentgw watch`)
   does not enforce the list: its identity is the approver-key holder,
   which cannot be matched to a name (known limitation). If one gateway
   ever takes approvals from several surfaces, the same string could name
   different people; a people-to-identities mapping in config is the
   planned fix, not prefixes.
4. **Allow.** Else if any `allow` rule matches: `allow`, `rule_id` = the
   first matching allow rule in file order.
5. **Default deny.** Else `deny`, `rule_id: default-deny`.

A rule matches when its `agents` (if present) has a pattern matching
`principal.agent_id`, its `tools` has a pattern matching
`<server>.<tool>`, and every `when` condition holds. `estimated_cost` is the
Pricer's estimate under the config.schema.json `prices` rule (numeric strings
count as their number; a present but unpriceable `arg_field` denies the call
with `evaluation-error` before any rule runs). `estimated_cost_above` holds when
`estimated_cost.micros > estimated_cost_above` (in micros). `budget_remaining_below[w]` holds
when `budget_remaining[w]` is present and `budget_remaining[w].micros <`
the amount; an absent window never satisfies the condition.

`reason` is `""` on allow, `"rule <id> requires approval"` on
require_approval, `"denied by rule <id>"` on deny by a rule,
`"agent <id> is not in the policy's agents list"` for unknown-agent, and
`"no rule allows <server>.<tool> for <agent_id>"` for default-deny.

`policy_version` is the lower-case hex SHA-256 of the UTF-8 bytes of the
emitted Cedar text (section 4). For raw Cedar input it is the hash of the
source as given.

Budgets (`budgets:`) are not evaluated here. The compiler turns each item into
`contracts.BudgetLimit` values (one per window) that the budgets node enforces
in `Budget.Reserve`. A call must fit every limit whose globs match it.

## 3. Entity model (what Cedar sees)

Schema, in Cedar human-readable schema syntax (no namespace):

```
entity Agent = {
  "agent_id": String,
  "owner": String,
  "run_id": String,
  "session_id": String,
};
entity Tool = {
  "full_name": String,   // "<server>.<tool>"
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
```

Request built from a `DecisionInput`:

- principal `Agent::"<agent_id>"` with the four attributes from `principal`;
- action `Action::"call"`;
- resource `Tool::"<server>.<tool>"` with `full_name`, `server`, `name`;
- context: `estimated_cost_micros` = `estimated_cost.micros`; each
  `remaining_<window>_micros` present iff `budget_remaining[window]` is.

Entities carry no parents. Currency is not visible to Cedar; the gateway is
single-currency (`config.currency`).

## 4. Cedar emitted per construct

The compiler emits one Cedar file: the `unknown-agent` policy first (if
`agents` is non-empty), then one policy per rule in file order. Each policy is
emitted in exactly this layout, so tests compare after collapsing runs of
whitespace to one space:

```
@id("<rule id>")
@effect("<allow|deny|require_approval>")
<permit|forbid> (
  principal,
  action == Action::"call",
  resource
)
when { <agents clause> }            // omitted when agents is omitted
when { <tools clause> }
when { context.estimated_cost_micros > <micros> }                                            // estimated_cost_above
when { context has remaining_<w>_micros && context.remaining_<w>_micros < <micros> } // one per budget_remaining_below window, order per_run, daily, monthly
;
```

- `effect: allow` and `effect: require_approval` emit `permit`; `effect: deny`
  emits `forbid`. The `@effect` annotation is how the evaluator tells the two
  permits apart (Cedar has no third effect).
- agents clause: `principal.agent_id like "<p1>" || principal.agent_id like "<p2>"`.
- tools clause: `resource.full_name like "<p1>" || resource.full_name like "<p2>"`.
- A glob is emitted as a Cedar `like` pattern verbatim: `*` is the wildcard
  in both. `"` and `\` inside a pattern are escaped as `\"` and `\\`. A single
  pattern `"*"` still emits the clause (`like "*"`), so output stays regular.
- Policies with no `when` clauses end with `)` followed by `;`.

The agents allowlist emits:

```
@id("unknown-agent")
@effect("deny")
forbid (
  principal,
  action == Action::"call",
  resource
)
unless { principal == Agent::"<id1>" || principal == Agent::"<id2>" };
```

Evaluation maps Cedar's answer back as in section 2: Cedar `Deny` with
reasons -> the lowest-index forbid among the reasons; Cedar `Deny` without
reasons -> `default-deny`; Cedar `Allow` -> inspect the `@effect` of the
permits in the reasons (require_approval first, then allow, lowest index
first), then apply the grant short-circuit.

## 5. Examples

Each example gives the YAML, the exact Cedar, and decisions for named inputs.
Inputs use `agent_id: billing-bot`, `run_id: r1`, no grants, and
`budget_remaining` as stated.

### 5.1 Deny destructive tools

```yaml
version: "1"
rules:
  - id: no-destructive
    effect: deny
    tools: ["*.delete_*"]
  - id: allow-all
    effect: allow
    tools: ["*"]
```

```
@id("no-destructive")
@effect("deny")
forbid (
  principal,
  action == Action::"call",
  resource
)
when { resource.full_name like "*.delete_*" };

@id("allow-all")
@effect("allow")
permit (
  principal,
  action == Action::"call",
  resource
)
when { resource.full_name like "*" };
```

| call                       | outcome | rule_id        |
|----------------------------|---------|----------------|
| `fs.delete_everything`     | deny    | no-destructive |
| `fs.echo`                  | allow   | allow-all      |

### 5.2 Approval over a cost threshold

```yaml
version: "1"
rules:
  - id: refunds-need-approval
    effect: require_approval
    tools: ["stripe.refund"]
    when: { estimated_cost_above: 100 }
    approvers: ["alice"]     # a GitHub login; an email entry here is only satisfiable from the terminal
    timeout: 10m
  - id: allow-stripe
    effect: allow
    agents: ["billing-*"]
    tools: ["stripe.*"]
```

```
@id("refunds-need-approval")
@effect("require_approval")
permit (
  principal,
  action == Action::"call",
  resource
)
when { resource.full_name like "stripe.refund" }
when { context.estimated_cost_micros > 100000000 };

@id("allow-stripe")
@effect("allow")
permit (
  principal,
  action == Action::"call",
  resource
)
when { principal.agent_id like "billing-*" }
when { resource.full_name like "stripe.*" };
```

| call, estimated_cost                 | outcome          | rule_id               | approval                                      |
|--------------------------------------|------------------|-----------------------|-----------------------------------------------|
| `stripe.refund`, 120.50              | require_approval | refunds-need-approval | `{approvers: [alice], timeout_seconds: 600}` |
| `stripe.refund`, 100.00              | allow            | allow-stripe          | null                                          |
| `stripe.refund`, 120.50, with grant for run r1 on stripe.refund until later | allow | refunds-need-approval | null, `grant_id` set |
| `stripe.refund`, 120.50, agent `ops-bot` | require_approval | refunds-need-approval | as row 1 (approval rule has no agents filter) |
| `search.search`, 0.005                | deny             | default-deny          | null                                          |

### 5.3 Approval when the daily budget runs low

```yaml
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
```

```
@id("low-budget-approval")
@effect("require_approval")
permit (
  principal,
  action == Action::"call",
  resource
)
when { resource.full_name like "*" }
when { context has remaining_daily_micros && context.remaining_daily_micros < 10000000 };

@id("allow-all")
@effect("allow")
permit (
  principal,
  action == Action::"call",
  resource
)
when { resource.full_name like "*" };
```

| budget_remaining            | outcome          | rule_id             |
|-----------------------------|------------------|---------------------|
| `{daily: 4.00}`             | require_approval | low-budget-approval |
| `{daily: 10.00}`            | allow            | allow-all           |
| `{}` (no daily limit)       | allow            | allow-all           |

### 5.4 Agent allowlist and budgets

```yaml
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
```

```
@id("unknown-agent")
@effect("deny")
forbid (
  principal,
  action == Action::"call",
  resource
)
unless { principal == Agent::"billing-bot" };

@id("allow-all")
@effect("allow")
permit (
  principal,
  action == Action::"call",
  resource
)
when { resource.full_name like "*" };
```

| agent_id      | outcome | rule_id       |
|---------------|---------|---------------|
| `billing-bot` | allow   | allow-all     |
| `ops-bot`     | deny    | unknown-agent |

`Limits()` for this file, in order:

```
{Agent:"*",           Tool:"*",        Window:per_run, Limit:{5000000,   USD}}
{Agent:"*",           Tool:"*",        Window:daily,   Limit:{50000000,  USD}}
{Agent:"billing-bot", Tool:"stripe.*", Window:monthly, Limit:{500000000, USD}}
```

### 5.5 Empty rules

`rules: []` compiles to an empty Cedar file; every call is `deny`,
`rule_id: default-deny`.
