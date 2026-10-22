# `_meta` conventions on MCP tool results

Two `_meta` keys on `CallToolResult`, one in each direction. Both are plain
JSON objects so any MCP server or client can use them without the SDK.

## 1. Upstream -> gateway: `_meta.cost` (proposed convention)

An MCP server that knows what a call cost reports it on the result:

```json
{
  "content": [ { "type": "text", "text": "refund re_456 created" } ],
  "isError": false,
  "_meta": {
    "cost": { "amount": 120.5, "currency": "USD" }
  }
}
```

| field      | type   | rule                                                        |
|------------|--------|-------------------------------------------------------------|
| `amount`   | number | decimal in major currency units; finite; `>= 0`             |
| `currency` | string | ISO 4217 upper case; must equal the gateway `config.currency` |

The gateway (budgets node, `budget.CostFromResult`) converts `amount` to
`contracts.Money` micros with round-half-away-from-zero and uses it as the
settled cost. A `_meta.cost` that is missing, not an object, non-finite,
negative, non-numeric, or in another currency is ignored and logged; the settled cost then falls back to the price-table
estimate, then to zero. A reported cost never changes the policy decision,
which was made on the estimate; it changes what is settled.

`_meta.cost` is tool output, not protocol envelope: the ledger keeps it when it
strips `resultType` and `io.modelcontextprotocol/*` keys (docs/adr/0008).

Servers that do not know their cost omit the key. The harness attaches it per
tool from `testdata/tools/`.

## 2. Gateway -> client: `_meta.agentgw`

When the gateway refuses a call it answers with a tool error, not a transport
error, so agents can read the reason:

```json
{
  "content": [ { "type": "text", "text": "agentgw: denied by policy: denied by rule no-destructive" } ],
  "isError": true,
  "_meta": {
    "agentgw": {
      "outcome": "denied",
      "reason": "denied by rule no-destructive",
      "rule_id": "no-destructive",
      "call_id": "c9a1f0e2d3b4a5968778695a4b3c2d1e"
    }
  }
}
```

`_meta.agentgw` is `contracts.GatewayMeta`. `outcome` is one of `denied`,
`budget_exceeded`, `approval_denied`, `approval_timeout` (the ledger
`EntryOutcome` values the proxy can produce). `rule_id` is empty for
`budget_exceeded`. The text content is `CallError.Error()`. Results that were
forwarded carry no `_meta.agentgw`; the upstream result is returned verbatim.
