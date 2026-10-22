# testdata

Shared fixtures for `internal/harness`. One line per file.

## tools/ (loaded by `harness.DefaultTools`; format is `harness.Tool`)

- `tools/echo.json`: `echo`, returns its arguments as one text item, no cost.
- `tools/search.json`: `search`, returns its arguments, `_meta.cost` 0.005 USD.
- `tools/refund.json`: `refund`, returns its arguments, `_meta.cost` = `args.amount` USD.
- `tools/delete_everything.json`: `delete_everything`, returns its arguments; the destructive tool policies deny.
- `tools/slow.json`: `slow`, returns its arguments after 10 s (`latency_ms`).

## golden/ (compared by `harness.Golden`; every line validates against contracts/schemas/ledger-entry.schema.json)

Shared assumptions in every golden: `principal.agent_id` `test-agent`, `owner`
`test@example.com`, upstream `action.server` `harness`. `result.content` is the
harness result after the ledger strips the protocol envelope (no `resultType`,
no `io.modelcontextprotocol/*` meta; `_meta.cost` kept; docs/adr/0008).
Ignored fields hold placeholders.

- `golden/allow.jsonl`: 5 `echo` calls with `{"n":1..5}`, decision allow by `allow-all`, outcome ok, cost 0.
- `golden/deny.jsonl`: 1 `delete_everything` `{"path":"/"}`, deny by `no-destructive`, outcome denied, error `agentgw: denied by policy: denied by rule no-destructive`.
- `golden/approval.jsonl`: 1 `refund` `{"amount":50,"charge":"ch_123"}`, require_approval by `refunds-need-approval`, outcome ok, cost 50 USD.
- `golden/budget.jsonl`: 3 `search` calls `{"query":"q1..q3"}` allowed by `allow-all`; first two ok at 0.005 USD, third budget_exceeded, actual 0, error `agentgw: budget exceeded: per_run budget exceeded`.
- `golden/timeout.jsonl`: 1 `refund` `{"amount":50,"charge":"ch_123"}`, require_approval by `refunds-need-approval`, outcome approval_timeout, estimated 50 USD, actual 0, error `agentgw: approval timed out`.
- `golden/error.jsonl`: 1 `echo` `{"n":1}` under failure injection, allow by `allow-all`, outcome error, content null, cost 0; `result.error` is ignored by Golden.
