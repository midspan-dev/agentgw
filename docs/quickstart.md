# Quickstart

Five minutes: put agentgw in front of one MCP server, watch the signed ledger
fill, add a rule, verify the ledger. We use the reference "everything" server
because its `echo` tool is harmless.

Needs: Claude Code, Node.js (for `npx`), Homebrew.

## 1. Install

```sh
brew install midspan-dev/tap/agentgw
agentgw version
```

No Homebrew: download a binary from the GitHub releases page. (The Docker
image, `ghcr.io/midspan-dev/agentgw`, is for running the gateway as a service, not
for this quickstart.)

## 2. Configure

```sh
mkdir -p ~/.agentgw && cd ~/.agentgw

cat > agentgw.yaml <<'EOF'
version: "1"
agent: { id: me, owner: me@example.com }
currency: USD
listen: ":8080"
upstreams:
  - { name: everything, command: ["npx", "-y", "@modelcontextprotocol/server-everything"] }
policy_path: policy.yaml
prices: []
redaction: { fields: [api_key, authorization], patterns: [] }
approvals: { cli: { token_path: approver.key } }
ledger: { path: ledger.jsonl, checkpoint_every: 100 }
key_path: ledger.key
state_path: agentgw.db
EOF

cat > policy.yaml <<'EOF'
version: "1"
rules:
  - { id: allow-all, effect: allow, tools: ["*"] }
EOF

agentgw keygen --config agentgw.yaml        # prints the ledger public key; keep it
agentgw approvals init --config agentgw.yaml
```

Relative paths in the config resolve against the config file's directory.

## 3. Wrap the server in Claude Code

```sh
claude mcp add everything -- agentgw run --config $HOME/.agentgw/agentgw.yaml
```

Claude Code now starts `agentgw run`, which starts the real server and sits
between them. Open Claude Code and ask: "Use the echo tool to say hello."

## 4. See the ledger

```sh
cat ~/.agentgw/ledger.jsonl
```

One signed JSON line per tool call: who asked, the arguments, the decision
(`allow`, rule `allow-all`), the policy version, and the result.

## 5. Add a rule

Add a deny rule to `~/.agentgw/policy.yaml`:

```yaml
version: "1"
rules:
  - { id: no-echo, effect: deny, tools: ["everything.echo"] }
  - { id: allow-all, effect: allow, tools: ["*"] }
```

Deny wins over allow whatever the order. Restart Claude Code (or `/mcp` reconnect) so the gateway reloads the policy,
then ask for the echo again. The call is refused with `denied by rule
no-echo`, never reaches the server, and is recorded as a denial.

## 6. Verify the ledger

```sh
agentgw verify --config ~/.agentgw/agentgw.yaml
```

This checks every signature and the hash chain. To check from somewhere else,
you need only the file and the public key `keygen` printed:

```sh
agentgw verify ledger.jsonl <pubkey-hex>
```

Edit any byte of `ledger.jsonl` and run it again to see it fail.

## Next

Rules can also hold a call for human approval (`effect: require_approval`,
decide with `agentgw approvals list|approve|deny`) and cap spend with
`prices` and `budgets`. See `contracts/policy-yaml.md` for the full grammar.
