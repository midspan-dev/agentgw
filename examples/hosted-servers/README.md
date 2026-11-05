# Two hosted MCP servers behind one gateway

Claude Code reaches GitHub's and Linear's hosted MCP servers through
`agentgw serve`. The gateway holds both credentials: a GitHub token it sends
as a header, and your Linear sign-in, which it refreshes. You configure neither
in the MCP client. The writes named in the policy wait for you in `agentgw
watch`, the reads named there go through, and anything else is denied.

That is only a boundary if the agent has no other way to reach those files,
so the steps below start Claude Code with no shell and no file tools.

| | GitHub | Linear |
|---|---|---|
| server | `https://api.githubcopilot.com/mcp/x/issues` (issues toolset) | `https://mcp.linear.app/mcp` |
| `auth.kind` | `header` | `authorization_code` |
| credential | a personal access token in `$GITHUB_TOKEN` | `agentgw login`, tokens in `tokens/linear.json` |
| gateway address | `http://127.0.0.1:8787/github` | `http://127.0.0.1:8787/linear` |

Needs agentgw, Claude Code, a Linear account, and a GitHub token for a
**throwaway repository** (a fine-grained token scoped to that one repository,
Issues read and write). Use either server alone by deleting the other from
`agentgw.yaml`.

## Run it

In this directory, set `agent.owner` in `agentgw.yaml`, then:

```sh
agentgw keygen --config agentgw.yaml           # prints the ledger public key
agentgw approvals init --config agentgw.yaml
agentgw login --config agentgw.yaml linear     # opens the browser; sign in and approve
export GITHUB_TOKEN=<your token>
agentgw serve --config agentgw.yaml
```

`serve` prints one line per server and keeps running. In a second terminal,
in this directory:

```sh
agentgw watch --config agentgw.yaml
```

In a third terminal, in this directory, define the restricted agent. Its only
tools are the two servers in `mcp.json`, reached through the gateway (the same
flags as [the laptop run](../github-actions/local.md)):

```sh
agent() {
  claude -p "$1" \
    --tools "" \
    --disallowedTools Bash Edit Write Read Glob Grep NotebookEdit WebFetch WebSearch Task Agent ListMcpResourcesTool ReadMcpResourceTool \
    --allowedTools "mcp__github" "mcp__linear" \
    --mcp-config mcp.json --strict-mcp-config \
    --permission-mode dontAsk --disable-slash-commands --no-session-persistence
}
```

List something:

```sh
agent "List the open issues in you/your-repo and my Linear teams."
```

`watch` shows each read as `allow … ok`. Now write something:

```sh
agent "Comment 'hello from agentgw' on issue #1 in you/your-repo."
```

`watch` shows a card, and nothing reaches the server until you type `a`
(approve) or `d` (deny). Afterwards:

```sh
agentgw verify --config agentgw.yaml
```

## With your usual Claude Code

To try the gateway from an ordinary session:

```sh
claude mcp add --transport http github http://127.0.0.1:8787/github
claude mcp add --transport http linear http://127.0.0.1:8787/linear
```

This is a functional demo, not a security boundary. Claude Code keeps its shell
and file tools and runs as you, so only its own permission prompts stand between
it and `tokens/linear.json`, `approver.key` and `policy.yaml`. File mode `0600`
does not separate two processes run by the same user. See
[Before you rely on it](https://docs.midspan.dev/quickstart#before-you-rely-on-it).

## What the files do

- `agentgw.yaml`: the two upstreams and their `auth`. No secret is in it.
  The token comes from the environment; the Linear tokens are in
  `tokens/linear.json`, readable only by you. Treat that file like a
  password: it can act as you on Linear until you revoke it.
- `policy.yaml`: named writes need approval, named reads go through. Linear's
  write tools are taken from its tool list; GitHub's tools from the self-hosted
  server's issues toolset. Linear's reads are matched by prefix (`list_`, `get_`,
  `search_`). Tools that match no rule are denied. New tools matching an
  existing prefix inherit that rule's behavior. A denied call in `watch` may
  just need a rule.
- `mcp.json`: the gateway's two addresses, for the restricted agent. No secret
  is in it.

`keygen`, `approvals init`, `login` and `serve` create `ledger.key`,
`approver.key`, `tokens/`, `agentgw.db` and `ledger.jsonl` here. Delete them
to start over, and remove the servers from Claude Code with
`claude mcp remove github` and `claude mcp remove linear`.

## Checked

On 2026-11-02, without credentials: both servers answer an unauthenticated
request with a 401 that points to their protected-resource metadata, the
metadata's `resource` matches the URL above, and Linear's authorization
server offers PKCE S256 and client registration, which is what `agentgw
login` needs. GitHub's authorization server offers no client registration,
which is why this example uses a token for it.

Then with a real Linear account: `agentgw login` registered a client, Linear
accepted the loopback redirect on an ephemeral port, and the token file was
written readable only by its owner. Through `serve`, `initialize`,
`tools/list` and a `list_teams` call succeeded (Linear needs no MCP
session), the client's own `Authorization` header never reached Linear, and
`agentgw verify` passed.

Not run: anything with a real GitHub token, an approved write on either server,
or a refresh against Linear. The policy's list of reads came after the run above.
