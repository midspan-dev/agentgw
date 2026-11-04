# Two hosted MCP servers behind one gateway

Claude Code reaches GitHub's and Linear's hosted MCP servers through
`agentgw serve`. The gateway holds both credentials: a GitHub token it sends
as a header, and your Linear sign-in, which it refreshes. Claude Code holds
neither. Every write waits for you in `agentgw watch`.

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

Point Claude Code at the gateway, from the directory you want to work in:

```sh
claude mcp add --transport http github http://127.0.0.1:8787/github
claude mcp add --transport http linear http://127.0.0.1:8787/linear
```

Ask Claude to list the open issues in your repository and in Linear: `watch`
shows each read as `allow … ok`. Ask it to comment on one or create one:
`watch` shows a card, and nothing reaches the server until you type `a`
(approve) or `d` (deny). Afterwards:

```sh
agentgw verify --config agentgw.yaml
```

## What the files do

- `agentgw.yaml`: the two upstreams and their `auth`. No secret is in it.
  The token comes from the environment; the Linear tokens are in
  `tokens/linear.json`, readable only by you. Treat that file like a
  password: it can act as you on Linear until you revoke it.
- `policy.yaml`: writes need approval, reads go through. Linear's write
  tools are taken from its tool list; GitHub's from the self-hosted server's
  issues toolset. A server can add tools at any time, and a new write tool
  is allowed until you add it, so check what `watch` shows.

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
`agentgw verify` passed. Not run with a real GitHub token.
