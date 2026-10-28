# agentgw

One MCP policy, on your laptop and in GitHub Actions. Approve CI actions by comment.

agentgw sits between your agent and its MCP servers. It allows, denies or holds
each tool call by a readable rule, and keeps a signed, independently verifiable
history of every call that you can check offline.

- Laptop: the [quickstart](docs/quickstart.md) takes about five minutes.
- GitHub Actions: [run the same policy in a workflow](docs/github-actions.md)
  and approve held calls by comment while the job is still running. This path
  needs agentgw v0.3.0-rc.2 or later from the
  [GitHub releases page](https://github.com/midspan-dev/agentgw/releases);
  brew installs 0.2.0 until 0.3.0 is final.
- Browser: try the demo at [midspan.dev](https://midspan.dev).

```sh
brew install midspan-dev/tap/agentgw
```

Docker: `docker run --rm ghcr.io/midspan-dev/agentgw version`.

## What agentgw does and does not protect against

agentgw governs the MCP tool calls routed through it, by policy, and signs a
ledger entry for each. It does not sandbox the agent. An agent with a shell as
your user (laptop) or on the runner (CI) can bypass it: edit `policy.yaml`,
write the state database, or read `approver.key` and approve itself. Give the
agent only the MCP tools, and keep the keys where the agent cannot read them.
The ledger proves what the gateway saw, not what happened outside it. The
approver signature proves the key holder decided; on GitHub the login is
recorded and linked, not cryptographically bound.

## Developing

Prerequisites: Docker with Compose v2. No local Go: `./scripts/go` runs the
toolchain from `compose.yaml` (`./scripts/go build ./...`,
`./scripts/go test ./...`).
