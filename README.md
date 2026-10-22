# agentgw

Policy-enforcing MCP proxy with a signed, replayable ledger of every agent action.
It sits between your agent and its MCP servers, allows, denies or holds each
tool call by a readable rule, and records every call in a ledger you can verify
offline.

```sh
brew install midspan-dev/tap/agentgw
```

Then follow the [quickstart](docs/quickstart.md) (about five minutes), or try
the browser demo at [midspan.dev](https://midspan.dev).

Docker: `docker run --rm ghcr.io/midspan-dev/agentgw version`.

## Developing

Prerequisites: Docker with Compose v2. No local Go: `./scripts/go` runs the
toolchain from `compose.yaml` (`./scripts/go build ./...`,
`./scripts/go test ./...`).
