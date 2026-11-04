# Hosted MCP servers

The [quickstart](quickstart) starts a local server and talks to it over stdio
with `agentgw run`. A hosted server is reached over HTTP instead: `agentgw
serve` listens on a local address, and your client connects to the gateway
there. The gateway keeps the server's credential, so the agent never sees it.

This page assumes you have done the quickstart's step 2, so `~/.agentgw`
holds a config, a policy and a ledger key. For a complete setup to copy,
with GitHub and Linear, see
[`examples/hosted-servers`](https://github.com/midspan-dev/agentgw/tree/main/examples/hosted-servers).

## 1. Add the server

Add a `listen` address and the server to `~/.agentgw/agentgw.yaml`:

```yaml
listen: 127.0.0.1:8787
upstreams:
  # keep the existing entries
  - name: search
    url: https://search.example.com/mcp
    path: /search
    auth:
      kind: header
      header: Authorization
      prefix: "Bearer "
      secret_env: SEARCH_API_KEY
```

`url` is the server's MCP endpoint; with `auth` it must be `https` (`http`
only for localhost), and so must `token_url` below. `path` is where the gateway serves it, so
the client connects to `http://127.0.0.1:8787/search`. Tools appear in the
ledger and in policy as `search.<tool>`.

## 2. Give the gateway the credential

`auth` has three kinds. A secret comes from `secret_env` (an environment
variable) or `secret_file` (a file, relative to the config's directory; one
trailing newline is trimmed), never from the config itself. `header` and
`client_credentials` need exactly one of the two.

**`header`** sends a fixed header on every request: an API key or a personal
access token.

```yaml
    auth:
      kind: header
      header: X-Api-Key          # or Authorization, with prefix: "Bearer "
      secret_file: search.key
```

**`client_credentials`** gets an access token with the OAuth 2.0 client
credentials grant, for servers that issue tokens to services rather than to
people. The gateway authenticates to `token_url` with HTTP Basic (`client_id`
and the secret), caches the token until shortly before it expires, and sends
`Authorization: Bearer <token>`.

```yaml
    auth:
      kind: client_credentials
      token_url: https://auth.example.com/oauth/token
      client_id: agentgw
      secret_env: CRM_CLIENT_SECRET
      scopes: ["mcp:tools"]                    # optional
      resource: https://crm.example.com/mcp    # optional (RFC 8707)
```

**`authorization_code`** is for servers where you sign in as yourself in the
browser, which is how most hosted MCP servers work. The gateway finds the
server's sign-in settings itself and registers as a client, so the smallest
config is:

```yaml
    auth:
      kind: authorization_code
```

Optional fields: `client_id` if the server gave you one instead of letting
clients register, `scopes`, `resource`, and `token_file` (where the tokens
are kept; default `tokens/<name>.json` next to the gateway's `state_path`).
If the server also gave you a client secret, add `secret_env` or
`secret_file` and `issuer`, the URL of the server you sign in at; the
gateway then uses only that server, so the secret cannot be sent anywhere
else.

For a server with `auth`, the gateway removes the client's own
`Authorization` header and sends its credential instead. If it cannot get a
token, the call fails and nothing reaches the server. The full schema is
[`contracts/schemas/config.schema.json`](https://github.com/midspan-dev/agentgw/blob/main/contracts/schemas/config.schema.json).

## 3. Sign in (`authorization_code` only)

For an upstream named `docs`:

```sh
agentgw login --config ~/.agentgw/agentgw.yaml docs
```

It prints a URL and opens it in your browser (`--no-browser` only prints
it). Sign in and approve; the browser comes back to the gateway on
`127.0.0.1`, so use a browser on the same machine, within 5 minutes. The
gateway then prints `logged in to docs; tokens in <path>`.

The token file holds a refresh token: anyone with the file can act as you
on that server until you revoke it. It is created readable only by you.
Treat it like a password.

## 4. Start the gateway

```sh
SEARCH_API_KEY=… agentgw serve --config ~/.agentgw/agentgw.yaml
```

It prints one line for each server with `auth`, naming the kind and never
the value. If a secret is missing (an unset variable, an empty or unreadable
file) it names the variable or file and does not start. It reads secrets
once: restart it to pick up a new one.

For `authorization_code` it refreshes the access token before it expires,
and several gateways can share one token file. It starts even if you have
not signed in yet: it prints `upstream docs: not logged in; run agentgw
login docs`, and calls to that server fail with the same instruction until
you do. Signing in while it
runs takes effect on the next call, without a restart. You also need to
sign in again when the server refuses the refresh token, or when you change
the server's `url` or `client_id` (a token is only used for the server and
client it was issued for).

## 5. Connect the client

Point the client at the gateway, not at the server. For Claude Code:

```sh
claude mcp add --transport http --scope user search http://127.0.0.1:8787/search
```

No credential goes on the client. `agentgw watch`, approvals and `agentgw
verify` work as in the quickstart.

## On a server with no browser

Sign in on a machine that has one, then copy the token file to the
server, at the path its config uses for that upstream (keep it readable
only by the gateway's user). The
gateway there refreshes it from then on.

Keep one copy in use. Most servers replace the refresh token each time it
is used, so two machines refreshing their own copies lock each other out,
and one of them needs a new sign-in. Some servers also refuse a token used
from a different machine than the one that signed in.

## Limits

- Signing in needs a browser on the gateway's machine; there is no
  device-code sign-in.
- `agentgw run` does not reach hosted servers: use `serve` as above.
- One credential per server, shared by every agent that uses the gateway.
- The gateway does not authenticate its own clients: anything that can reach
  `listen` calls the server with your credential. Keep it on `127.0.0.1`
  unless something else in front of it controls access.
- Browser-based MCP clients are refused unless served from the gateway's own
  address: a request with any other `Origin` gets a 403, and so does one to a
  `127.0.0.1` listener with a non-loopback `Host`. This stops web pages from
  using your credential.
