# Hosted MCP servers

The [quickstart](quickstart) starts a local server and talks to it over stdio
with `agentgw run`. A hosted server is reached over HTTP instead: `agentgw
serve` listens on a local address, and your client connects to the gateway
there. The gateway holds the server's credential, so you don't configure it in
the MCP client. That alone does not keep it from the agent: see
[Before you rely on it](#before-you-rely-on-it).

Needs agentgw 0.4.0 or later. Check with `agentgw version`; upgrade with
`brew upgrade midspan-dev/tap/agentgw`.

This page assumes you have done the quickstart's step 2, so `~/.agentgw`
holds a config, a policy and a ledger key. It connects Linear with your own
browser sign-in; [other ways to authenticate](#other-ways-to-authenticate)
follow. For a complete setup to copy, with GitHub and Linear and a restricted
agent, see
[`examples/hosted-servers`](https://github.com/midspan-dev/agentgw/tree/main/examples/hosted-servers).

## 1. Add the server

In `~/.agentgw/agentgw.yaml`, change the `listen` line `init` wrote and add the
server:

```yaml
listen: 127.0.0.1:8787
upstreams:
  # keep the existing entries
  - name: linear
    url: https://mcp.linear.app/mcp
    path: /linear
    auth:
      kind: authorization_code
```

`url` is the server's MCP endpoint; with `auth` it must be `https` (`http`
only for localhost). `path` is where the gateway serves it, so the client
connects to `http://127.0.0.1:8787/linear`. Tools appear in the ledger and in
policy as `linear.<tool>`.

## 2. Decide what needs approval

The starter policy's `allow-all` rule matches every tool on every server, so
as it stands Linear's writes would run without asking. In
`~/.agentgw/policy.yaml`, narrow that rule to the quickstart's server and add
two more:

```yaml
  - id: allow-all
    effect: allow
    tools: ["everything.*"]   # was "*"
  - id: linear-reads
    effect: allow
    tools: ["linear.list_*", "linear.get_*", "linear.search_*"]
  - id: linear-writes
    effect: require_approval
    tools:
      - "linear.save_*"
      - "linear.create_*"
      - "linear.delete_*"
      - "linear.retire_*"
      - "linear.restore_*"
      - "linear.prepare_*"
      - "linear.update_diff"
      - "linear.merge_diff"
      - "linear.submit_diff_review"
      - "linear.resolve_diff_thread"
      - "linear.share_issue"
      - "linear.unshare_issue"
      - "linear.mark_notification"
    timeout: 10m
```

Linear's write tools are from its tool list on 2026-11-02. Tools that match no
rule are denied. New tools matching an existing prefix inherit that rule's
behavior. `agentgw watch` shows the name of a denied tool, so you can add it to
the right rule.

## 3. Sign in

```sh
agentgw login --config ~/.agentgw/agentgw.yaml linear
```

It prints a URL and opens it in your browser (`--no-browser` only prints
it). Sign in and approve; the browser comes back to the gateway on
`127.0.0.1`, so use a browser on the same machine, within 5 minutes. The
gateway then prints `logged in to linear; tokens in <path>`.

The token file holds a refresh token: anyone with the file can act as you
on that server until you revoke it. It is created readable only by you.
Treat it like a password.

## 4. Start the gateway

```sh
agentgw serve --config ~/.agentgw/agentgw.yaml
```

It prints one line for each server with `auth`, naming the kind and never
the value.

It refreshes the access token before it expires, and several gateways can
share one token file. It starts even if you have not signed in yet: it prints
`upstream linear: not logged in; run agentgw login linear`, and calls to that
server fail with the same instruction until you do. Signing in while it
runs takes effect on the next call, without a restart. You also need to
sign in again when the server refuses the refresh token, or when you change
the server's `url` or `client_id` (a token is only used for the server and
client it was issued for).

## 5. Connect the client

Point the client at the gateway, not at the server. For Claude Code:

```sh
claude mcp add --transport http --scope user linear http://127.0.0.1:8787/linear
```

No credential goes on the client. With `agentgw watch` open in another
terminal, ask Claude Code: "List my Linear teams." `watch` prints the call as
`allow … linear.list_teams … ok`. Approvals and `agentgw verify` work as in the
quickstart.

## Other ways to authenticate

`auth` has three kinds. A secret comes from `secret_env` (an environment
variable) or `secret_file` (a file, relative to the config's directory; one
trailing newline is trimmed), never from the config itself. `header` and
`client_credentials` need exactly one of the two.

**`header`** sends a fixed header on every request: an API key or a personal
access token.

```yaml
  - name: search
    url: https://search.example.com/mcp
    path: /search
    auth:
      kind: header
      header: Authorization      # or X-Api-Key, with no prefix
      prefix: "Bearer "
      secret_env: SEARCH_API_KEY
```

Give the secret to the gateway when you start it:

```sh
SEARCH_API_KEY=… agentgw serve --config ~/.agentgw/agentgw.yaml
```

If a secret is missing (an unset variable, an empty or unreadable file) `serve`
names the variable or file and does not start. It reads secrets once: restart
it to pick up a new one.

**`client_credentials`** gets an access token with the OAuth 2.0 client
credentials grant, for servers that issue tokens to services rather than to
people. The gateway authenticates to `token_url` with HTTP Basic (`client_id`
and the secret), caches the token until shortly before it expires, and sends
`Authorization: Bearer <token>`. `token_url` must be `https` (`http` only for
localhost).

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
server's sign-in settings itself and registers as a client, so the config in
step 1 is all Linear needs. Optional fields: `client_id` if the server gave you
one instead of letting clients register, `scopes`, `resource`, and `token_file`
(where the tokens are kept; default `tokens/<name>.json` next to the gateway's
`state_path`). If the server also gave you a client secret, add `secret_env` or
`secret_file` and `issuer`, the URL of the server you sign in at; the
gateway then uses only that server, so the secret cannot be sent anywhere
else.

For any server with `auth`, the gateway removes the client's own
`Authorization` header and sends its credential instead. If it cannot get a
token, the call fails and nothing reaches the server. Each new server also needs
policy rules like those in step 2. The full schema is
[`contracts/schemas/config.schema.json`](https://github.com/midspan-dev/agentgw/blob/main/contracts/schemas/config.schema.json).

## Before you rely on it

Here Claude Code has its usual shell and file tools and runs as you, like the
gateway. Only its own permission prompts stand between it and your token file,
`approver.key` and `policy.yaml`; a file readable only by you is still readable
by anything you run. This setup shows the gateway working. It does not contain
the agent.

To contain it, start the agent with no tools except the gateway's: see the
quickstart's [Before you rely on it](quickstart#before-you-rely-on-it), and the
restricted start in
[`examples/hosted-servers`](https://github.com/midspan-dev/agentgw/tree/main/examples/hosted-servers).

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
