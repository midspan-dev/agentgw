# Quickstart

One MCP policy, on your laptop first and then in GitHub Actions. Five minutes
here: put agentgw in front of one MCP server, watch every tool call as
it happens, hold one for your approval, and verify the signed ledger. We use
the reference "everything" server because its `echo` tool is harmless.

This walkthrough is a functional demo, not a security boundary: see
[Before you rely on it](#before-you-rely-on-it).

Needs: Claude Code, Node.js (for `npx`), Homebrew.

## 1. Install

```sh
brew install midspan-dev/tap/agentgw
agentgw version
```

No Homebrew: download a binary from the
[GitHub releases page](https://github.com/midspan-dev/agentgw/releases). (The Docker
image, `ghcr.io/midspan-dev/agentgw`, is for running the gateway as a service,
not for this quickstart.)

## 2. Set up

```sh
agentgw init -- npx -y @modelcontextprotocol/server-everything
```

Answer the prompts (Enter takes the default in brackets; name the server
`everything`), or add `--yes --name everything` after `init` to skip them.
`init` starts the server once to list its tools, then writes everything to
`~/.agentgw`:

```
listing tools on "everything" (up to 2 min; a first npx run downloads the server)
created  /Users/you/.agentgw/agentgw.yaml
created  /Users/you/.agentgw/policy.yaml    (… tools found on "everything"; … need approval)
created  /Users/you/.agentgw/ledger.key     public key 3b1a…82fe
         ledger public key (signer in every entry):
         <your public key: 64 hex characters>
created  /Users/you/.agentgw/approver.key

registered with Claude Code: claude mcp add --scope user everything -- /opt/homebrew/bin/agentgw run --config /Users/you/.agentgw/agentgw.yaml --server everything
         available in Claude Code from any directory (scope user)
```

- `policy.yaml` is a starter policy: tools whose names suggest a destructive
  or paid action (delete, refund, send, …) wait for your approval, and
  every other tool is allowed (the playground's example policy denies
  unmatched calls instead). Keep the public key; it verifies the ledger
  anywhere.
- The two key files are secrets. `approver.key` approves calls, so an agent
  that can read it can approve itself. In this walkthrough it can: see
  [Before you rely on it](#before-you-rely-on-it).
- `init` registers the gateway with Claude Code for you, available from any
  directory. If `claude` is not on your PATH, it prints the `claude mcp add`
  command to run yourself.
- If the server cannot be listed (for example, no network for the first `npx`
  download), you see `warning: could not list tools` and get a generic
  template policy. To get rules for the real tools, fix the cause and, while
  `policy.yaml` is still the untouched file `init` wrote, delete it and run the
  same `init` command again; it keeps every existing file and writes only the
  missing one. Once you have edited the policy, edit it instead.

## 3. Watch

In a second terminal:

```sh
agentgw watch
```

It prints a status block (ledger, policy, approver) and then one line per
tool call, as it happens. Leave it open.

## 4. Make a call

Open Claude Code and ask: "Use the echo tool to say hello." Claude Code starts
`agentgw run`, which starts the real server and sits between them. `watch`
prints the call:

```
14:02:11  allow    everything.echo               ok        allow-all           v 9c1d2e3f
```

Time, decision, tool, outcome, the rule that decided it and the policy
version. Every call is also one signed line in `~/.agentgw/ledger.jsonl`.

## 5. Require approval

Add a rule to the `rules:` list in `~/.agentgw/policy.yaml`:

```yaml
  - id: review-echo
    effect: require_approval
    tools: ["everything.echo"]
    timeout: 5m
```

Save. `watch` reports `policy.yaml changed: compiles, version …`. There is
nothing to restart: the gateway applies the new policy on the next tool call.
(Save a typo to see `INVALID`; the gateway keeps the last valid policy until
you fix it.)

## 6. Approve and deny

Ask for the echo again. Claude Code waits, and `watch` shows the held call as
a card: the tool, the rule, the exact arguments and their hash. Type `a` and
Enter. Claude Code gets the result, and `watch` prints `approved … by you` and
the call line with outcome `ok`.

Ask once more and answer `d`. The call never reaches the server, Claude Code
is told it was denied, and `watch` prints an `approval_denied` line. With
several calls waiting, answer by card number: `a 2`, or `d 2 not now` to give
the agent a reason.

## 7. Verify the ledger

```sh
agentgw verify --config ~/.agentgw/agentgw.yaml
```

This checks every signature and the hash chain and prints the counts, for
example `ok: 4 entries, 0 checkpoints`. To check from somewhere else, you need
only the file and the public key `init` printed:

```sh
agentgw verify ledger.jsonl <pubkey-hex>
```

To see it fail, tamper with a copy, not your working ledger:

```sh
cp ~/.agentgw/ledger.jsonl /tmp/ledger.jsonl
```

Edit any byte of `/tmp/ledger.jsonl`, then run
`agentgw verify /tmp/ledger.jsonl <pubkey-hex>`.

## Next

Rules can also deny calls outright (`effect: deny`, which wins over every
other rule) and cap spend with `prices` and `budgets`. `agentgw approvals
list|approve|deny` decides held calls without `watch`. See
[`contracts/policy-yaml.md`](https://github.com/midspan-dev/agentgw/blob/main/contracts/policy-yaml.md) for the
full grammar.

The same policy format runs in GitHub Actions, with a policy written for the
GitHub MCP server and approvals by comment while the job is still running: see
[Run in GitHub Actions](github-actions).

## Before you rely on it

Here Claude Code has its usual shell and file tools and runs as you, on the
same machine as the gateway. It could read `~/.agentgw/approver.key` and
approve its own calls, edit `policy.yaml`, rewrite the ledger with
`ledger.key`, or start the MCP server without the gateway. The gateway only
enforces policy on calls that go through it.

For real enforcement the agent must have no tools except the gateway's: no
shell, no file access, no other MCP servers. The
[GitHub Actions example](github-actions#4-what-this-does-and-does-not-protect-against)
is the tested configuration: Claude Code starts with every built-in tool
removed and only the wrapped server's tools allowed, and
[`COMPAT.md`](https://github.com/midspan-dev/agentgw/blob/main/examples/github-actions/COMPAT.md) records the
evidence for the flags. Its
[laptop run](https://github.com/midspan-dev/agentgw/blob/main/examples/github-actions/local.md) uses the same
flags on your machine.
