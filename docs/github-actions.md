# Run in GitHub Actions

When someone opens an issue in your repository, a workflow starts Claude Code to
triage it. Claude Code reaches GitHub only through agentgw, which applies your
policy to every call: it may read the issue and comment, but closing or editing
the issue waits until someone with write access replies `/approve`, and
rewriting comments is refused. The workflow then uploads a signed record of
every call, allowed or not, that you can verify anywhere.

This example shows how to run agentgw in GitHub Actions. Its policy uses the
same format as the quickstart, with rules for the GitHub MCP server's tools
instead of the echo tool. You'll find the workflow and configuration in
[examples/github-actions](https://github.com/midspan-dev/agentgw/tree/main/examples/github-actions).

Needs: a GitHub repository you own, an Anthropic API key, and agentgw (see the
[quickstart](quickstart)) to make two keys and verify the ledger.

## 1. Set up

Copy the example into your repository (a throwaway public repository is
fine). From your repository's root:

```sh
git clone --depth 1 https://github.com/midspan-dev/agentgw /tmp/agentgw
mkdir -p examples .github/workflows
cp -R /tmp/agentgw/examples/github-actions examples/
cp examples/github-actions/.github/workflows/triage.yml .github/workflows/
```

The workflow reads its files from `examples/github-actions/`, so keep that
path. In `agentgw.yaml`, set `approvals.github.repo` to `your-login/your-repo`
and `agent.owner` to your email or login (it is recorded in the ledger). The workflow pins
the agentgw release it installs (`AGENTGW_VERSION`), which must be 0.3.0
or later for the approvals and outcome comment this page describes.
Then make the keys:

```sh
cd examples/github-actions
agentgw keygen --config agentgw.yaml           # prints the ledger public key
agentgw approvals init --config agentgw.yaml
cat ledger.key approver.key
```

Create the secrets `AGENTGW_LEDGER_KEY` and `AGENTGW_APPROVER_KEY` (the two
files' contents) and `ANTHROPIC_API_KEY`, and the repository variable
`AGENTGW_LEDGER_PUBKEY` (the printed public key). Delete the two key files or
keep them somewhere safe; the example's `.gitignore` keeps them out of the
repository.

Commit and push to the default branch: GitHub runs an `issues` workflow only
from the default branch, so an issue opened before the workflow lands there
starts nothing. Enable Actions, then open an issue, for example:

```
Title: Search returns no results for quoted phrases
Body:  Searching for "release notes" with the quotes returns nothing.
```

Any issue works; the agent's instructions are in `prompt.txt`. Only issues opened by the repository's owner, members and collaborators
start a run (the workflow checks `author_association`): each run spends your
Anthropic key and the issue text is the agent's input, so keep that gate on a
public repository.

The workflow asks for `issues: write` (the agent's comment, the issue edit
once approved, and the gateway's approval comments) and `contents: read`
(checkout). Checking who may approve needs only the "Metadata" permission that
every job token has.

## 2. The run

The policy has three rules: reading and commenting are allowed, any issue edit
or close waits for approval, and rewriting comments and all repository writes are
denied. The agent is told to read the issue, comment, close it, and try once to
edit its own comment.

When it asks to close the issue, the gateway holds the call and comments:

````
**agentgw is holding a tool call for approval**

- Agent: `issue-triage`
- Tool: `github.issue_write`
- Estimated cost: 0 USD
- Rule: `issue-write-needs-approval`
- Expires: 2026-10-27T12:36:14Z
- Ref: 82MCFBZH

Arguments (redacted):

```json
{"issue_number":5,"method":"update","owner":"midspan-dev","repo":"agentgw-gha-demo","state":"closed","state_reason":"not_planned"}
```

Reply with one of:

    /approve 82MCFBZH
    /deny 82MCFBZH [reason]

<!-- agentgw ref=82MCFBZH -->
````

Reply on the issue as someone with write access:

```
/approve <ref>
```

or `/deny <ref> reason`. The job continues, the gateway posts an outcome comment
naming who decided, and the denied comment edit never reaches GitHub. The job
then verifies the ledger and uploads it.

```
ok: 4 entries, 0 checkpoints
```

Approval works while the job is still running; there is no resume after the
runner ends. If nobody answers within the rule's timeout the call expires
and nothing runs.

## 3. Who may approve

The gateway polls the issue's comments (outbound requests only; a runner accepts
no inbound connections). A reply counts only if its author is a user, not a bot
(so neither the job's own token nor another workflow can approve), is not the
gateway's own account, and has a repository role at or above `min_permission`
(default `write`). The gateway checks the role through the GitHub API on every
reply, so a role revoked mid-run takes effect on the next one. Everyone else is
ignored and logged. Each comment is read once; editing it later changes nothing.

Do not give the GitHub MCP server a personal access token owned by an approver.
The agent can post comments through that server, and its `/approve` would carry
your standing. The example uses the job's token, whose comments are from a Bot.

## 4. What this does and does not protect against

The agent has no shell and no file tools: the workflow starts Claude Code with
every built-in tool removed and only the wrapped server's tools allowed. This
matters because on a runner everything shares one machine. An agent with a
shell could read the approver key and approve itself, edit `policy.yaml`, or
rewrite the ledger with the ledger key. The example's [`COMPAT.md`](https://github.com/midspan-dev/agentgw/blob/main/examples/github-actions/COMPAT.md) records the
check that the agent really has only the intended tools.

The approver signature shows that the process holding the approver key approved
this call with these arguments. It does not by itself show that a particular
GitHub user did; the ledger entry links to the comment, which GitHub keeps. Anyone
who can run arbitrary code on the runner during the job could forge it. The
policy, not the token's scopes, is what limits the agent: the token can do more
than the policy allows.

## 5. Verify

The job's "Upload the ledger" step saves the ledger as the `agentgw-ledger`
artifact. Open the run from your repository's Actions tab and download it from
the Artifacts section at the bottom of the run's summary page; it comes as a zip
containing `ledger.jsonl`. With the GitHub CLI, `gh run download <run-id> -n
agentgw-ledger` fetches and unzips it. Then check it with the public key you
saved:

```sh
agentgw verify ledger.jsonl <pubkey-hex>
```

Run the same issue on your laptop with the same `policy.yaml` (see
[`local.md`](https://github.com/midspan-dev/agentgw/blob/main/examples/github-actions/local.md) in the example) and compare the two ledgers: each equivalent call has the same
`policy_version`, `outcome` and `rule_id`.
