# codevalidator

[![test](https://github.com/larsmw/codevalidator/actions/workflows/test.yml/badge.svg)](https://github.com/larsmw/codevalidator/actions/workflows/test.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A diff-focused code review helper for catching things *deliberately or accidentally
hidden* in a change - a backdoor slipped in by an LLM coding assistant, a compromised
contributor, or a supply-chain compromise. Combines fast deterministic checks with an
LLM review pass, and is built to layer on top of (not duplicate) what dedicated tools
like gitleaks, Semgrep, or Socket.dev already do well.

## Why this exists, and what it isn't

Secret scanning, static analysis, and supply-chain scanning are mature, well-solved
problems - gitleaks/trufflehog scan full git history and live-verify leaked keys;
Semgrep/CodeQL do real AST/dataflow analysis across files; Socket.dev/OSSF Scorecard
track dependency *behavior* and reputation. codevalidator doesn't try to out-build any
of those. What it targets instead is the gap none of them cover well: code that was
*deliberately made to look like something it isn't* - a hardcoded bypass condition,
a change that quietly does more than its commit message claims, a test weakened in the
same diff as the logic it would have caught. That's a different question than "does
this match a known-bad pattern," and it's why half of this tool is an LLM asking "does
this diff actually do what it says" rather than more regexes.

Use `--diff` as the default way to run this - reviewing a specific change against its
stated intent is the strongest signal this tool has. Whole-repo scanning still works
(and the heuristic scanners are useful defense-in-depth on their own), but a full-repo
LLM pass is the weakest and most expensive way to use this tool.

## See it in action

Say a diff quietly adds a debug backdoor to a login check, and neuters the test that
would have caught it:

```diff
--- a/src/auth.py
+++ b/src/auth.py
@@ -1,5 +1,5 @@
 def login(username, password):
     user = find_user(username)
-    if not check_password(user, password):
+    if not check_password(user, password) or username == "debug_override":
         return LoginResult(success=False, status_code=401)
     return LoginResult(success=True)
--- a/tests/test_auth.py
+++ b/tests/test_auth.py
@@ -1,5 +1,4 @@
 def test_login_rejects_bad_password():
     user = create_user("alice", "correct-horse")
     result = login("alice", "wrong-password")
-    assert result.success is False
     assert result.status_code == 401
```

`codevalidator . --diff HEAD --no-llm` (heuristics only, no API key needed) catches it:

```
[HIGH] tests/test_auth.py:4  (diff-heuristics/test-weakened, confidence=low)
  A test assertion was removed in this diff. This diff also touches non-test files,
  which is the pattern to worry about most - confirm the weakened test wasn't hiding
  a real behavior change.
  > assert result.success is False

[MEDIUM] src/auth.py  (diff-heuristics/unfamiliar-author-sensitive-path, confidence=low)
  mallory@example.com has never touched this security-sensitive file before in the
  visible git history. This author has no other commits in this repo's visible
  history. Not inherently wrong but worth a second reviewer's eyes.
```

That's the deterministic layer alone - no LLM call, no cost. Add `--llm-provider
anthropic` (or `mistral`, or `both`) and the semantic pass independently flags the
`debug_override` condition itself as a hardcoded auth bypass, usually with higher
confidence than either heuristic on its own.

## Install

```bash
python3 -m venv .venv && .venv/bin/pip install -e .

# to use Mistral instead of (or alongside) Anthropic:
.venv/bin/pip install -e ".[mistral]"
```

Needs credentials for whichever LLM provider(s) you use: `ANTHROPIC_API_KEY` (or
`ant auth login`) for Anthropic, `MISTRAL_API_KEY` for Mistral. Heuristic-only scans
(`--no-llm`) need no credentials at all.

## Usage

```bash
# Review a diff against its stated purpose - the core workflow
codevalidator /path/to/repo --diff HEAD --intent "Refactor the retry logic in the HTTP client"

# Review a PR branch against main
codevalidator /path/to/repo --diff main...feature-branch --intent-file pr-description.txt

# Cross-check the same diff through both Anthropic and Mistral
codevalidator /path/to/repo --diff HEAD --llm-provider both

# Heuristics only, no API calls, no cost
codevalidator /path/to/repo --diff HEAD --no-llm

# Whole-repo scan (heuristics + LLM, capped at --llm-max-files for cost)
codevalidator /path/to/repo

# JSON for scripting / CI, non-zero exit only on critical findings
codevalidator /path/to/repo --diff HEAD --format json --fail-on critical -o report.json
```

Exit code is `1` if any finding at or above `--fail-on` (default: `high`) is present,
so it can gate a pre-commit hook or CI job once you're happy with the noise level.

## How it works

Three layers, all merged into one `Finding` list (severity, category, file:line,
evidence, confidence) and deduped/sorted into a single report:

1. **Heuristic scanners** (`src/codevalidator/scanners/`) - fast, free, deterministic,
   whole-repo. Hardcoded credentials, `eval`/`exec`/`pickle.loads` and other
   dynamic-execution sinks (especially `decode(...) -> exec(...)` chains),
   reverse-shell shapes, Unicode "Trojan Source" bidi/zero-width tricks
   (CVE-2021-42574), `npm`/pip install-time scripts, insecure/overridden dependency
   sources, `pull_request_target` privilege-escalation in GitHub Actions, malicious
   git/husky hooks, and unusual file permissions.

2. **Diff heuristics** (`src/codevalidator/diff_heuristics.py`) - fast, free,
   deterministic, only with `--diff` (they need a before/after to mean anything):
   - **Test tampering**: a test assertion removed or a test skipped in the same diff
     as production code changes - the classic "neuter the test that would catch it"
     pattern. Severity escalates to `HIGH` specifically when non-test files change too.
   - **Author anomaly**: a security-sensitive path (auth, CI config, crypto, payments,
     migrations, ...) touched by an author with no prior git history on that file.
     Approximate by nature (git history is read from the current checked-out state) -
     treat it as "worth a second reviewer," not proof of anything.

3. **LLM semantic review** (`src/codevalidator/llm_review.py`, `providers.py`) - the
   part that reads for intent, not just pattern. Sends source (or, with `--diff`, the
   diff itself) to Claude or Mistral with a rubric aimed at what the above can't see:
   logic that behaves differently for a hardcoded trigger value, an inverted auth
   check, code whose behavior contradicts its own name or comments. With `--intent`,
   it additionally checks whether every part of the diff serves the stated purpose,
   flagging unrelated riders as `scope-creep` - a common way to bundle a malicious
   change into an otherwise-legitimate diff. File content is explicitly treated as
   untrusted data in the prompt, with an instruction to ignore and flag anything in it
   that looks like a prompt-injection attempt.

   `--llm-provider both` runs the review through Anthropic *and* Mistral and
   cross-checks results (`llm_review.cross_check`): findings independently
   corroborated by both models on the same file/nearby line get flagged and
   confidence-boosted. **Findings from only one model are never suppressed or
   downgraded** - the point of cross-checking is that disagreement is itself a signal
   worth a look, not a reason to hide something one model caught and the other missed.
   Roughly doubles LLM cost/tokens. If only one provider has credentials configured,
   it degrades gracefully to that one instead of failing outright.

   Every LLM run reports token usage (`LLM usage: N calls, X input, Y output tokens`)
   in the report - raw counts as returned by the API, deliberately with **no dollar
   estimate**, since hardcoded pricing drifts out of date or varies by account.
   Failed batches (rate limits, API errors) are called out explicitly rather than
   silently producing an incomplete "no findings" report.

## Using it in CI

`action.yml` at the repo root packages this as a reusable GitHub Action, so a
consuming repo doesn't need to install anything itself:

```yaml
name: codevalidator
on: pull_request

jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0  # needed so the diff can reach the PR base commit

      - uses: larsmw/codevalidator@v1
        with:
          intent: ${{ github.event.pull_request.title }}
          llm-provider: anthropic
          fail-on: high
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
```

### GitLab, Gitea, or anything else

`action.yml` is just a thin GitHub Actions wrapper - the CLI itself has no GitHub
dependency (no GitHub API calls, no `GITHUB_*` env vars read anywhere in
`src/codevalidator/`), so it runs the same way on any CI that can `pip install` and
has `git`. There's no maintained wrapper for other platforms; the pattern is always
"install, then compute the diff spec from whatever that CI calls base/head":

```yaml
# .gitlab-ci.yml
codevalidator:
  stage: test
  variables:
    GIT_DEPTH: 0  # full history, so the diff can reach the MR's target branch
  script:
    - pip install "git+https://github.com/larsmw/codevalidator.git@v1"
    - codevalidator . --diff "$CI_MERGE_REQUEST_DIFF_BASE_SHA...$CI_MERGE_REQUEST_DIFF_HEAD_SHA"
        --intent "$CI_MERGE_REQUEST_TITLE" --fail-on high
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
```

Gitea Actions is close enough to GitHub Actions syntax that `action.yml` may work
there with little to no change (own `.gitea/workflows/` directory, same `uses:`/
`run:`/`with:` shape). Bitbucket Pipelines, Jenkins, or a local pre-commit hook: same
`pip install` + `codevalidator . --diff <base>...<head>`, just swap in that system's
own predefined variables for the base/head refs.

With no LLM secret configured, drop `llm: false` in as an input and it still runs
the deterministic layer (test-tampering, author-anomaly, all the heuristic scanners)
for free. On a `pull_request` from a fork, secrets aren't available to the workflow
by default anyway - the action degrades to heuristics-only automatically rather than
failing, per the graceful-degradation behavior described above.

## Known limitations

- **Not a guarantee.** A clean report is evidence, not proof. This raises the cost of
  hiding something; it doesn't make hiding something impossible.
- **Not a replacement for gitleaks/Semgrep/a dependency-vuln scanner.** Those do their
  respective jobs (secret history scanning, AST/dataflow analysis, CVE matching) far
  more thoroughly than the heuristic scanners here, which are intentionally lightweight.
- **Regex scanners will flag their own pattern definitions and test fixtures** if you
  point codevalidator at its own source - the patterns for "netcat reverse shell" or
  "credential read near a network call" *contain* the strings they're looking for.
  Same as grepping grep's own source with grep, not a bug. Use `--exclude` for known
  fixture/test paths if it's noisy.
- **Whole-repo LLM review has a file/size cap** (`--llm-max-files`, default 80; ~20K
  chars/file) to bound cost. `--diff` sidesteps this entirely by only reviewing what
  changed - it's the intended way to use this tool, not just a cost workaround.
- **Author-anomaly is approximate.** It reads git history from whatever's currently
  checked out, which may or may not cleanly exclude the diff's own commits depending
  on branch topology. Treat it as a prior worth a look, not a verdict.
- Confidence is reported honestly per finding; treat `low`-confidence findings as
  "worth a human glance," not "confirmed."

## Development

```bash
.venv/bin/pip install -e ".[dev,mistral]"
.venv/bin/pytest
```
