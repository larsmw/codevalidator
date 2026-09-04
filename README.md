# codevalidator

Scans a repository for signs that its code doesn't do what it claims to — hardcoded
secrets, dynamic-code-execution backdoors, data exfiltration, supply-chain tampering,
CI/git-hook abuse, and (via an LLM pass) subtler logic that regexes can't catch, like
a hardcoded bypass condition or behavior that contradicts a function's own name.

Built for the specific worry that an LLM coding assistant (or a human, or a compromised
dependency) slipped something malicious into a codebase that looks fine on a skim.

## Install

```bash
python3 -m venv .venv && .venv/bin/pip install -e .
```

## Usage

```bash
# Full scan: heuristics + LLM semantic review
codevalidator /path/to/repo

# Heuristics only, no API calls
codevalidator /path/to/repo --no-llm

# Review only uncommitted changes (fast, focused, cheap - good for "did the
# assistant that just wrote this diff sneak anything in")
codevalidator /path/to/repo --diff HEAD

# Review a PR branch against main
codevalidator /path/to/repo --diff main...feature-branch

# JSON for scripting / CI, non-zero exit only on critical findings
codevalidator /path/to/repo --format json --fail-on critical -o report.json
```

Exit code is `1` if any finding at or above `--fail-on` (default: `high`) is present,
so it can gate a pre-commit hook or CI job once you're happy with the noise level.

## How it works

Two independent passes, deliberately overlapping in coverage:

1. **Heuristic scanners** (`src/codevalidator/scanners/`) - fast, free, deterministic
   regex/structural checks: hardcoded credentials, `eval`/`exec`/`pickle.loads` and
   other dynamic-execution sinks (especially `decode(...) -> exec(...)` chains),
   reverse-shell shapes, Unicode "Trojan Source" bidi/zero-width tricks
   (CVE-2021-42574), `npm`/pip install-time scripts, insecure/overridden dependency
   sources, `pull_request_target` privilege-escalation in GitHub Actions, malicious
   git/husky hooks, and unusual file permissions.
2. **LLM semantic review** (`src/codevalidator/llm_review.py`) - sends source (or,
   with `--diff`, just the diff) to Claude with a rubric aimed at what regexes
   structurally cannot see: logic that behaves differently for a hardcoded trigger
   value, an inverted auth check, code whose behavior contradicts its own name or
   comments, unnecessary indirection whose only effect is to hide a change. File
   content is explicitly treated as untrusted data in the prompt, with an instruction
   to ignore and flag anything in it that looks like a prompt-injection attempt.

Both passes emit the same `Finding` shape (severity, category, file:line, evidence,
confidence) and get merged, deduped, and sorted into one report.

## Known limitations

- **Not a guarantee.** A clean report is evidence, not proof. This raises the cost of
  hiding something; it doesn't make hiding something impossible.
- **Regex scanners will flag their own pattern definitions and test fixtures** if you
  point codevalidator at its own source - the patterns for "netcat reverse shell" or
  "credential read near a network call" *contain* the strings they're looking for.
  This is an inherent, well-known property of this technique (the same thing happens
  scanning grep's own source with grep), not a bug. Use `--exclude` for known
  fixture/test paths if it's noisy.
- **LLM review has a file/size cap** (`--llm-max-files`, default 80; ~20K chars/file)
  to bound cost on large repos. `--diff` sidesteps this entirely by only reviewing
  what changed - prefer it for anything beyond a one-time full audit.
- Confidence is reported honestly per finding; treat `low`-confidence findings as
  "worth a human glance," not "confirmed."

## Development

```bash
.venv/bin/pip install -e ".[dev]"
.venv/bin/pytest
```
