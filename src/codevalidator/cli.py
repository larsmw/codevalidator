from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

from . import diff_heuristics, llm_review, providers, report
from .models import ScanContext, Severity
from .scanners import ALL_SCANNERS, run_all
from .walker import collect_files


def _changed_files(repo_root: Path, diff_spec: str) -> set[str] | None:
    try:
        result = subprocess.run(
            ["git", "-C", str(repo_root), "diff", "--name-only", diff_spec],
            capture_output=True, text=True, timeout=30, check=True,
        )
    except (subprocess.SubprocessError, OSError) as e:
        print(f"warning: could not compute changed files for --changed-only ({e})", file=sys.stderr)
        return None
    return {line for line in result.stdout.splitlines() if line}


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="codevalidator",
        description="Scan a repository for backdoors, secrets, and other signs of untrustworthy code.",
    )
    p.add_argument("path", nargs="?", default=".", help="Repository path to scan (default: current directory)")
    p.add_argument("--diff", nargs="?", const="HEAD", default=None, metavar="REF",
                    help="Only run the LLM review pass against `git diff REF` (default ref: HEAD, i.e. "
                         "uncommitted changes). Heuristic scanners still run repo-wide unless --changed-only.")
    p.add_argument("--changed-only", action="store_true",
                    help="With --diff, also restrict heuristic scanners to the changed files only.")
    intent_group = p.add_mutually_exclusive_group()
    intent_group.add_argument("--intent", default=None, metavar="TEXT",
                    help="Stated purpose of the change being reviewed (PR description, ticket text, etc.) "
                         "- only used with --diff. The LLM flags parts of the diff that don't serve this "
                         "stated intent (scope creep is a common way to hide a change in a legitimate-"
                         "looking diff).")
    intent_group.add_argument("--intent-file", default=None, metavar="PATH",
                    help="Read --intent text from a file instead of the command line.")
    p.add_argument("--llm", dest="llm", action="store_true", default=True, help="Run the LLM semantic review pass (default).")
    p.add_argument("--no-llm", dest="llm", action="store_false", help="Skip the LLM review pass; heuristics only.")
    p.add_argument("--llm-provider", choices=[*providers.DEFAULT_MODELS, "both"], default=llm_review.DEFAULT_PROVIDER,
                    help=f"Which LLM API to use for the review pass (default: {llm_review.DEFAULT_PROVIDER}). "
                         "anthropic reads ANTHROPIC_API_KEY, mistral reads MISTRAL_API_KEY. 'both' runs the "
                         "same review through both providers (roughly doubles cost/tokens) and cross-checks "
                         "results - findings independently corroborated by both models are marked as such; "
                         "findings from only one model are still shown at full severity, never suppressed.")
    p.add_argument("--llm-model", default=None,
                    help="Model for LLM review (default depends on --llm-provider: "
                         + ", ".join(f"{p}={m}" for p, m in providers.DEFAULT_MODELS.items()) +
                         "). Ignored when --llm-provider both is used - each provider runs its own default model.")
    p.add_argument("--llm-max-files", type=int, default=llm_review.DEFAULT_MAX_FILES,
                    help="Cap on files sent through LLM review in whole-repo mode (default: %(default)s)")
    p.add_argument("--scanners", default=None,
                    help=f"Comma-separated list of heuristic scanners to run (default: all). Available: {', '.join(ALL_SCANNERS)}")
    p.add_argument("--exclude", action="append", default=[], metavar="GLOB",
                    help="Glob pattern to exclude (repeatable), e.g. --exclude 'tests/fixtures/*'")
    p.add_argument("--format", choices=["text", "json", "markdown"], default="text")
    p.add_argument("--output", "-o", default=None, metavar="PATH", help="Write report to a file instead of stdout")
    p.add_argument("--severity-threshold", default="info", choices=[s.name.lower() for s in Severity],
                    help="Omit findings below this severity from the report (default: info, i.e. show everything)")
    p.add_argument("--fail-on", default="high", choices=["never", *[s.name.lower() for s in Severity]],
                    help="Exit with status 1 if any finding at/above this severity is present (default: high)")
    p.add_argument("--no-color", action="store_true", help="Disable ANSI color in text output")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    repo_root = Path(args.path).resolve()
    if not repo_root.is_dir():
        print(f"error: {repo_root} is not a directory", file=sys.stderr)
        return 2

    only_scanners = set(args.scanners.split(",")) if args.scanners else None
    if only_scanners:
        unknown = only_scanners - set(ALL_SCANNERS)
        if unknown:
            print(f"error: unknown scanner(s): {', '.join(sorted(unknown))}", file=sys.stderr)
            return 2

    intent = args.intent
    if args.intent_file:
        intent = Path(args.intent_file).read_text()
    if intent and not args.diff:
        print("warning: --intent/--intent-file only applies with --diff, ignoring", file=sys.stderr)
        intent = None

    files = collect_files(repo_root, extra_excludes=args.exclude)

    if args.diff and args.changed_only:
        changed = _changed_files(repo_root, args.diff)
        if changed is not None:
            files = [f for f in files if f.rel_path in changed]

    ctx = ScanContext(repo_root=repo_root, files=files)
    findings = run_all(ctx, only=only_scanners)

    if args.diff:
        try:
            diff_text = llm_review.get_diff_text(repo_root, args.diff)
            findings.extend(diff_heuristics.check_test_tampering(diff_text))
            findings.extend(diff_heuristics.check_author_anomaly(repo_root, args.diff))
        except RuntimeError as e:
            print(f"warning: {e}", file=sys.stderr)

    usage: list = []
    if args.llm:
        if args.llm_provider == "both":
            if args.llm_model:
                print("warning: --llm-model is ignored with --llm-provider both", file=sys.stderr)
            llm_providers, model_kwargs = ["anthropic", "mistral"], {}
        else:
            llm_providers, model_kwargs = [args.llm_provider], {"model": args.llm_model}
        try:
            if args.diff:
                if len(llm_providers) > 1:
                    llm_findings, usage = llm_review.review_diff_multi(
                        repo_root, args.diff, llm_providers=llm_providers, intent=intent)
                else:
                    llm_findings, one_usage = llm_review.review_diff(
                        repo_root, args.diff, provider=llm_providers[0], intent=intent, **model_kwargs)
                    usage = [one_usage]
            else:
                if len(llm_providers) > 1:
                    llm_findings, usage = llm_review.review_repo_multi(
                        ctx, llm_providers=llm_providers, max_files=args.llm_max_files)
                else:
                    llm_findings, one_usage = llm_review.review_repo(
                        ctx, provider=llm_providers[0], max_files=args.llm_max_files, **model_kwargs)
                    usage = [one_usage]
            findings.extend(llm_findings)
        except llm_review.LLMUnavailable as e:
            print(f"warning: {e}", file=sys.stderr)
        except RuntimeError as e:
            print(f"warning: {e}", file=sys.stderr)

    findings = report.dedupe_and_sort(findings)
    threshold = Severity.parse(args.severity_threshold)
    findings = [f for f in findings if f.severity >= threshold]

    if args.format == "json":
        out = report.render_json(findings, str(repo_root), usage=usage)
    elif args.format == "markdown":
        out = report.render_markdown(findings, str(repo_root), usage=usage)
    else:
        use_color = False if args.no_color else None  # None -> auto-detect tty in render_text
        out = report.render_text(findings, str(repo_root), use_color=use_color, usage=usage)

    if args.output:
        Path(args.output).write_text(out + "\n")
        print(f"report written to {args.output}", file=sys.stderr)
    else:
        print(out)

    if args.fail_on == "never":
        return 0
    fail_threshold = Severity.parse(args.fail_on)
    worst = report.highest_severity(findings)
    if worst is not None and worst >= fail_threshold:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
