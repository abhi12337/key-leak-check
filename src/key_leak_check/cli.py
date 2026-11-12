"""Command line interface.

  key-leak-check scan [PATH ...]
  key-leak-check rules
"""

from __future__ import annotations

import argparse
import os
import sys
import textwrap

from . import __version__
from .findings import RULES, SEVERITIES, SEVERITY_RANK, Finding
from .report import render_json, render_text, use_color
from .scanner import MAX_BYTES_DEFAULT, ScanResult, scan_path

EXIT_OK, EXIT_FINDINGS, EXIT_ERROR = 0, 1, 2


def _exit_code(findings: list[Finding], fail_on: str) -> int:
    if fail_on == "never":
        return EXIT_OK
    lim = SEVERITY_RANK[fail_on]
    return EXIT_FINDINGS if any(SEVERITY_RANK[f.severity] <= lim for f in findings) else EXIT_OK


def _filter_min(findings: list[Finding], min_sev: str) -> list[Finding]:
    lim = SEVERITY_RANK[min_sev]
    return [f for f in findings if SEVERITY_RANK[f.severity] <= lim]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="key-leak-check",
        description="Find secret API keys that end up in the browser: public env vars, client code, "
                    "AI SDKs in the browser, hard-coded keys, built bundles, source maps and .env files. "
                    "Reads files only: never builds, runs or connects to anything.",
        epilog="A clean report is not a guarantee. See 'What it does not check' in the README.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    s = sub.add_parser("scan", help="scan project folders / files")
    s.add_argument("paths", nargs="*", default=None, help="folders or files to scan (default: .)")
    s.add_argument("--exclude", action="append", default=[], metavar="GLOB",
                   help="glob of paths to skip (repeatable), e.g. --exclude 'docs/*'")
    s.add_argument("--include-tests", action="store_true", help="also scan test / fixture files")
    s.add_argument("--include-build", action=argparse.BooleanOptionalAction, default=True,
                   help="scan build output (dist/, build/, out/, .next/static, ...) when it exists "
                        "(default: on; --no-include-build to skip)")
    s.add_argument("--disable", action="append", default=[], metavar="RULE",
                   help="ignore a rule id (repeatable), e.g. --disable KLC006")
    s.add_argument("--max-file-mb", type=float, default=MAX_BYTES_DEFAULT / 1024 / 1024,
                   help="skip source files larger than this (default: 5; bundles up to 20)")
    s.add_argument("--json", action="store_true", help="print a JSON report instead of text")
    s.add_argument("--fail-on", choices=[*SEVERITIES, "never"], default="high",
                   help="exit 1 if any finding is at or above this severity (default: high)")
    s.add_argument("--min-severity", choices=SEVERITIES, default="info",
                   help="hide findings below this severity (default: info = show all)")
    s.add_argument("--no-color", action="store_true", help="disable ANSI colours")
    s.add_argument("--brief", action="store_true", help="omit the why/fix text")

    sub.add_parser("rules", help="list every rule with why it matters and how to fix it")
    return parser


def cmd_scan(args) -> int:
    paths = args.paths or ["."]
    for p in paths:
        if not os.path.exists(p):
            print(f"error: {p} does not exist", file=sys.stderr)
            return EXIT_ERROR
    unknown = [r for r in args.disable if r.upper() not in RULES]
    if unknown:
        print(f"error: unknown rule id(s): {', '.join(unknown)} (see `key-leak-check rules`)", file=sys.stderr)
        return EXIT_ERROR
    max_bytes = int(args.max_file_mb * 1024 * 1024)
    results: list[ScanResult] = [scan_path(p, excludes=args.exclude, include_tests=args.include_tests,
                                           include_build=args.include_build, max_bytes=max_bytes) for p in paths]
    disabled = {r.upper() for r in args.disable}
    if len(results) > 1:   # make locations unambiguous
        for r, label in zip(results, paths):
            if os.path.isfile(label) or label == ".":
                continue
            for f in r.findings:
                if f.file:
                    f.file = f"{label.rstrip('/')}/{f.file}".replace("\\", "/")
    findings = [f for r in results for f in r.findings if f.rule_id not in disabled]
    exit_code = _exit_code(findings, args.fail_on)
    shown = _filter_min(findings, args.min_severity)
    files = sum(r.files_scanned for r in results)
    env_files = [e for r in results for e in r.env_files]
    source = sum(r.source_files for r in results)
    build = sum(r.build_files for r in results)
    build_dirs = [d for r in results for d in r.build_dirs]
    frameworks = sorted({fw for r in results for fw in r.frameworks})
    if args.json:
        sys.stdout.write(render_json(shown, meta={
            "targets": [r.root for r in results], "files_scanned": files, "frameworks": frameworks,
            "env_files": env_files, "source_files": source, "build_dirs": build_dirs, "build_files": build,
            "exit_code": exit_code,
        }))
    else:
        header = [f"Scanned {', '.join(paths)}",
                  f"{files} file(s): {len(env_files)} env file(s), {source} source file(s), "
                  f"{build} built file(s)" + (f" in {', '.join(d + '/' for d in build_dirs)}" if build_dirs else "")]
        header.append(f"Frameworks: {', '.join(frameworks)}" if frameworks else
                      "Frameworks: none detected (client/server split is guessed from file paths)")
        if not args.include_build:
            header.append("Build output skipped (--no-include-build).")
        sys.stdout.write(render_text(shown, header=header, color=use_color(force=False if args.no_color else None),
                                     verbose_fix=not args.brief, footer=[f"Exit code: {exit_code}"]))
    return exit_code


def cmd_rules(_args) -> int:
    for r in RULES.values():
        print(f"{r.id}  {r.title}")
        print(textwrap.fill(r.why, 92, initial_indent="    ", subsequent_indent="    "))
        print("    Fix:")
        print(textwrap.indent(Finding(r.id, "low", "", extra={"framework": "next", "provider": "openai"}).fix, "      "))
        print()
    print("Fix snippets are shown for Next.js here; each finding in a scan shows the snippet for the")
    print("framework it was found in (Vite/CRA, Expo, SvelteKit, Nuxt, Astro).")
    return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except (ValueError, OSError):
            pass
    args = build_parser().parse_args(argv)
    return {"scan": cmd_scan, "rules": cmd_rules}[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
