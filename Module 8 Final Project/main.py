"""
SecretScanner CLI
- Accepts a file or directory and scans recursively for hardcoded secrets
- Uses regex patterns (see patterns.py)
- Outputs TXT/CSV/JSON report with filename, line number, pattern, and masked match
"""
from __future__ import annotations
import argparse
import json
import logging
from pathlib import Path
from typing import Iterable, List, Dict

from scanner import scan_path
from patterns import PATTERNS

LOG = logging.getLogger("secret_scanner")

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="secret-scanner",
        description="Scan files or directories for hardcoded secrets."
    )
    p.add_argument("--path", "-p", required=True, help="File or directory to scan.")
    p.add_argument("--output", "-o", default=None,
                   help="Optional output file path. If omitted, prints to stdout.")
    p.add_argument("--format", "-f", choices=["txt", "csv", "json"], default="txt",
                   help="Report format (default: txt).")
    p.add_argument("--ext", nargs="*", default=[],
                   help="Only include files with these extensions (e.g. --ext .py .js .ts .env). "
                        "Leave empty to scan all text-like files.")
    p.add_argument("--ignore", nargs="*", default=[".git", ".venv", "node_modules", "__pycache__"],
                   help="Directory or filename globs to ignore.")
    p.add_argument("--max-bytes", type=int, default=2_000_000,
                   help="Skip files larger than this many bytes (default 2MB).")
    p.add_argument("--verbose", "-v", action="store_true", help="Enable debug logging.")
    return p.parse_args()

def write_report(results: List[Dict], fmt: str, outpath: Path | None):
    def as_txt(rows: Iterable[Dict]) -> str:
        if not rows:
            return "No findings.\n"
        lines = []
        for r in rows:
            lines.append(
                f"[!] {r['pattern_name']} | {r['file']}:{r['line']}\n"
                f"    match: {r['masked']}"
            )
        return "\n".join(lines) + "\n"

    def as_csv(rows: Iterable[Dict]) -> str:
        import csv
        from io import StringIO
        buf = StringIO()
        writer = csv.DictWriter(buf, fieldnames=["pattern_name", "file", "line", "masked"])
        writer.writeheader()
        for r in rows:
            writer.writerow({k: r[k] for k in writer.fieldnames})
        return buf.getvalue()

    def as_json(rows: Iterable[Dict]) -> str:
        return json.dumps(rows, indent=2)

    if fmt == "txt":
        text = as_txt(results)
    elif fmt == "csv":
        text = as_csv(results)
    else:
        text = as_json(results)

    if outpath:
        outpath.parent.mkdir(parents=True, exist_ok=True)
        outpath.write_text(text, encoding="utf-8")
        LOG.info("Report written to %s", outpath)
    else:
        print(text, end="")

def main():
    args = parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s: %(message)s"
    )
    path = Path(args.path).resolve()
    if not path.exists():
        LOG.error("Path not found: %s", path)
        raise SystemExit(2)

    LOG.info("Scanning: %s", path)
    results = scan_path(
        path=path,
        patterns=PATTERNS,
        include_exts=set(args.ext or []),
        ignore_globs=set(args.ignore or []),
        max_bytes=args.max_bytes,
    )
    LOG.info("Findings: %d", len(results))
    write_report(results, args.format, Path(args.output) if args.output else None)

if __name__ == "__main__":
    main()
