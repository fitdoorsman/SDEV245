from __future__ import annotations
import fnmatch
import logging
import re
from pathlib import Path
from typing import Dict, Iterable, List, Pattern, Tuple, Set

LOG = logging.getLogger("secret_scanner")

def is_binary(path: Path, sample_size: int = 2048) -> bool:
    try:
        data = path.read_bytes()[:sample_size]
    except Exception:
        return True
    return b"\x00" in data

def should_skip(path: Path, ignore_globs: Set[str], max_bytes: int, include_exts: Set[str]) -> bool:
    name = str(path)
    for g in ignore_globs:
        if fnmatch.fnmatch(name, f"*{g}*"):
            return True
    if path.is_file() and path.stat().st_size > max_bytes:
        return True
    if include_exts:
        return path.suffix not in include_exts
    bin_exts = {".png", ".jpg", ".jpeg", ".gif", ".pdf", ".zip", ".exe", ".dll", ".so", ".dylib", ".mp4", ".mov"}
    return path.suffix in bin_exts

def mask_secret(s: str, keep: int = 6) -> str:
    s = s.strip()
    if len(s) <= keep * 2:
        return "*" * max(4, len(s))
    return s[:keep] + "..." + s[-keep:]

def scan_file(file_path: Path, compiled_patterns: List[Tuple[str, Pattern]]) -> List[Dict]:
    findings: List[Dict] = []
    try:
        if is_binary(file_path):
            return findings
        with file_path.open("r", encoding="utf-8", errors="ignore") as f:
            for lineno, line in enumerate(f, start=1):
                for pname, pregex in compiled_patterns:
                    for m in pregex.finditer(line):
                        text = m.group(0)
                        findings.append({
                            "pattern_name": pname,
                            "file": str(file_path),
                            "line": lineno,
                            "masked": mask_secret(text),
                        })
    except Exception as e:
        LOG.debug("Failed reading %s: %s", file_path, e)
    return findings

def compile_patterns(patterns: Iterable[Tuple[str, str]]) -> List[Tuple[str, Pattern]]:
    compiled = []
    for name, regex in patterns:
        compiled.append((name, re.compile(regex)))
    return compiled

def scan_path(path: Path,
              patterns: Iterable[Tuple[str, str]],
              include_exts: Set[str],
              ignore_globs: Set[str],
              max_bytes: int) -> List[Dict]:
    compiled = compile_patterns(patterns)
    results: List[Dict] = []
    if path.is_file():
        if not should_skip(path, ignore_globs, max_bytes, include_exts):
            results.extend(scan_file(path, compiled))
        return results

    for p in path.rglob("*"):
        if not p.is_file():
            continue
        if should_skip(p, ignore_globs, max_bytes, include_exts):
            continue
        results.extend(scan_file(p, compiled))
    return results
