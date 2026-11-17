#!/usr/bin/env python3
"""Pick IL2CPP methods from Il2CppDumper's script.json and write Ghidra inputs.

Usage:
  python3 -I select_targets.py <il2cpp-out-dir> <work-dir> PATTERN [PATTERN ...]
      [--exclude REGEX] [--limit N] [--list]

PATTERN is a case-insensitive regex matched against the full method name
("Namespace.Type$$Method"). Typical: 'LevelSolver\\$\\$' or '\\$\\$IsFree$'.

Writes into <work-dir>:
  targets.tsv  rva_hex <TAB> safe_name <TAB> full_name   (input for DecompileIl2cppTargets.java)
  names.tsv    rva_hex <TAB> full_name   for ALL methods  (callee naming)
  labels.tsv   rva_hex <TAB> label       metadata/string slots (global naming)
names.tsv / labels.tsv are rebuilt only when script.json is newer.

script.json "Address" values are RVAs (integers, image base NOT added).
"""
import argparse
import json
import re
import sys
from pathlib import Path


def safe(name: str) -> str:
    s = re.sub(r"[^A-Za-z0-9_.$]+", "_", name).strip("_")
    return s[:180] or "fn"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("dump_dir", type=Path)
    ap.add_argument("work_dir", type=Path)
    ap.add_argument("patterns", nargs="+")
    ap.add_argument("--exclude", default=None, help="regex of names to drop")
    ap.add_argument("--limit", type=int, default=200, help="max targets (default 200)")
    ap.add_argument("--list", action="store_true", help="only print matches, write nothing")
    a = ap.parse_args()

    script = a.dump_dir / "script.json"
    if not script.is_file():
        print(f"missing {script}", file=sys.stderr)
        return 2
    data = json.loads(script.read_text(encoding="utf-8"))
    methods = data.get("ScriptMethod", [])

    def addr(v):
        return int(v, 16) if isinstance(v, str) else int(v)

    rx = [re.compile(p, re.I) for p in a.patterns]
    ex = re.compile(a.exclude, re.I) if a.exclude else None
    hits, seen = [], set()
    for m in methods:
        n = m["Name"]
        if any(r.search(n) for r in rx) and not (ex and ex.search(n)):
            rva = addr(m["Address"])
            if rva and rva not in seen:
                seen.add(rva)
                hits.append((rva, n, m.get("Signature", "")))
    hits.sort(key=lambda h: h[1])
    for rva, n, sig in hits[: a.limit]:
        print(f"0x{rva:08X}  {n}")
    print(f"# {len(hits)} match(es){' (truncated to --limit)' if len(hits) > a.limit else ''}", file=sys.stderr)
    if a.list or not hits:
        return 0 if hits else 1

    a.work_dir.mkdir(parents=True, exist_ok=True)
    used = {}
    with open(a.work_dir / "targets.tsv", "w", encoding="utf-8") as f:
        for rva, n, sig in hits[: a.limit]:
            s = safe(n)
            if s in used:  # generic specializations share a name
                s = f"{s}_{rva:X}"
            used[s] = 1
            f.write(f"{rva:x}\t{s}\t{n}\n")

    names, labels = a.work_dir / "names.tsv", a.work_dir / "labels.tsv"
    stale = lambda p: not p.exists() or p.stat().st_mtime < script.stat().st_mtime
    if stale(names):
        with open(names, "w", encoding="utf-8") as f:
            for m in methods:
                r = addr(m["Address"])
                if r:
                    f.write(f"{r:x}\t{m['Name']}\n")
    if stale(labels):
        with open(labels, "w", encoding="utf-8") as f:
            for m in data.get("ScriptMetadata", []):
                f.write(f"{addr(m['Address']):x}\t{m['Name']}\n")
            for m in data.get("ScriptMetadataMethod", []):
                f.write(f"{addr(m['Address']):x}\t{m['Name']}\n")
            for m in data.get("ScriptString", []):
                v = json.dumps(m.get("Value", ""), ensure_ascii=False)[:80]
                f.write(f"{addr(m['Address']):x}\tStringLiteral {v}\n")
    print(f"wrote {a.work_dir/'targets.tsv'} ({min(len(hits), a.limit)} targets)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
