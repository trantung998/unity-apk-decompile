#!/usr/bin/env python3
"""Print a class from Il2CppDumper's dump.cs: base class, fields with offsets, methods with RVA.

Usage:
  python3 -I dump_class.py <dump.cs> <ClassName> [--methods REGEX] [--bases]
    --bases   also print each base class (inherited fields live at lower offsets)
  python3 -I dump_class.py <dump.cs> --offset <ClassName> 0x1c   # which field is at 0x1c (walks bases)

Use it to turn `*(param_1 + 0x1c)` into a field name: param_1 is `this` of the method's class.
"""
import re
import sys
from pathlib import Path

CLS = re.compile(r"^(?:\[.*\]\s*)?(?:(?:public|private|internal|protected|sealed|abstract|static|readonly|ref|unsafe)\s+)*"
                 r"(?:class|struct|enum|interface)\s+([^\s:<]+(?:<[^>]*>)?)\s*(?::\s*([^{/]+))?")


def find(lines, name):
    out = []
    for i, l in enumerate(lines):
        m = CLS.match(l)
        if m and (m.group(1) == name or m.group(1).split("<")[0] == name):
            j, depth, started = i, 0, False
            while j < len(lines):
                depth += lines[j].count("{") - lines[j].count("}")
                started |= "{" in lines[j]
                if started and depth <= 0:
                    break
                j += 1
            ns = lines[i - 1] if i and lines[i - 1].startswith("// Namespace") else ""
            out.append((ns, m.group(1), (m.group(2) or "").strip(), lines[i:j + 1]))
    return out


def fields(block):
    res = []
    for l in block:
        m = re.search(r"^\s*(.*?);\s*//\s*(0x[0-9A-Fa-f]+)\s*$", l)
        if m and "(" not in m.group(1):
            res.append((int(m.group(2), 16), m.group(1).strip()))
    return res


def base_name(b):
    b = b.split(",")[0].strip()
    return b.split("<")[0] if b else ""


def main():
    a = sys.argv[1:]
    if len(a) < 2:
        print(__doc__)
        return 2
    lines = Path(a[0]).read_text(encoding="utf-8", errors="replace").splitlines()
    if a[1] == "--offset":
        name, off = a[2], int(a[3], 16)
        while name:
            hits = find(lines, name)
            if not hits:
                print(f"{name}: not found")
                return 1
            _, n, b, block = hits[0]
            for o, decl in fields(block):
                if o == off and "static" not in decl and "const" not in decl:
                    print(f"{n}+{hex(off)}: {decl}")
                    return 0
            name = base_name(b)
        print("no field at that offset (check the base chain / generic base)")
        return 1
    name = a[1]
    rx = re.compile(a[a.index("--methods") + 1], re.I) if "--methods" in a else None
    todo, seen = [name], set()
    while todo:
        n = todo.pop(0)
        if n in seen or n in ("", "object", "MonoBehaviour", "Object", "Component", "ScriptableObject"):
            continue
        seen.add(n)
        for ns, cname, b, block in find(lines, n):
            print(f"{ns}\n{block[0].strip()}")
            for o, decl in fields(block):
                print(f"   {hex(o):>7}  {decl}")
            for k, l in enumerate(block):
                m = re.search(r"RVA: (0x[0-9A-F]+)", l)
                if m and k + 1 < len(block):
                    sig = block[k + 1].strip()
                    if not rx or rx.search(sig):
                        print(f"   {m.group(1):>11}  {sig}")
            print()
            if "--bases" in a and b:
                todo.append(base_name(b))
    if not seen - {""}:
        print(f"{name}: not found", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
