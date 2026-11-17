#!/usr/bin/env python3
"""Read AssetRipper-exported Unity YAML (.asset/.prefab/.unity) as Python data.

Library use (import from your own script dir, not from the export dir):
    from unity_yaml import load_docs, guid_map, find_assets
    gm = guid_map(assets_dir)                 # guid -> asset path (from .meta)
    docs = load_docs(path)                    # list of {"MonoBehaviour": {...}} etc.

CLI:
    python3 -P unity_yaml.py <Assets-dir> find <regex>     # list ScriptableObject/MonoBehaviour assets whose
                                                           # m_Name or script field names match
    python3 -P unity_yaml.py <Assets-dir> dump <file> [N]  # print first N docs as JSON
    python3 -P unity_yaml.py <Assets-dir> script <Name>    # assets whose m_Script guid is <Name>.cs

Needs PyYAML; falls back to ~/.cache/unity-apk-decompile/venv (setup line printed if missing). Unity tags (!u!114 &123) are stripped; fileID
references stay as {"fileID": .., "guid": .., "type": ..} dicts - resolve guid with guid_map().
"""
import json
import os
import re
import sys
from pathlib import Path

VENV_PY = Path.home() / ".cache/unity-apk-decompile/venv/bin/python"
try:
    import yaml
except ModuleNotFoundError:
    if VENV_PY.exists() and Path(sys.executable) != VENV_PY:
        os.execv(str(VENV_PY), [str(VENV_PY), "-P", *sys.argv])
    sys.exit("PyYAML missing. One-time setup:\n  python3 -m venv ~/.cache/unity-apk-decompile/venv && "
             "~/.cache/unity-apk-decompile/venv/bin/pip install pyyaml")

TAG = re.compile(r"^--- !u!\d+ &-?\d+( stripped)?$", re.M)


def load_docs(path):
    t = Path(path).read_text(encoding="utf-8", errors="replace")
    t = "\n".join(l for l in t.splitlines() if not l.startswith("%"))
    return [d for d in yaml.safe_load_all(TAG.sub("---", t)) if d]


def guid_map(assets_dir):
    out = {}
    for meta in Path(assets_dir).rglob("*.meta"):
        m = re.search(r"^guid: ([0-9a-f]{32})", meta.read_text(errors="replace"), re.M)
        if m:
            out[m.group(1)] = meta.with_suffix("")
    return out


def script_guid(assets_dir, class_name):
    for meta in Path(assets_dir).rglob(f"{class_name}.cs.meta"):
        m = re.search(r"^guid: ([0-9a-f]{32})", meta.read_text(), re.M)
        if m:
            return m.group(1)
    return None


def main():
    if len(sys.argv) < 4:
        print(__doc__)
        return 2
    root, cmd, arg = Path(sys.argv[1]), sys.argv[2], sys.argv[3]
    if cmd == "dump":
        n = int(sys.argv[4]) if len(sys.argv) > 4 else 3
        print(json.dumps(load_docs(arg)[:n], indent=1, default=str)[:20000])
    elif cmd == "script":
        g = script_guid(root, arg)
        if not g:
            print(f"no {arg}.cs.meta under {root}", file=sys.stderr)
            return 1
        for p in root.rglob("*.asset"):
            if g in p.read_text(errors="replace")[:4000]:
                print(p)
    elif cmd == "find":
        rx = re.compile(arg, re.I)
        for p in list(root.rglob("*.asset")) + list(root.rglob("*.prefab")):
            head = p.read_text(errors="replace")[:4000]
            if rx.search(p.name) or rx.search(head):
                print(p)
    return 0


if __name__ == "__main__":
    sys.exit(main())
