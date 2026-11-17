#!/usr/bin/env python3
"""Export a Unity game's assets with AssetRipper, headless (no browser clicks).

Usage:
  python3 -I assetripper_export.py <game.apk|.xapk|folder> <new-out-dir> [--mode project|primary]

  project (default): Unity project (scenes, prefabs, ScriptableObjects as YAML + .meta GUIDs)
  primary          : primary content only (textures/audio/models/text), faster

Env: ASSETRIPPER = path to AssetRipper.GUI.Free (else searched in common places).
AssetRipper is started on a free localhost port with --headless and driven over its
HTTP API (/LoadFile or /LoadFolder, then /Export/UnityProject or /Export/PrimaryContent).
Pass the whole XAPK or the unpacked folder so base + split APKs load together.
Out dir must be new or empty: AssetRipper overwrites files.
"""
import argparse
import os
import shutil
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

CANDIDATES = [
    "~/Downloads/AssetRipper_mac_arm64/AssetRipper.GUI.Free",
    "~/tools/AssetRipper/AssetRipper.GUI.Free",
    "~/Applications/AssetRipper/AssetRipper.GUI.Free",
]


def find_binary():
    env = os.environ.get("ASSETRIPPER")
    for c in ([env] if env else []) + CANDIDATES:
        p = Path(c).expanduser()
        if p.is_file():
            return p
    w = shutil.which("AssetRipper.GUI.Free")
    return Path(w) if w else None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("source", type=Path)
    ap.add_argument("out", type=Path)
    ap.add_argument("--mode", choices=["project", "primary"], default="project")
    ap.add_argument("--timeout", type=int, default=7200)
    a = ap.parse_args()
    src, out = a.source.expanduser().resolve(), a.out.expanduser().resolve()
    binary = find_binary()
    if not binary:
        print("AssetRipper.GUI.Free not found; set ASSETRIPPER (github.com/AssetRipper/AssetRipper/releases)", file=sys.stderr)
        return 2
    if out.exists() and any(out.iterdir()):
        print(f"{out} is not empty; choose a new directory", file=sys.stderr)
        return 2
    out.mkdir(parents=True, exist_ok=True)

    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    base = f"http://127.0.0.1:{port}"
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))  # bypass system proxy
    log, console = out.parent / f"{out.name}.assetripper.log", out.parent / f"{out.name}.console.log"

    def call(route, fields=None, timeout=a.timeout):
        data = None if fields is None else urllib.parse.urlencode(fields).encode()
        with opener.open(base + route, data=data, timeout=timeout) as r:
            return r.read()

    with console.open("w") as stream:
        proc = subprocess.Popen([str(binary), "--headless", "--port", str(port), "--log-path", str(log)],
                                cwd=binary.parent, stdout=stream, stderr=subprocess.STDOUT)
        try:
            deadline = time.monotonic() + 120
            while True:
                if proc.poll() is not None:
                    raise RuntimeError(f"AssetRipper exited; see {console}")
                try:
                    call("/", timeout=2)
                    break
                except (OSError, urllib.error.URLError):
                    if time.monotonic() > deadline:
                        raise RuntimeError(f"AssetRipper not ready; see {console}")
                    time.sleep(0.5)
            t0 = time.monotonic()
            print(f"loading {src} ...", flush=True)
            call("/LoadFolder" if src.is_dir() else "/LoadFile", {"Path": str(src)})
            route = "/Export/UnityProject" if a.mode == "project" else "/Export/PrimaryContent"
            print(f"exporting ({a.mode}) to {out} ...", flush=True)
            call(route, {"Path": str(out), "CreateSubfolder": "false"})
            text = log.read_text(errors="replace") if log.exists() else ""
            assets = next((p for p in (out / "ExportedProject/Assets", out / "Assets") if p.is_dir()), out)
            files = sum(1 for p in assets.rglob("*") if p.is_file())
            done = "Finished post-export" in text or (a.mode == "primary" and files)
            print(f"{'OK' if done else 'UNCONFIRMED'}: {files} files under {assets} in {time.monotonic()-t0:.0f}s; log {log}")
            return 0 if done and files else 1
        finally:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    proc.kill()


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:  # noqa: BLE001
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)
