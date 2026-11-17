#!/usr/bin/env python3
"""Unpack an Android Unity game and decide the decompile route.

Usage: python3 -I unity_triage.py <game.apk|.xapk|.apks|.apkm|dir> <out-dir>

Extracts every APK (base + splits) into <out-dir>/unpacked/<apk-name>/, then
writes <out-dir>/triage.json and prints a summary with the recommended route.
Read-only on the input; never executes anything from the package.
"""
import json
import re
import struct
import sys
import zipfile
from pathlib import Path

VER_FILES = ("globalgamemanagers", "data.unity3d", "mainData", "level0", "unity default resources")
PROTECTION_LIBS = {
    "libpairip": "Google Play PairIP (license/integrity; repacked APK may crash at start)",
    "libjiagu": "360 Jiagu packer", "libDexHelper": "SecNeo/Bangcle packer",
    "libsecexe": "Bangcle", "libshell": "generic shell packer", "libtprt": "Tencent ACE/TP",
    "libtersafe": "Tencent TerSafe", "libanogs": "Tencent ACE anti-cheat",
    "libNetHTProtect": "NetEase Yidun", "libmsaoaidsec": "MSA OAID/sec",
    "libapp_guard": "app guard", "libAppGuard": "AppGuard", "libliapp": "LIAPP",
    "libdxbase": "DexProtector", "libprotectt": "Protectt",
}
VER_RX = re.compile(rb"(?<![\d.])(?:20[12]\d|6\d{3}|[45])\.\d{1,2}\.\d{1,3}[abfpx]\d{1,3}")


def elf_info(data: bytes):
    if data[:4] != b"\x7fELF":
        return None
    cls = {1: 32, 2: 64}.get(data[4])
    mach = struct.unpack_from("<H", data, 18)[0]
    return {"bits": cls, "machine": {40: "arm", 183: "aarch64", 3: "x86", 62: "x86_64"}.get(mach, mach)}


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__)
        return 2
    src, out = Path(sys.argv[1]).expanduser(), Path(sys.argv[2]).expanduser()
    unpacked = out / "unpacked"
    unpacked.mkdir(parents=True, exist_ok=True)

    apks = []
    if src.is_dir():
        apks = sorted(src.rglob("*.apk"))
    elif zipfile.is_zipfile(src):
        with zipfile.ZipFile(src) as z:
            names = z.namelist()
            if "AndroidManifest.xml" in names:
                apks = [src]
            else:  # xapk / apks / apkm: container of apks
                for n in names:
                    if n.endswith(".apk"):
                        dst = out / "apks" / Path(n).name
                        dst.parent.mkdir(parents=True, exist_ok=True)
                        if not dst.exists():
                            dst.write_bytes(z.read(n))
                        apks.append(dst)
                for n in names:  # OBB carried inside xapk
                    if n.endswith(".obb"):
                        dst = out / "obb" / Path(n).name
                        dst.parent.mkdir(parents=True, exist_ok=True)
                        if not dst.exists():
                            dst.write_bytes(z.read(n))
    if not apks:
        print("no APK found in input", file=sys.stderr)
        return 2

    r = {"input": str(src), "apks": [], "abis": {}, "libil2cpp": [], "metadata": None,
         "managed_dlls": [], "unity_version": None, "protection": [], "data_files": {}, "notes": []}
    ver_seen = {}
    for apk in apks:
        dest = unpacked / apk.stem
        with zipfile.ZipFile(apk) as z:
            entries = z.namelist()
            if not dest.exists():
                for n in entries:  # zip-slip guard
                    if n.startswith("/") or ".." in Path(n).parts:
                        raise SystemExit(f"unsafe path in {apk}: {n}")
                z.extractall(dest)
        r["apks"].append({"apk": str(apk), "dir": str(dest), "entries": len(entries)})
        for n in entries:
            p = dest / n
            if n.startswith("lib/") and n.endswith(".so"):
                abi, lib = n.split("/")[1], Path(n).name
                r["abis"].setdefault(abi, []).append(lib)
                for k, why in PROTECTION_LIBS.items():
                    if lib.startswith(k):
                        r["protection"].append(f"{lib} ({abi}): {why}")
                if lib == "libil2cpp.so":
                    with open(p, "rb") as f:
                        info = elf_info(f.read(64))
                    r["libil2cpp"].append({"abi": abi, "path": str(p), "size": p.stat().st_size, **(info or {})})
            elif n.endswith("global-metadata.dat"):
                head = p.read_bytes()[:8]
                magic, ver = struct.unpack("<II", head) if len(head) == 8 else (0, 0)
                r["metadata"] = {"path": str(p), "size": p.stat().st_size, "magic": hex(magic),
                                 "version": ver if magic == 0xFAB11BAF else None,
                                 "encrypted_or_obfuscated": magic != 0xFAB11BAF}
            elif "/Managed/" in n and n.endswith(".dll"):
                r["managed_dlls"].append(str(p))
            elif n.startswith("assets/"):
                kind = ("addressables" if n.startswith("assets/aa/") else
                        "player_data" if n.startswith("assets/bin/Data/") else "streaming_assets_or_sdk")
                d = r["data_files"].setdefault(kind, {"files": 0, "bytes": 0})
                d["files"] += 1
                d["bytes"] += p.stat().st_size
            if Path(n).name in VER_FILES and Path(n).name not in ver_seen:
                with open(p, "rb") as f:
                    m = VER_RX.search(f.read(4096))
                if m:
                    ver_seen[Path(n).name] = m.group(0).decode()
    for name in VER_FILES:  # player data header wins over engine resources
        if name in ver_seen:
            r["unity_version"] = f"{ver_seen[name]} (from {name})"
            break
    if r["unity_version"] is None:
        from collections import Counter
        for apk in r["apks"]:
            for p in Path(apk["dir"]).glob("lib/*/libunity.so"):
                c = Counter(VER_RX.findall(p.read_bytes()))
                if c:
                    r["unity_version"] = c.most_common(1)[0][0].decode() + " (guess from libunity.so)"
                    break

    # Route decision
    asm_csharp = [d for d in r["managed_dlls"] if d.endswith("Assembly-CSharp.dll")]
    if r["libil2cpp"]:
        best = sorted(r["libil2cpp"], key=lambda x: (x.get("bits") != 64, x["abi"]))[0]
        r["backend"] = "IL2CPP"
        r["chosen_lib"] = best
        if r["metadata"] is None:
            r["route"] = "metadata missing: look in assets/, OBB, asset bundles, or dump from memory at runtime"
        elif r["metadata"]["encrypted_or_obfuscated"]:
            r["route"] = "metadata encrypted: find decryption (Frida dump after load) before any dumper"
        elif best.get("bits") == 64:
            r["route"] = "IL2CPP arm64: REA inspect-il2cpp-metadata --binary (names+addresses) or Il2CppDumper -> targeted Ghidra"
        else:
            r["route"] = "IL2CPP armv7 only: Il2CppDumper -> targeted Ghidra (REA cannot link 32-bit binaries); try to obtain an arm64 split of the SAME version"
    elif asm_csharp:
        r["backend"] = "Mono"
        r["route"] = "Mono: Assembly-CSharp.dll is real IL -> ilspycmd/dnSpy gives near-source C#; no Ghidra needed"
    else:
        r["backend"] = "unknown"
        r["route"] = "no libil2cpp.so and no Assembly-CSharp.dll: not Unity, or code hidden by a packer (see protection)"
    if not r["metadata"] and r["libil2cpp"]:
        r["notes"].append("global-metadata.dat not at assets/bin/Data/Managed/Metadata/")
    if any(k.startswith("libpairip") for libs in r["abis"].values() for k in libs):
        r["notes"].append("PairIP present: static analysis is fine; repacked/resigned APK is expected to fail at launch")

    (out / "triage.json").write_text(json.dumps(r, indent=2))
    env = [f"W={out}"]
    if r.get("chosen_lib"):
        env.append(f"SO='{r['chosen_lib']['path']}'")
    if r["metadata"]:
        env.append(f"META='{r['metadata']['path']}'")
    (out / "paths.env").write_text("\n".join(env) + "\n")
    print(f"backend      : {r['backend']}")
    print(f"unity        : {r['unity_version']}")
    print(f"abis         : {', '.join(f'{a}({len(l)})' for a, l in r['abis'].items())}")
    if r.get("chosen_lib"):
        c = r["chosen_lib"]
        print(f"libil2cpp    : {c['abi']} {c.get('bits')}-bit {c['size']:,} B  {c['path']}")
    if r["metadata"]:
        m = r["metadata"]
        print(f"metadata     : magic {m['magic']} version {m['version']} {m['size']:,} B  {m['path']}")
    print(f"data         : {r['data_files']}")
    for p in r["protection"]:
        print(f"protection   : {p}")
    for n in r["notes"]:
        print(f"note         : {n}")
    print(f"ROUTE        : {r['route']}")
    print(f"triage.json  : {out / 'triage.json'}")
    print(f"next         : source {out / 'paths.env'}   # sets W, SO, META")
    return 0


if __name__ == "__main__":
    sys.exit(main())
