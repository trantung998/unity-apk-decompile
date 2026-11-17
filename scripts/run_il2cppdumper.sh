#!/usr/bin/env bash
# Run Il2CppDumper non-interactively.
# Usage: bash run_il2cppdumper.sh <libil2cpp.so> <global-metadata.dat> <out-dir>
# Env: IL2CPPDUMPER_DIR = folder containing Il2CppDumper.dll
#      (default: first of ~/tools/Il2CppDumper, ~/.hermes/cache/scratch/il2cppdumper)
# The tool folder is copied to <out-dir>/.bin with RequireAnyKey=false so it never
# blocks on "Press any key", and the user's own config.json stays untouched.
set -euo pipefail
SO=$1; META=$2; OUT=$3
DIR=${IL2CPPDUMPER_DIR:-}
for c in "$DIR" "$HOME/tools/Il2CppDumper" "$HOME/.hermes/cache/scratch/il2cppdumper"; do
  [[ -n "$c" && -f "$c/Il2CppDumper.dll" ]] && { DIR=$c; break; }
done
[[ -f "$DIR/Il2CppDumper.dll" ]] || { echo "Il2CppDumper.dll not found: set IL2CPPDUMPER_DIR (net6/net8 release from github.com/Perfare/Il2CppDumper)" >&2; exit 2; }
mkdir -p "$OUT/.bin"
for f in "$DIR"/*.dll "$DIR"/*.json "$DIR"/*.py; do [[ -f "$f" ]] && cp "$f" "$OUT/.bin/"; done
python3 -I - "$OUT/.bin/config.json" <<'EOF'
import json, sys, pathlib
p = pathlib.Path(sys.argv[1])
c = json.loads(p.read_text()) if p.exists() else {}
c.update(RequireAnyKey=False, GenerateStruct=True, GenerateDummyDll=True)
p.write_text(json.dumps(c, indent=2))
EOF
export DOTNET_ROLL_FORWARD=LatestMajor   # lets a net6/net8 build run on a newer runtime
dotnet "$OUT/.bin/Il2CppDumper.dll" "$SO" "$META" "$OUT" </dev/null 2>&1 | tee "$OUT/il2cppdumper.log" | tail -15
for f in dump.cs script.json il2cpp.h stringliteral.json; do
  [[ -s "$OUT/$f" ]] || { echo "FAILED: $OUT/$f missing - see $OUT/il2cppdumper.log (try Cpp2IL or Il2CppInspectorRedux)" >&2; exit 1; }
done
echo "OK: $(grep -c 'RVA: 0x' "$OUT/dump.cs") methods with RVA in $OUT/dump.cs" >&2
