#!/usr/bin/env bash
# Import libil2cpp.so once (no auto-analysis), then decompile only targets.tsv.
# Usage: bash ghidra_decompile.sh <libil2cpp.so> <work-dir> [out-dir]
#   <work-dir> holds targets.tsv / names.tsv / labels.tsv from select_targets.py;
#   the Ghidra project is kept in <work-dir>/ghidra-project and reused next time.
# Env: GHIDRA_HEADLESS_MAXMEM (default 16G), ANALYZE_HEADLESS (auto-detected),
#      SAVE=1 to keep names in the project (default: -readOnly, nothing saved).
set -euo pipefail
SO=$(cd "$(dirname "$1")" && pwd)/$(basename "$1"); WORK=$(cd "$2" && pwd); OUT=${3:-$WORK/native-code}
mkdir -p "$OUT"; OUT=$(cd "$OUT" && pwd)
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
AH=${ANALYZE_HEADLESS:-}
for c in "$AH" /opt/homebrew/opt/ghidra/libexec/support/analyzeHeadless "$(command -v analyzeHeadless || true)" \
         "${GHIDRA_INSTALL_DIR:-/nonexistent}/support/analyzeHeadless"; do
  [[ -n "$c" && -x "$c" ]] && { AH=$c; break; }
done
[[ -x "$AH" ]] || { echo "analyzeHeadless not found; set ANALYZE_HEADLESS" >&2; exit 2; }
export GHIDRA_HEADLESS_MAXMEM=${GHIDRA_HEADLESS_MAXMEM:-16G}   # default 2G hangs/OOMs on 100+ MB libs
[[ -s "$WORK/targets.tsv" ]] || { echo "missing $WORK/targets.tsv (run select_targets.py)" >&2; exit 2; }

# Pick processor from the ELF header (class byte 5, machine at 0x12).
read -r CLS MACH < <(python3 -I -c 'import sys,struct;h=open(sys.argv[1],"rb").read(20);print(h[4],struct.unpack_from("<H",h,18)[0])' "$SO")
case "$CLS/$MACH" in
  1/40)  PROC=ARM:LE:32:v8 ;;           # armeabi-v7a (v8 superset decodes v7 fine)
  2/183) PROC=AARCH64:LE:64:v8A ;;      # arm64-v8a
  1/3)   PROC=x86:LE:32:default ;;
  2/62)  PROC=x86:LE:64:default ;;
  *) echo "unsupported ELF class/machine $CLS/$MACH" >&2; exit 2 ;;
esac
PROJ="$WORK/ghidra-project"; NAME=il2cpp; PROG=$(basename "$SO")
mkdir -p "$PROJ"
COMMON=(-noanalysis -scriptPath "$HERE/ghidra" -postScript DecompileIl2cppTargets.java
        "$OUT" "$WORK/targets.tsv" "$WORK/names.tsv" "$WORK/labels.tsv")
LOG="$WORK/ghidra-decompile.log"
if [[ -d "$PROJ/$NAME.rep" ]]; then
  RO=(-readOnly); [[ "${SAVE:-0}" == 1 ]] && RO=()
  "$AH" "$PROJ" "$NAME" -process "$PROG" ${RO[@]+"${RO[@]}"} "${COMMON[@]}" >"$LOG" 2>&1 || true
else
  echo "first import of $PROG ($PROC) - ~10-60 s with -noanalysis, reused afterwards" >&2
  "$AH" "$PROJ" "$NAME" -import "$SO" -processor "$PROC" -loader ElfLoader -max-cpu 8 "${COMMON[@]}" >"$LOG" 2>&1 || true
fi
grep -E "IMAGE_BASE|^INFO .*DONE |NO_FUNCTION|SCRIPT ERROR|Exception|REPORT: (Import|Save)" "$LOG" | sed 's/^INFO  //' | head -80
echo "log: $LOG  output: $OUT  (_index.tsv column 2 = Ghidra address = image base + RVA)" >&2
grep -q "OK" "$OUT/_index.tsv" 2>/dev/null
