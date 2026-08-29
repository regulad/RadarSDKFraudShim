#!/usr/bin/env bash
# Full inventory of every release/pre-release: version strings, UUID, symbol kind, offset.
set -uo pipefail
REPO="radarlabs/radar-sdk-ios-fraud-spm"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT; cd "$WORK"

plist_val() {
  python3 - "$1" "$2" <<'PY' 2>/dev/null
import sys,plistlib
try:
    with open(sys.argv[1],'rb') as f: d=plistlib.load(f)
    print(d.get(sys.argv[2],''))
except Exception: print('')
PY
}

tags="$(for p in 1 2; do curl -fsSL "https://api.github.com/repos/$REPO/releases?per_page=100&page=$p"; done | jq -r '.[].tag_name' | sort -uV)"

printf '%-16s %-9s %-6s %-20s %-9s %-8s %s\n' TAG SHORTVER CFVER SYMBOL_KIND OFFSET VMADDR UUID
for tag in $tags; do
  d="$WORK/$tag"; mkdir -p "$d"
  if ! curl -fsSL -o "$d/f.zip" "https://github.com/$REPO/releases/download/$tag/RadarSDKFraud.xcframework.zip" 2>/dev/null; then
    printf '%-16s %s\n' "$tag" "(no xcframework asset)"; continue
  fi
  unzip -qq -o "$d/f.zip" -d "$d" >/dev/null 2>&1
  fwdir="$(find "$d" -ipath '*ios-arm64/RadarSDKFraud.framework' ! -ipath '*simulator*' -type d | head -n1)"
  dsym="$(find "$d" -ipath '*ios-arm64/dSYMs/*RadarSDKFraud.framework.dSYM/Contents/Resources/DWARF/RadarSDKFraud' ! -ipath '*simulator*' | head -n1)"
  if [[ -z "$fwdir" || -z "$dsym" ]]; then printf '%-16s %s\n' "$tag" "(no device arm64 fw/dSYM)"; continue; fi
  bin="$fwdir/RadarSDKFraud"

  short="$(plist_val "$fwdir/Info.plist" CFBundleShortVersionString)"
  cfver="$(plist_val "$fwdir/Info.plist" CFBundleVersion)"
  vmaddr="$(llvm-objdump --macho --private-headers "$bin" 2>/dev/null | awk '/segname __TEXT/{f=1} f&&/vmaddr/{print $2; exit}')"
  uuid="$(llvm-objdump --macho --private-headers "$bin" 2>/dev/null | awk '/LC_UUID/{f=1} f&&/uuid/{print $2; exit}')"

  swift="$(llvm-nm --defined-only "$dsym" 2>/dev/null | grep -iE ' t .*12isJailbroken.*Tf4d_n$' | awk 'NR==1{print $1}')"
  splain="$(llvm-nm --defined-only "$dsym" 2>/dev/null | grep -iE ' t .*12isJailbrokenSbyFZ$' | awk 'NR==1{print $1}')"
  objc="$(llvm-nm --defined-only "$dsym" 2>/dev/null | grep -iE ' t -\[.* isJailbroken\]$' | awk 'NR==1{print $1}')"
  if   [[ -n "$swift"  ]]; then kind="swift Tf4d_n";  off="$swift"
  elif [[ -n "$splain" ]]; then kind="swift SbyFZ";   off="$splain"
  elif [[ -n "$objc"   ]]; then kind="objc -isJail";  off="$objc"
  else kind="NONE(none-found)"; off=""; fi

  offhex="?"; [[ -n "$off" ]] && { offhex="0x$(printf '%s' "$off" | sed 's/^0*//')"; [[ "$offhex" == "0x" ]] && offhex="0x0"; }
  vm="${vmaddr:+$(printf '%s' "$vmaddr" | sed 's/^0x0*/0x/;s/^0x$/0x0/')}"
  printf '%-16s %-9s %-6s %-20s %-9s %-8s %s\n' "$tag" "${short:-?}" "${cfver:-?}" "$kind" "$offhex" "${vm:-?}" "${uuid:-?}"
done
