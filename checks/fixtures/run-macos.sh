#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Run the macOS fixtures from the repository root. Needs /usr/bin/python3, sandbox-exec,
# and srt on PATH for the srt fixtures (skipped if srt is missing).
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"; root="$(cd "$here/../.." && pwd)"
out="${ASAL_FIXTURE_OUT:-$(mktemp -d)}"; mkdir -p "$out"
py=/usr/bin/python3
rc=0
render() { sed -e "s#@HOME@#$HOME#g" -e "s#@WORKSPACE@#$root#g" "$1" > "$2"; }

run_fixture() {  # name, command...
  local name="$1"; shift
  (cd "$root" && "$@" "$py" checks/asal.py probe --context fixture --json > "$out/$name.json" 2>/dev/null)
  "$py" "$here/compare.py" "$out/$name.json" "$here/expected/$name.json" || rc=1
}

render "$here/macos/strict.sb.in" "$out/strict.sb"
render "$here/macos/weak.sb.in" "$out/weak.sb"
run_fixture macos-sandbox-exec-strict sandbox-exec -f "$out/strict.sb" env -u SSH_AUTH_SOCK
run_fixture macos-sandbox-exec-weak sandbox-exec -f "$out/weak.sb" env
if command -v srt >/dev/null; then
  run_fixture macos-srt-workspace-only srt --settings "$root/examples/srt/srt-workspace-only.json"
  run_fixture macos-srt-no-denyread srt --settings "$here/macos/srt-no-denyread.json"
else
  echo "srt not found: skipping srt fixtures"
fi
exit $rc
