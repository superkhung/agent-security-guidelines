#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Run the container fixtures from the repository root on a Linux host with Docker.
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"; root="$(cd "$here/../.." && pwd)"
out="${ASAL_FIXTURE_OUT:-$(mktemp -d)}"; mkdir -p "$out"
compose_dir="$root/examples/devcontainer/.devcontainer"
export WORKSPACE_DIR="$root"
rc=0
probe='python3 /workspace/checks/asal.py probe --workspace /workspace --context fixture --json'

check() { python3 "$here/compare.py" "$out/$1.json" "$here/expected/$1.json" || rc=1; }

docker compose -f "$compose_dir/compose.yaml" up -d --build --quiet-pull >/dev/null 2>&1 || { echo "compose up failed"; exit 1; }
image="$(docker compose -f "$compose_dir/compose.yaml" images agent --format json 2>/dev/null | python3 -c 'import json,sys; d=json.load(sys.stdin); d=d if isinstance(d,list) else [d]; print(d[0]["Repository"]+":"+d[0]["Tag"])' 2>/dev/null)"
image="${image:-agent-sandbox-agent:latest}"

# Wait until Squid accepts connections from the agent container.
for i in $(seq 1 30); do
  docker compose -f "$compose_dir/compose.yaml" exec -T agent python3 -c 'import socket; socket.create_connection(("proxy", 3128), 2)' 2>/dev/null && break
  sleep 1
done
docker compose -f "$compose_dir/compose.yaml" exec -T agent $probe > "$out/devcontainer-strict.json"; check devcontainer-strict

docker run --rm -u 1000:1000 -v "$root:/workspace:ro" -w /workspace "$image" $probe > "$out/container-default.json"; check container-default

fake="$(mktemp -d)"; mkdir -p "$fake/.ssh" "$fake/.config/gh"
echo "fake key, not a secret" > "$fake/.ssh/id_test"; echo "fake: token" > "$fake/.config/gh/hosts.yml"
# A workspace any uid can write to: on CI runners the checkout belongs to the runner user,
# so uid 1000 in the container could not create the symlink probe there.
ws="$(mktemp -d)"; cp "$root/checks/asal.py" "$ws/"
chmod -R a+rwX "$fake" "$ws"
docker run --rm --privileged -u 1000:1000 -e HOME=/home/agent -v "$fake:/home/agent" -v "$ws:/workspace" -w /workspace \
  "$image" python3 /workspace/asal.py probe --workspace /workspace --context fixture --json --no-network > "$out/container-privileged-home.json"
check container-privileged-home

docker run --rm --network host -u 1000:1000 -v "$root:/workspace:ro" -w /workspace "$image" $probe > "$out/container-network-host.json"; check container-network-host

docker compose -f "$compose_dir/compose.yaml" down -v >/dev/null 2>&1
rm -rf "$fake" "$ws"
exit $rc
