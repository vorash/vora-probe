#!/usr/bin/env bash
# Build the lab workload image and load it into the k3s node.
#
# The node has no image builder, the image is not published to a registry, and
# ghcr is not in this loop. So it is built here, saved, and imported into the
# node's containerd under an unpullable tag.
set -euo pipefail

HOST="${LAB_HOST:-mini-vora}"
IMAGE="${LAB_IMAGE:-vora-probe-lab-memorytest:dev}"
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

command -v docker >/dev/null || { echo "docker is required to build the lab image" >&2; exit 1; }

docker build -t "$IMAGE" "$here/memory-test"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
docker save "$IMAGE" -o "$tmp/image.tar"

scp -q "$tmp/image.tar" "$HOST:/tmp/vora-lab-image.tar"
ssh "$HOST" "sudo -n k3s ctr -n k8s.io images import /tmp/vora-lab-image.tar && rm -f /tmp/vora-lab-image.tar"

echo "imported $IMAGE on $HOST"

# The manifests pin imagePullPolicy: IfNotPresent, so the imported copy is what
# runs. A digest-mismatch failure here means the tag moved under a running lab.
