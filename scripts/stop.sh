#!/bin/bash
# URSUS の 3 サービスを停止する (start.sh の対称形)。

set -euo pipefail

[[ $EUID -eq 0 ]] || { echo "must run as root (use sudo)" >&2; exit 1; }

# 依存逆順で停止 (ui → detector → sensor)
SERVICES=(ursus-ui ursus-detector ursus-sensor)

echo ">>> stopping URSUS"
for svc in "${SERVICES[@]}"; do
    systemctl stop "$svc" 2>/dev/null || true
done

echo "stopped."
