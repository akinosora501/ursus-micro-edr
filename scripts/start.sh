#!/bin/bash
# URSUS の 3 サービスを起動する。
#
# auto-start (boot 時起動) は別途:
#   sudo systemctl enable ursus-sensor ursus-detector ursus-ui

set -euo pipefail

[[ $EUID -eq 0 ]] || { echo "must run as root (use sudo)" >&2; exit 1; }

SERVICES=(ursus-sensor ursus-detector ursus-ui)

echo ">>> starting URSUS"
for svc in "${SERVICES[@]}"; do
    systemctl start "$svc"
done

echo
echo "status:"
for svc in "${SERVICES[@]}"; do
    state=$(systemctl is-active "$svc" 2>&1 || true)
    case "$state" in
        active)   color="\033[1;32m" ;;
        failed)   color="\033[1;31m" ;;
        *)        color="\033[1;33m" ;;
    esac
    printf "  %-20s ${color}%s\033[0m\n" "$svc" "$state"
done

echo
echo "  ui   :  http://127.0.0.1:8080/"
echo "  logs :  journalctl -u ursus-sensor -u ursus-detector -u ursus-ui -f"
