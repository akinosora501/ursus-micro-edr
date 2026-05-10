#!/bin/bash
# URSUS アンインストーラ。
#
# 既定では data / config.yml / rules / quarantine を保持してコードのみ削除する。
# --purge を付けると上記もすべて削除し、ursus ユーザーも消す。
#
#   sudo /opt/ursus/scripts/uninstall.sh
#   sudo /opt/ursus/scripts/uninstall.sh --purge

set -euo pipefail

INSTALL_DIR=/opt/ursus
SERVICE_USER=ursus
QUARANTINE_DIR=/var/quarantine/ursus

PURGE=false
for arg in "$@"; do
    case "$arg" in
        --purge) PURGE=true ;;
        -h|--help)
            cat <<EOF
Usage: uninstall.sh [--purge]

Removes URSUS code and systemd units.
By default, $INSTALL_DIR/data, config.yml, rules/, and $QUARANTINE_DIR
are preserved. Use --purge to remove them as well (and the 'ursus' user).
EOF
            exit 0 ;;
        *) echo "unknown arg: $arg" >&2; exit 1 ;;
    esac
done

[[ $EUID -eq 0 ]] || { echo "must run as root (use sudo)" >&2; exit 1; }

log() { printf "\033[1;36m>>>\033[0m %s\n" "$*"; }

log "stopping and disabling services"
for svc in ursus-sensor ursus-detector ursus-ui; do
    systemctl stop "$svc" 2>/dev/null || true
    systemctl disable "$svc" 2>/dev/null || true
done

log "removing systemd units"
rm -f /etc/systemd/system/ursus-sensor.service \
      /etc/systemd/system/ursus-detector.service \
      /etc/systemd/system/ursus-ui.service
systemctl daemon-reload

if [[ $PURGE == true ]]; then
    log "purging $INSTALL_DIR and $QUARANTINE_DIR"
    rm -rf "$INSTALL_DIR" "$QUARANTINE_DIR"
    if id -u "$SERVICE_USER" >/dev/null 2>&1; then
        log "removing user '$SERVICE_USER'"
        userdel "$SERVICE_USER" 2>/dev/null || true
    fi
    echo
    echo "URSUS fully purged."
else
    log "removing code (preserving data, config, rules, quarantine)"
    # 残すもの: data/, config.yml, rules/, $QUARANTINE_DIR
    rm -rf "$INSTALL_DIR/.venv" \
           "$INSTALL_DIR/src" \
           "$INSTALL_DIR/systemd" \
           "$INSTALL_DIR/scripts"
    rm -f  "$INSTALL_DIR/pyproject.toml" \
           "$INSTALL_DIR/DESIGN.md" \
           "$INSTALL_DIR/README.md" 2>/dev/null || true
    echo
    cat <<EOF
URSUS uninstalled. The following are preserved:
  $INSTALL_DIR/data/
  $INSTALL_DIR/config.yml
  $INSTALL_DIR/rules/
  $QUARANTINE_DIR/

Run with --purge to remove these as well.
EOF
fi
