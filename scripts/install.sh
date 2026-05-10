#!/bin/bash
# URSUS インストーラ
#
# ローカル clone のリポジトリ内容を /opt/ursus に rsync し、
# venv を構築して systemd ユニットを配置する。
# auto-start はしない。立ち上げは scripts/start.sh で。
#
#   sudo ./scripts/install.sh

set -euo pipefail

INSTALL_DIR=/opt/ursus
SERVICE_USER=ursus
QUARANTINE_DIR=/var/quarantine/ursus
PYTHON=${PYTHON:-python3}

log() { printf "\033[1;36m>>>\033[0m %s\n" "$*"; }
err() { printf "\033[1;31merror:\033[0m %s\n" "$*" >&2; exit 1; }

# ---- 1. preflight ----
[[ $EUID -eq 0 ]]            || err "must run as root (use sudo)"
command -v systemctl >/dev/null || err "systemd is required"
command -v rsync     >/dev/null || err "rsync is required"
command -v useradd   >/dev/null || err "useradd is required"
command -v "$PYTHON" >/dev/null || err "$PYTHON not found in PATH"

"$PYTHON" -c 'import sys; sys.exit(0 if sys.version_info >= (3,11) else 1)' \
    || err "Python 3.11+ required (got $($PYTHON --version 2>&1))"

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
REPO_DIR=$(cd "$SCRIPT_DIR/.." && pwd)

[[ -f "$REPO_DIR/pyproject.toml" ]] || err "pyproject.toml not found in $REPO_DIR"
[[ -d "$REPO_DIR/systemd"        ]] || err "systemd/ not found in $REPO_DIR"
[[ -f "$REPO_DIR/config.yml"     ]] || err "config.yml not found in $REPO_DIR"


echo ""
echo "██╗   ██╗██████╗ ███████╗██╗   ██╗███████╗"
echo "██║   ██║██╔══██╗██╔════╝██║   ██║██╔════╝"
echo "██║   ██║██████╔╝███████╗██║   ██║███████╗"
echo "██║   ██║██╔══██╗╚════██║██║   ██║╚════██║"
echo "╚██████╔╝██║  ██║███████║╚██████╔╝███████║"
echo " ╚═════╝ ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚══════╝"
echo "============================================="
echo " URSUS Micro-EDR for education."
echo "============================================="
echo ""

log "Starting installation..."
echo "    source : $REPO_DIR"
echo "    target : $INSTALL_DIR"
echo "    user   : $SERVICE_USER"
echo

# ---- 2. system user ----
if ! id -u "$SERVICE_USER" >/dev/null 2>&1; then
    log "creating system user '$SERVICE_USER'"
    useradd --system --no-create-home --home "$INSTALL_DIR" \
            --shell /usr/sbin/nologin "$SERVICE_USER"
else
    log "user '$SERVICE_USER' already exists"
fi

# ---- 3. directories ----
log "creating directories"
mkdir -p "$INSTALL_DIR" "$INSTALL_DIR/data" "$QUARANTINE_DIR"

# ---- 4. rsync repo ----
log "syncing source"
rsync -a --delete \
    --exclude='.venv' \
    --exclude='.git' \
    --exclude='__pycache__' \
    --exclude='*.pyc' \
    --exclude='*.egg-info' \
    --exclude='/data' \
    --exclude='/docs' \
    --exclude='issue.md' \
    "$REPO_DIR/" "$INSTALL_DIR/"

# ---- 5. venv ----
if [[ ! -x "$INSTALL_DIR/.venv/bin/python3" ]]; then
    log "creating venv"
    "$PYTHON" -m venv "$INSTALL_DIR/.venv"
fi
log "installing package + deps"
"$INSTALL_DIR/.venv/bin/pip" install --quiet --upgrade pip
"$INSTALL_DIR/.venv/bin/pip" install --quiet -e "$INSTALL_DIR"

# ---- 6. permissions ----
log "setting permissions"
# code: root:ursus, 全ユーザー読み取り可
# ディレクトリ自体を ursus グループに持たせ、g+w にすることで
# UI プロセスが config.yml.tmp を作成して設定更新できるようにする。
chown -R root:"$SERVICE_USER" "$INSTALL_DIR"
chmod -R u=rwX,g=rX,o=rX "$INSTALL_DIR"
chmod g+w "$INSTALL_DIR"

# data/ : root:ursus 770 + setgid
# setgid を立てることで、root (sensor) が作成した DB ファイルも ursus グループになる。
mkdir -p "$INSTALL_DIR/data"
chown -R root:"$SERVICE_USER" "$INSTALL_DIR/data"
chmod 2770 "$INSTALL_DIR/data"
chmod -R g+w "$INSTALL_DIR/data"  # 既存の DB ファイル等がある場合のため

# config.yml : root:ursus 660
chown root:"$SERVICE_USER" "$INSTALL_DIR/config.yml"
chmod 660 "$INSTALL_DIR/config.yml"

# scripts は実行可
chmod +x "$INSTALL_DIR/scripts/"*.sh

# quarantine : detector のみ (root)
chown root:root "$QUARANTINE_DIR"
chmod 700 "$QUARANTINE_DIR"

# ---- 7. systemd units ----
log "installing systemd units"
cp "$INSTALL_DIR/systemd/"*.service /etc/systemd/system/
chmod 644 /etc/systemd/system/ursus-*.service
systemctl daemon-reload

# ---- done ----
echo
log "URSUS installed at $INSTALL_DIR"
cat <<EOF

  start :   sudo $INSTALL_DIR/scripts/start.sh
  stop  :   sudo $INSTALL_DIR/scripts/stop.sh
  logs  :   journalctl -u ursus-sensor -u ursus-detector -u ursus-ui -f
  ui    :   http://127.0.0.1:8080/

  enable on boot:
            sudo systemctl enable ursus-sensor ursus-detector ursus-ui

EOF
