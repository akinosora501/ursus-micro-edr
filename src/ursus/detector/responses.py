"""アラート発火時のレスポンス処理。

action ごとに ACTIONS に登録されたハンドラを呼ぶ。
dry_run モードでは実行はせず response_log に記録だけ残す。

安全ガード:
- kill_process: PID <= 1 (init) と detector 自身の PID を拒否。
- quarantine_file: 主要なシステムパスを拒否。/etc/passwd 等を quarantine
  するとシステムが起動不能になるため。
- block_network: 学習環境での誤動作リスク (ループバック断による操作不能化等)
  が大きいため、現在は **恒久的に無効化** されている。ルール側で
  response: [block_network] を指定しても iptables は呼ばれない。
  再有効化が必要なら git 履歴から実装を戻すこと。
"""
import os
import shutil
import signal as signal_mod
import time
from pathlib import Path

from ursus.common.logging import get_logger

QUARANTINE_DIR = Path("/var/quarantine/ursus")

# quarantine_file が触れてはならない重要パス。realpath で正規化したあと
# このプレフィックス（または完全一致）に該当したら拒否する。
_PROTECTED_PATH_PREFIXES = (
    "/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow", "/etc/sudoers",
    "/etc/hosts", "/etc/resolv.conf", "/etc/fstab",
    "/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/",
    "/lib/", "/lib64/", "/usr/lib/", "/usr/lib64/",
    "/boot/", "/proc/", "/sys/", "/dev/", "/run/",
)


class ResponseHandler:
    def __init__(self, dry_run, allowed_actions):
        self.dry_run = dry_run
        self.allowed_actions = set(allowed_actions)
        self.log = get_logger("detector.response")

    def dispatch(self, conn, rule, alert_id, event):
        for action in rule.response:
            if action not in self.allowed_actions:
                self._record(conn, alert_id, action, None, success=False,
                             detail="not in allowed_actions")
                continue
            handler = ACTIONS.get(action)
            if handler is None:
                self._record(conn, alert_id, action, None, success=False,
                             detail="unknown action")
                continue
            try:
                handler(self, conn, alert_id, event)
            except Exception as e:
                self._record(conn, alert_id, action, None, success=False,
                             detail=f"error: {e}")

    def _record(self, conn, alert_id, action, target, success, detail):
        conn.execute(
            "INSERT INTO response_log "
            "(timestamp, alert_id, action, target, dry_run, success, detail) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (time.time(), alert_id, action, target,
             int(self.dry_run), int(success), detail),
        )
        self.log.info(
            "response_executed",
            alert_id=alert_id,
            action=action,
            target=target,
            dry_run=self.dry_run,
            success=success,
            detail=detail,
        )


# --- safety helpers --------------------------------------------------------

def _is_safe_to_quarantine(path):
    """quarantine しても OS 破壊につながらないパスか。"""
    if not path:
        return False
    try:
        real = os.path.realpath(path)
    except OSError:
        return False
    for prefix in _PROTECTED_PATH_PREFIXES:
        # 完全一致（/etc/passwd 等）または末尾スラッシュ付きディレクトリ配下
        if prefix.endswith("/"):
            if real.startswith(prefix):
                return False
        else:
            if real == prefix or real.startswith(prefix + "/"):
                return False
    return True


def _is_safe_to_kill_pid(pid):
    """kill しても致命的にならない PID か。"""
    if pid is None:
        return False
    try:
        pid_int = int(pid)
    except (TypeError, ValueError):
        return False
    if pid_int <= 1:            # init / kernel
        return False
    if pid_int == os.getpid():  # detector 自身
        return False
    if pid_int == os.getppid(): # detector の親 (systemd など) も保険で除外
        return False
    return True


# --- actions ---------------------------------------------------------------

def _action_alert(handler, conn, alert_id, event):
    # 単に通知ログを残す。実害ゼロ。
    handler._record(conn, alert_id, "alert", target=None, success=True,
                    detail=f"event_id={event['id']}")


def _action_kill_process(handler, conn, alert_id, event):
    pid = event["pid"]
    if not _is_safe_to_kill_pid(pid):
        handler._record(conn, alert_id, "kill_process", str(pid), False,
                        f"refused: protected pid ({pid})")
        return
    if handler.dry_run:
        handler._record(conn, alert_id, "kill_process", str(pid), True, "dry_run")
        return
    try:
        os.kill(pid, signal_mod.SIGTERM)
        handler._record(conn, alert_id, "kill_process", str(pid), True, "SIGTERM")
    except ProcessLookupError:
        handler._record(conn, alert_id, "kill_process", str(pid), False, "no such process")
    except PermissionError as e:
        handler._record(conn, alert_id, "kill_process", str(pid), False, str(e))


def _action_quarantine_file(handler, conn, alert_id, event):
    path = event["file_path"]
    if not path:
        handler._record(conn, alert_id, "quarantine_file", None, False, "no file_path")
        return
    if not _is_safe_to_quarantine(path):
        handler._record(conn, alert_id, "quarantine_file", path, False,
                        "refused: protected system path")
        return
    if handler.dry_run:
        handler._record(conn, alert_id, "quarantine_file", path, True, "dry_run")
        return
    try:
        QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
        os.chmod(path, 0o000)
        dest = QUARANTINE_DIR / Path(path).name
        shutil.move(path, dest)
        handler._record(conn, alert_id, "quarantine_file", path, True,
                        f"moved to {dest}")
    except Exception as e:
        handler._record(conn, alert_id, "quarantine_file", path, False, str(e))


def _action_block_network(handler, conn, alert_id, event):
    """ネットワーク遮断：無効化"""
    ip = event["remote_addr"]
    handler._record(
        conn, alert_id, "block_network", ip, False,
        "refused: feature permanently disabled in this build",
    )


ACTIONS = {
    "alert": _action_alert,
    "kill_process": _action_kill_process,
    "quarantine_file": _action_quarantine_file,
    "block_network": _action_block_network,
}
