"""systemd-journald を journalctl サブプロセス経由で購読する auth collector。

`journalctl -f --output=json` を1回起動して常駐させ、stdout の JSON 行を
受け取る。journalctl 自体は libsystemd の sd_journal_wait で寝ているため、
新規ログ到着はカーネル通知で叩き起こされる（取りこぼし・遅延ともなし）。
我々の Python は select で stdout の fd を待ち、500ms ごとに stop_event を
確認する。

追加 pip / apt パッケージ不要、journalctl は systemd 同梱。
"""
import json
import re
import select
import subprocess

from ursus.common.db import get_connection, insert_event
from ursus.common.logging import get_logger

# --- 正規表現パターン -------------------------------------------------------
# journal MESSAGE 形式（プレフィックス無し）:
#   Accepted password for root from 1.2.3.4 port 22 ssh2
#   Failed password for invalid user admin from 1.2.3.4 port 22 ssh2
#   parrot : TTY=pts/0 ; PWD=/home ; USER=root ; COMMAND=/usr/bin/ls
# MESSAGE 先頭にスペースが入ることがあるため \s* で吸収

RE_ACCEPTED = re.compile(
    r'\bAccepted\s+(\S+)\s+for\s+(\S+)\s+from\s+(\S+)'
)
RE_FAILED = re.compile(
    r'\bFailed\s+(\S+)\s+for\s+(?:invalid user\s+)?(\S+)\s+from\s+(\S+)'
)
RE_SUDO = re.compile(
    r'^\s*(\S+)\s+:\s+.*COMMAND=(.+)$'
)


def parse_line(line, service_hint=None):
    """journal MESSAGE を解析。マッチしなければ None。

    service_hint: journal 由来のとき `_COMM` を渡す。sudo は MESSAGE 単体
    ではプレフィックスが落ちているため、hint で判定する。
    """
    m = RE_ACCEPTED.search(line)
    if m:
        return {
            "service": "sshd",
            "result": "success",
            "method": m.group(1),
            "user": m.group(2),
            "source_ip": m.group(3),
        }
    m = RE_FAILED.search(line)
    if m:
        return {
            "service": "sshd",
            "result": "failure",
            "method": m.group(1),
            "user": m.group(2),
            "source_ip": m.group(3),
        }
    # sudo: hint が "sudo" なら bare 形式でマッチ
    if service_hint == "sudo":
        m = RE_SUDO.search(line)
        if m:
            return {
                "service": "sudo",
                "result": "sudo",
                "user": m.group(1),
                "command": m.group(2).strip(),
                "source_ip": None,
            }
    return None


# --- コレクタ本体 -----------------------------------------------------------

class JournalAuthCollector:
    def __init__(self, db_path, hostname, units=None, comms=None):
        self.db_path = db_path
        self.hostname = hostname
        self.units = list(units or [])
        self.comms = list(comms or [])
        self.log = get_logger("sensor.auth.journal")

    def run(self, stop_event):
        conn = get_connection(self.db_path)
        proc = self._spawn_journalctl()
        if proc is None:
            conn.close()
            return

        self.log.info(
            "journal_auth_collector_started",
            hostname=self.hostname,
            units=self.units,
            comms=self.comms,
            journalctl_pid=proc.pid,
        )
        try:
            self._read_loop(conn, proc, stop_event)
        finally:
            self._terminate(proc)
            conn.close()
            self.log.info("journal_auth_collector_stopped")

    # --- subprocess ------------------------------------------------------

    def _spawn_journalctl(self):
        # -f             : tail -f 相当（追記を待つ）
        # --output=json  : 1行 1JSON
        # --no-pager     : pager 介在を防ぐ
        # stdbuf -oL     : journalctl 側の stdout を行バッファ化（パイプ
        #                  出力時のブロックバッファリング回避）
        cmd = ["stdbuf", "-oL",
               "journalctl", "-f", "--output=json", "--no-pager"]

        # journalctl の match セマンティクス:
        #   - 同じフィールドの match は OR 結合される
        #   - 異なるフィールドの match は AND 結合される
        #   - "+" を境にすると左右のグループ全体が OR 結合される
        #   - ただし "+" は FIELD=VALUE 形式の match 同士の間でしか使えない
        #     ("-u UNIT" のようなオプションは "+" の隣に置けない)
        # → -u UNIT は使わず、自前で _SYSTEMD_UNIT=UNIT に変換する。
        unit_args = [f"_SYSTEMD_UNIT={u}" for u in self.units]
        comm_args = [f"_COMM={c}" for c in self.comms]

        if unit_args and comm_args:
            cmd += unit_args + ["+"] + comm_args
        else:
            cmd += unit_args + comm_args

        if not self.units and not self.comms:
            self.log.warning("no_journal_filters_configured")

        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,    # 早期終了時の原因表示のため捕捉
                bufsize=1,                 # 行バッファ
                text=True,
            )
        except FileNotFoundError as e:
            self.log.error("journalctl_not_found", error=str(e))
            return None
        self.log.info("journalctl_spawned", argv=cmd, pid=proc.pid)
        return proc

    @staticmethod
    def _drain_stderr(proc):
        """既に exit している journalctl の stderr を読み出す（最大 4KB）。"""
        if proc is None or proc.stderr is None:
            return None
        try:
            data = proc.stderr.read(4096)
            return data.strip() if data else None
        except Exception:
            return None

    def _terminate(self, proc):
        if proc is None or proc.poll() is not None:
            return
        try:
            proc.terminate()
            proc.wait(timeout=5.0)
        except subprocess.TimeoutExpired:
            proc.kill()
            try:
                proc.wait(timeout=2.0)
            except subprocess.TimeoutExpired:
                pass
        except Exception:
            pass

    # --- read loop -------------------------------------------------------

    def _read_loop(self, conn, proc, stop_event):
        fd = proc.stdout.fileno()
        poller = select.poll()
        poller.register(fd, select.POLLIN | select.POLLHUP | select.POLLERR)

        while not stop_event.is_set():
            events = poller.poll(500)  # 500ms は stop_event 確認用
            if not events:
                if proc.poll() is not None:
                    self.log.warning(
                        "journalctl_exited",
                        returncode=proc.returncode,
                        stderr=self._drain_stderr(proc),
                    )
                    return
                continue

            for _fd, mask in events:
                if mask & select.POLLIN:
                    line = proc.stdout.readline()
                    if not line:
                        self.log.warning(
                            "journalctl_eof",
                            returncode=proc.poll(),
                            stderr=self._drain_stderr(proc),
                        )
                        return
                    try:
                        self._handle_line(conn, line)
                    except Exception:
                        self.log.exception("journal_handle_failed")
                if mask & (select.POLLHUP | select.POLLERR):
                    self.log.warning(
                        "journalctl_pipe_closed",
                        mask=mask,
                        returncode=proc.poll(),
                        stderr=self._drain_stderr(proc),
                    )
                    return

    # --- line handling ---------------------------------------------------

    def _handle_line(self, conn, line):
        line = line.strip()
        if not line:
            return
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            return

        msg = rec.get("MESSAGE", "")
        # 非UTF8 のとき journald は MESSAGE をバイト配列(int list)で返す
        if isinstance(msg, list):
            try:
                msg = bytes(msg).decode("utf-8", "replace")
            except Exception:
                return
        if not isinstance(msg, str) or not msg:
            return

        comm = rec.get("_COMM")
        parsed = parse_line(msg, service_hint=comm)
        if parsed is None:
            self.log.debug(
                "journal_line_skipped",
                comm=comm,
                msg_preview=msg[:120],
            )
            return

        raw = {
            **parsed,
            "raw_line": msg,
            "log_source": "journal",
            "_systemd_unit": rec.get("_SYSTEMD_UNIT"),
            "_comm": comm,
            "_pid": rec.get("_PID"),
            "syslog_identifier": rec.get("SYSLOG_IDENTIFIER"),
        }
        try:
            event_id = insert_event(
                conn,
                event_type="auth",
                hostname=self.hostname,
                raw=raw,
                process_name=rec.get("SYSLOG_IDENTIFIER") or comm,
                pid=int(rec["_PID"]) if rec.get("_PID") else None,
                auth_user=parsed.get("user"),
                auth_result=parsed.get("result"),
                source_ip=parsed.get("source_ip"),
                cmdline=parsed.get("command"),
            )
        except Exception:
            self.log.exception("auth_record_failed")
            return

        self.log.info(
            "auth_collected",
            event_id=event_id,
            service=parsed.get("service"),
            result=parsed.get("result"),
            user=parsed.get("user"),
            source_ip=parsed.get("source_ip"),
        )
