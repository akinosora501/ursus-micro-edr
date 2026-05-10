"""psutil による TCP 接続コレクタ。

`psutil.net_connections(kind='tcp')` を一定間隔で呼び、前回スナップショット
との差分から「新しい LISTEN」「新しい ESTABLISHED」を events 表に書き込む。

ESTABLISHED は同一 (pid, remote_ip, remote_port) への連発を debounce する
（HTTP/2 connection pool やポーリング常駐で ephemeral port が違うだけの
重複イベントを抑制）。LISTEN は重要シグナルなので debounce 対象外。

設計上の取りこぼし:
- ポーリング間隔より短命な ESTABLISHED は捕捉できない。Phase 4 の eBPF
  (kprobe inet_csk_accept / tcp_v4_connect) 置き換えで解消する想定。
- UDP は対象外。DNS / NTP / QUIC は見えない。

権限:
- 全ユーザーの接続を見るには root が必要。sensor は netlink プロセス
  コレクタの都合で既に root で動いている前提。
"""
import time

import psutil

from ursus.common.db import get_connection, insert_event
from ursus.common.logging import get_logger

# 安定状態のみを記録対象にする。SYN_SENT / TIME_WAIT 等の遷移ステートは
# ノイズが大きく、ポーリングでは正確に捉えられないので捨てる。
_TRACKED_STATES = ("LISTEN", "ESTABLISHED")


class NetworkCollector:
    def __init__(self, db_path, hostname, poll_interval_sec=2.0,
                 established_debounce_sec=5.0):
        self.db_path = db_path
        self.hostname = hostname
        self.poll_interval = float(poll_interval_sec)
        self.established_debounce_sec = max(0.0, float(established_debounce_sec))
        self.log = get_logger("sensor.network")

        # 許可リスト用: EDR起動時点で存在するネットワークセッションはベースラインとしてイベント化しない
        self._known = set()
        # ESTABLISHED の重複抑制: (pid, raddr_ip, raddr_port) -> last emit monotonic ts
        self._last_established_emit = {}

    def run(self, stop_event):
        conn = get_connection(self.db_path)
        try:
            # EDR起動時点で存在する接続をスナップショット取得し、許可リストとして記録
            self._known = self._snapshot_keys()

            self.log.info(
                "network_collector_started",
                hostname=self.hostname,
                poll_interval_sec=self.poll_interval,
                baseline=len(self._known),
            )

            while not stop_event.is_set():
                # まず stop_event を待つ。短い終了応答性のため。
                if stop_event.wait(self.poll_interval):
                    break

                try:
                    snapshot = psutil.net_connections(kind="tcp")
                except (psutil.AccessDenied, OSError) as e:
                    self.log.error("net_connections_failed", error=str(e))
                    continue

                current = set()
                new_conns = []
                for sc in snapshot:
                    if sc.status not in _TRACKED_STATES:
                        continue
                    key = _conn_key(sc)
                    current.add(key)
                    if key not in self._known:
                        new_conns.append(sc)

                for sc in new_conns:
                    if not self._should_emit(sc):
                        continue
                    try:
                        self._record(conn, sc)
                    except Exception:
                        self.log.exception("network_record_failed")

                self._known = current
                self._gc_debounce()
        finally:
            conn.close()
            self.log.info("network_collector_stopped")

    def _snapshot_keys(self):
        # EDR起動時点で存在するネットワークセッションを許可リスト登録するためのスナップショット機能
        try:
            return {
                _conn_key(sc)
                for sc in psutil.net_connections(kind="tcp")
                if sc.status in _TRACKED_STATES
            }
        except (psutil.AccessDenied, OSError) as e:
            self.log.error("net_connections_failed", error=str(e))
            return set()

    def _should_emit(self, sc):
        """ESTABLISHED の (pid, raddr) 重複を debounce する。LISTEN はそのまま通す。"""
        if sc.status != "ESTABLISHED":
            return True
        if self.established_debounce_sec <= 0:
            return True
        if not sc.raddr:
            return True
        key = (sc.pid, sc.raddr.ip, sc.raddr.port)
        now = time.monotonic()
        last = self._last_established_emit.get(key)
        if last is not None and now - last < self.established_debounce_sec:
            return False
        self._last_established_emit[key] = now
        return True

    def _gc_debounce(self):
        """期限切れの debounce エントリを掃除する。メモリリーク防止。"""
        if self.established_debounce_sec <= 0 or not self._last_established_emit:
            return
        cutoff = time.monotonic() - self.established_debounce_sec
        # 大量の不活性エントリが溜まらないように、窓を超えたものは捨てる。
        self._last_established_emit = {
            k: ts for k, ts in self._last_established_emit.items() if ts > cutoff
        }

    def _record(self, conn, sc):
        laddr = list(sc.laddr) if sc.laddr else None
        raddr = list(sc.raddr) if sc.raddr else None
        process_name = _lookup_process_name(sc.pid)
        family = sc.family.name if hasattr(sc.family, "name") else str(sc.family)
        sock_type = sc.type.name if hasattr(sc.type, "name") else str(sc.type)

        raw = {
            "fd": sc.fd,
            "family": family,
            "type": sock_type,
            "src_addr": laddr,   # machine-local (source) address
            "dst_addr": raddr,   # remote (destination) address
            "status": sc.status,
            "pid": sc.pid,
            "process_name": process_name,
        }

        event_id = insert_event(
            conn,
            event_type="network",
            hostname=self.hostname,
            raw=raw,
            pid=sc.pid,
            process_name=process_name,
            local_port=laddr[1] if laddr else None,
            remote_addr=raddr[0] if raddr else None,
            remote_port=raddr[1] if raddr else None,
            conn_state=sc.status,
        )
        self.log.info(
            "network_collected",
            event_id=event_id,
            status=sc.status,
            laddr=laddr,
            raddr=raddr,
            pid=sc.pid,
            process_name=process_name,
        )


# --- helpers ---------------------------------------------------------------

def _conn_key(sc):
    """差分検出用のキー。同一接続なら同一キーになる。"""
    laddr = (sc.laddr.ip, sc.laddr.port) if sc.laddr else None
    raddr = (sc.raddr.ip, sc.raddr.port) if sc.raddr else None
    return (laddr, raddr, sc.status, sc.pid)


def _lookup_process_name(pid):
    """pid から process 名を取る。死んでいたら None。"""
    if not pid:
        return None
    try:
        return psutil.Process(pid).name()
    except (psutil.NoSuchProcess, psutil.AccessDenied, ProcessLookupError):
        return None
