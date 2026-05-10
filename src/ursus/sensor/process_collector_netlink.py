"""PROC_EVENTS netlink (cn_proc) によるプロセスコレクタ。

Linux カーネルの netlink CONNECTOR インタフェースを直接購読し、
exec(2) の成功イベントをリアルタイムに受信する。ポーリング不要なので
短命プロセスも取りこぼさない。

実装は Python 標準ライブラリ (socket / struct / pwd) のみ。bcc・eBPF・
auditd などの追加コンポーネントは不要。

要件:
- Linux カーネル CONFIG_PROC_EVENTS=y, CONFIG_CONNECTOR=y（ほぼ全ディストリで標準）
- root 権限 (CAP_NET_ADMIN)

ABI 参考:
- /usr/include/linux/netlink.h
- /usr/include/linux/connector.h
- /usr/include/linux/cn_proc.h
"""
import os
import pwd
import socket
import struct
from pathlib import Path

from ursus.common.db import get_connection, insert_event
from ursus.common.logging import get_logger

# --- カーネル ABI 定数 -------------------------------------------------------
NETLINK_CONNECTOR = 11
NLMSG_DONE = 3

CN_IDX_PROC = 1
CN_VAL_PROC = 1

PROC_CN_MCAST_LISTEN = 1
PROC_CN_MCAST_IGNORE = 2

# proc_event.what
PROC_EVENT_EXEC = 0x00000002

# --- struct レイアウト ------------------------------------------------------
# nlmsghdr: __u32 len, __u16 type, __u16 flags, __u32 seq, __u32 pid  (16 bytes)
_NLMSGHDR = struct.Struct("=IHHII")

# cn_msg ヘッダ: cb_id(idx,val) + seq + ack + len + flags  (20 bytes)
_CNMSG = struct.Struct("=IIIIHH")

# proc_event ヘッダ: what + cpu + timestamp_ns  (16 bytes)
_EVTHDR = struct.Struct("=IIQ")


class NetlinkProcessCollector:
    def __init__(self, db_path, hostname):
        self.db_path = db_path
        self.hostname = hostname
        self.log = get_logger("sensor.process.netlink")
        self._conn = None
        self._sock = None

    def run(self, stop_event):
        self._conn = get_connection(self.db_path)
        self._sock = self._open_socket()
        self._send_op(PROC_CN_MCAST_LISTEN)
        # stop_event を 200ms ごとに見に戻るためソケットにタイムアウトを付ける。
        self._sock.settimeout(0.2)

        self.log.info(
            "netlink_process_collector_started",
            hostname=self.hostname,
            netlink_pid=os.getpid(),
        )
        try:
            while not stop_event.is_set():
                try:
                    data, _ = self._sock.recvfrom(8192)
                except socket.timeout:
                    continue
                except OSError as e:
                    self.log.error("netlink_recv_failed", error=str(e))
                    continue
                try:
                    self._handle_message(data)
                except Exception:
                    self.log.exception("netlink_handle_failed")
        finally:
            try:
                self._send_op(PROC_CN_MCAST_IGNORE)
            except OSError:
                pass
            self._sock.close()
            self._conn.close()
            self.log.info("netlink_process_collector_stopped")

    def _open_socket(self):
        try:
            s = socket.socket(socket.AF_NETLINK, socket.SOCK_DGRAM, NETLINK_CONNECTOR)
        except OSError as e:
            raise RuntimeError(
                "netlink socket を開けません。Linux + root 権限が必要です: " + str(e)
            ) from e
        # bind: pid=0 でカーネル自動採番、groups=CN_IDX_PROC で connector の
        # プロセスイベントマルチキャストを購読。
        try:
            s.bind((0, CN_IDX_PROC))
        except PermissionError as e:
            s.close()
            raise RuntimeError(
                "netlink bind に失敗しました（CAP_NET_ADMIN が必要、root で起動してください）: "
                + str(e)
            ) from e
        return s

    def _send_op(self, op):
        """PROC_CN_MCAST_LISTEN / IGNORE をカーネルに送る。"""
        body = struct.pack("=I", op)
        cn_payload = _CNMSG.pack(
            CN_IDX_PROC, CN_VAL_PROC,  # cb_id
            0, 0,                       # seq, ack
            len(body), 0,               # len, flags
        ) + body
        total_len = _NLMSGHDR.size + len(cn_payload)
        nl_hdr = _NLMSGHDR.pack(total_len, NLMSG_DONE, 0, 0, 0)
        self._sock.send(nl_hdr + cn_payload)

    def _handle_message(self, data):
        # 1メッセージ = 1 nlmsg = 1 cn_msg = 1 proc_event(connectorの慣例)。
        if len(data) < _NLMSGHDR.size + _CNMSG.size + _EVTHDR.size:
            return

        # nlmsghdr はスキップ。cn_msg ヘッダから idx/val を確認。
        idx, val, _seq, _ack, _payload_len, _flags = _CNMSG.unpack_from(
            data, _NLMSGHDR.size
        )
        if idx != CN_IDX_PROC or val != CN_VAL_PROC:
            return

        evt_off = _NLMSGHDR.size + _CNMSG.size
        what, _cpu, _ts_ns = _EVTHDR.unpack_from(data, evt_off)
        body_off = evt_off + _EVTHDR.size

        # 学習目的では exec のみ扱う。fork/exit/uid 変更も同じパターンで追加可能。
        if what == PROC_EVENT_EXEC:
            pid, tgid = struct.unpack_from("=II", data, body_off)
            # スレッドからの exec も tgid（プロセスID）で集約する。
            self._record_exec(tgid)

    def _record_exec(self, pid):
        info = _read_proc_info(pid)
        if info is None:
            # exec 直後にプロセスが消えていた場合（極短命）、最低限の情報だけ残せる
            # こともできるが、cmdline が無いと検知に意味が無いので捨てる。
            return

        cmdline_str = " ".join(info["cmdline"]) if info["cmdline"] else None
        raw = {**info, "source": "netlink"}
        try:
            event_id = insert_event(
                self._conn,
                event_type="process",
                hostname=self.hostname,
                raw=raw,
                pid=info["pid"],
                ppid=info["ppid"],
                user=info["username"],
                process_name=info["name"],
                parent_process_name=info["parent_name"],
                cmdline=cmdline_str,
                exe_path=info["exe"],
            )
        except Exception:
            self.log.exception("netlink_record_failed", pid=pid)
            return

        self.log.info(
            "process_collected",
            event_id=event_id,
            pid=info["pid"],
            ppid=info["ppid"],
            process_name=info["name"],
            parent_process_name=info["parent_name"],
            user=info["username"],
        )


# --- /proc 読み取り ---------------------------------------------------------

def _read_proc_info(pid):
    """/proc/<pid> から必要な属性を集める。プロセス消失時は None。"""
    base = Path(f"/proc/{pid}")
    try:
        comm = (base / "comm").read_text(encoding="utf-8").strip()
        cmdline_bytes = (base / "cmdline").read_bytes()
        status = (base / "status").read_text(encoding="utf-8")
    except (FileNotFoundError, ProcessLookupError, PermissionError):
        return None

    cmdline = [a.decode("utf-8", "replace") for a in cmdline_bytes.split(b"\x00") if a]

    try:
        exe = os.readlink(base / "exe")
    except (FileNotFoundError, ProcessLookupError, PermissionError):
        exe = None

    ppid, uid = _parse_status(status)
    parent_name = _read_comm(ppid) if ppid else None

    if uid is not None:
        try:
            username = pwd.getpwuid(uid).pw_name
        except KeyError:
            username = str(uid)
    else:
        username = None

    return {
        "pid": pid,
        "ppid": ppid,
        "uid": uid,
        "name": comm,
        "exe": exe,
        "cmdline": cmdline,
        "username": username,
        "parent_name": parent_name,
    }


def _read_comm(pid):
    try:
        return Path(f"/proc/{pid}/comm").read_text(encoding="utf-8").strip()
    except (FileNotFoundError, ProcessLookupError, PermissionError):
        return None


def _parse_status(status):
    """/proc/<pid>/status から PPid と (real) Uid を取り出す。"""
    ppid = None
    uid = None
    for line in status.splitlines():
        if line.startswith("PPid:"):
            try:
                ppid = int(line.split()[1])
            except (IndexError, ValueError):
                pass
        elif line.startswith("Uid:"):
            try:
                # Uid: real effective saved fs
                uid = int(line.split()[1])
            except (IndexError, ValueError):
                pass
        if ppid is not None and uid is not None:
            break
    return ppid, uid
