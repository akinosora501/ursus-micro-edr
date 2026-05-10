"""watchdog (inotify) によるファイル変更コレクタ。

watch_paths の各ディレクトリを再帰的に watch し、create / modify / delete /
move を events 表に書き込む。

スレッドモデル:
- watchdog Observer はファイルシステム通知を別スレッドで受け取り、
  FileSystemEventHandler のコールバックを Observer 側スレッドで呼ぶ。
- SQLite 接続をスレッドをまたいで共有しないため、Handler は受け取った
  イベントを Queue に積むだけにし、DB 書き込みは run() スレッドで行う。

modify の重複抑制:
- 同一 path への連続 modify は modify_debounce_sec の間 1 件目だけ通し、
  以降は破棄する（leading-only）。商用 EDR の "file write storm
  suppression" の最小版に相当。破棄数のサマリは出さない。
"""
import fnmatch
import os
import queue
import threading
import time
from pathlib import Path

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from ursus.common.db import get_connection, insert_event
from ursus.common.logging import get_logger


class _FileEventHandler(FileSystemEventHandler):
    """watchdog の通知を Queue に詰め替えるだけのハンドラ。"""

    def __init__(self, out_queue, exclude_patterns, exclude_dirs, debounce_sec):
        self._queue = out_queue
        self._exclude_patterns = list(exclude_patterns or [])
        # exclude_dirs は呼び出し側で realpath 済みの絶対パス前提。
        # DB ディレクトリ等、コレクタ自身が頻繁に書き込む場所を入れる。
        self._exclude_dirs = [os.path.normpath(d) for d in (exclude_dirs or [])]
        self._debounce_sec = max(0.0, float(debounce_sec))
        # path -> 最後に modify を emit した monotonic 時刻
        # watchdog は emitter ごとに別スレッドを持つので lock で保護。
        self._last_modify_emit = {}
        self._lock = threading.Lock()

    def on_created(self, event):
        self._emit("create", event.src_path, event.is_directory)

    def on_modified(self, event):
        # ディレクトリの modified は配下のファイル変更ごとに発火して
        # ノイズが多いため、検知価値の低い directory modify は捨てる。
        if event.is_directory:
            return
        if self._is_excluded(event.src_path):
            return
        if not self._should_emit_modify(event.src_path):
            return
        self._queue.put({
            "op": "modify",
            "path": event.src_path,
            "is_directory": False,
            "src_path": None,
        })

    def on_deleted(self, event):
        self._emit("delete", event.src_path, event.is_directory)

    def on_moved(self, event):
        # path は移動後のパス、src_path は移動元。
        dest = getattr(event, "dest_path", None)
        if dest:
            if self._is_excluded(dest):
                return
            self._queue.put({
                "op": "move",
                "path": dest,
                "is_directory": event.is_directory,
                "src_path": event.src_path,
            })
            return
        # dest が無い変則ケースは create 相当として扱う。
        self._emit("move", event.src_path, event.is_directory)

    def _emit(self, op, path, is_directory):
        if self._is_excluded(path):
            return
        self._queue.put({
            "op": op,
            "path": path,
            "is_directory": is_directory,
            "src_path": None,
        })

    def _should_emit_modify(self, path):
        """同一 path への modify は debounce 窓内では捨てる。"""
        if self._debounce_sec <= 0:
            return True
        now = time.monotonic()
        with self._lock:
            last = self._last_modify_emit.get(path)
            if last is not None and now - last < self._debounce_sec:
                return False
            self._last_modify_emit[path] = now
        return True

    def _is_excluded(self, path):
        # DB ディレクトリ配下は無条件で除外（自己フィードバックループ防止）。
        # SQLite の WAL/SHM/journal ファイルが秒間数千の modify を生むため、
        # ここで切らないとコレクタが自分の書き込みを観測し続ける。
        try:
            real = os.path.realpath(path)
        except OSError:
            real = path
        for d in self._exclude_dirs:
            if real == d or real.startswith(d + os.sep):
                return True
        name = os.path.basename(path)
        for pattern in self._exclude_patterns:
            if fnmatch.fnmatch(name, pattern) or fnmatch.fnmatch(path, pattern):
                return True
        return False


class FileCollector:
    def __init__(self, db_path, hostname, watch_paths, exclude_patterns,
                 modify_debounce_sec=2.0):
        self.db_path = db_path
        self.hostname = hostname
        self.watch_paths = list(watch_paths or [])
        self.exclude_patterns = list(exclude_patterns or [])
        self.modify_debounce_sec = float(modify_debounce_sec)
        # DB ファイルが置かれているディレクトリ。SQLite の本体・WAL・SHM・
        # journal は同一ディレクトリに作られるため、ディレクトリ単位で除外
        # すれば全部まとめてカバーできる。
        self._db_dir = os.path.realpath(os.path.dirname(os.path.abspath(db_path)))
        self.log = get_logger("sensor.file")

    def run(self, stop_event):
        if not self.watch_paths:
            self.log.warning("file_collector_no_watch_paths")
            return

        out_queue = queue.Queue()
        handler = _FileEventHandler(
            out_queue,
            self.exclude_patterns,
            exclude_dirs=[self._db_dir],
            debounce_sec=self.modify_debounce_sec,
        )
        observer = Observer()

        scheduled = []
        for path in self.watch_paths:
            if not Path(path).exists():
                self.log.warning("watch_path_missing", path=path)
                continue
            try:
                observer.schedule(handler, path, recursive=True)
                scheduled.append(path)
            except OSError as e:
                self.log.error("watch_schedule_failed", path=path, error=str(e))

        if not scheduled:
            self.log.error("file_collector_no_valid_paths")
            return

        conn = get_connection(self.db_path)
        observer.start()
        self.log.info(
            "file_collector_started",
            hostname=self.hostname,
            watch_paths=scheduled,
            exclude_patterns=self.exclude_patterns,
            exclude_dirs=[self._db_dir],
            modify_debounce_sec=self.modify_debounce_sec,
        )

        try:
            while not stop_event.is_set():
                try:
                    payload = out_queue.get(timeout=0.5)
                except queue.Empty:
                    continue
                try:
                    self._record(conn, payload)
                except Exception:
                    self.log.exception("file_record_failed", payload=payload)
        finally:
            observer.stop()
            observer.join(timeout=5.0)
            conn.close()
            self.log.info("file_collector_stopped")

    def _record(self, conn, payload):
        event_id = insert_event(
            conn,
            event_type="file",
            hostname=self.hostname,
            raw=payload,
            file_path=payload["path"],
            file_op=payload["op"],
        )
        self.log.info(
            "file_collected",
            event_id=event_id,
            op=payload["op"],
            path=payload["path"],
            is_directory=payload["is_directory"],
        )
