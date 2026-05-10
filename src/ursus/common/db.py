"""SQLite connection and schema management.

イベントは全コンポーネントが共有する単一の SQLite ファイルに溜める。
WAL モードを有効にすることで Sensor / Detector / UI が同時アクセスできる。
"""
import json
import sqlite3
import time
from pathlib import Path

SCHEMA_DDL = """
CREATE TABLE IF NOT EXISTS events (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  timestamp     REAL NOT NULL,
  event_type    TEXT NOT NULL CHECK(event_type IN ('process','file','network','auth')),
  hostname      TEXT NOT NULL,
  raw_json      TEXT NOT NULL,
  pid                  INTEGER,
  ppid                 INTEGER,
  user                 TEXT,
  process_name         TEXT,
  parent_process_name  TEXT,
  cmdline              TEXT,
  exe_path             TEXT,
  file_path            TEXT,
  file_op              TEXT,
  remote_addr          TEXT,
  remote_port          INTEGER,
  local_port           INTEGER,
  conn_state           TEXT,
  auth_user            TEXT,
  auth_result          TEXT,
  source_ip            TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_ts    ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_type  ON events(event_type, timestamp);
CREATE INDEX IF NOT EXISTS idx_events_pid   ON events(pid);
CREATE INDEX IF NOT EXISTS idx_events_ppid  ON events(ppid);

CREATE TABLE IF NOT EXISTS alerts (
  id                   INTEGER PRIMARY KEY AUTOINCREMENT,
  timestamp            REAL NOT NULL,
  rule_id              TEXT NOT NULL,
  rule_title           TEXT NOT NULL,
  severity             TEXT NOT NULL CHECK(severity IN ('low','medium','high','critical')),
  triggered_event_id   INTEGER NOT NULL REFERENCES events(id),
  mitre                TEXT,
  context_json         TEXT,
  acknowledged         INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_alerts_ts    ON alerts(timestamp);
CREATE INDEX IF NOT EXISTS idx_alerts_rule  ON alerts(rule_id);

CREATE TABLE IF NOT EXISTS response_log (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  timestamp    REAL NOT NULL,
  alert_id     INTEGER NOT NULL REFERENCES alerts(id),
  action       TEXT NOT NULL,
  target       TEXT,
  dry_run      INTEGER NOT NULL,
  success      INTEGER NOT NULL,
  detail       TEXT
);

CREATE TABLE IF NOT EXISTS detector_state (
  key          TEXT PRIMARY KEY,
  value        TEXT NOT NULL
);
"""


def get_connection(path):
    """SQLite 接続を WAL モードで開く。親ディレクトリは無ければ作る。"""
    db_path = Path(path)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path), isolation_level=None, timeout=30.0)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.row_factory = sqlite3.Row
    return conn


def init_schema(conn):
    """テーブルとインデックスを冪等に作成する。"""
    conn.executescript(SCHEMA_DDL)


def insert_event(conn, event_type, hostname, raw, **denorm):
    """events 表に1件 INSERT する。

    denorm には pid / process_name / file_path などの非正規化カラムを
    キーワード引数で渡す。None は無視する。
    """
    cols = ["timestamp", "event_type", "hostname", "raw_json"]
    vals = [time.time(), event_type, hostname, json.dumps(raw, ensure_ascii=False, default=str)]
    for key, value in denorm.items():
        if value is None:
            continue
        cols.append(key)
        vals.append(value)
    placeholders = ",".join("?" * len(vals))
    sql = f"INSERT INTO events ({','.join(cols)}) VALUES ({placeholders})"
    return conn.execute(sql, vals).lastrowid


def purge_old_events(conn, retention_days):
    """retention_days より古い events を削除し、削除件数を返す。"""
    cur = conn.execute(
        "DELETE FROM events WHERE timestamp < strftime('%s','now') - (? * 86400)",
        (retention_days,),
    )
    return cur.rowcount
