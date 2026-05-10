"""ルール評価エンジン。

events 表をストリーム的に追いかけ、ルールに合致したイベントについて
alerts を発火し、レスポンスをディスパッチする。

チェックポイントは detector_state(key='last_evaluated_event_id') で永続化する。
"""
import json
import time

from ursus.common.db import get_connection
from ursus.common.logging import get_logger
from ursus.detector.operators import OPERATORS

CHECKPOINT_KEY = "last_evaluated_event_id"
FETCH_LIMIT = 500


class DetectionEngine:
    def __init__(self, db_path, rules, response_handler, poll_interval=1.0):
        self.db_path = db_path
        self.rules = rules
        self.response_handler = response_handler
        self.poll_interval = poll_interval
        self.log = get_logger("detector.engine")

        # event_type ごとに分類しておくと評価ループで余計なルールを見ないで済む。
        self.rules_by_type = {}
        for r in rules:
            self.rules_by_type.setdefault(r.event_type, []).append(r)

    def run(self, stop_event):
        conn = get_connection(self.db_path)
        try:
            last_id = self._load_checkpoint(conn)
            self.log.info(
                "engine_started",
                last_evaluated_event_id=last_id,
                rules_count=len(self.rules),
                poll_interval_sec=self.poll_interval,
            )
            while not stop_event.is_set():
                try:
                    last_id = self._tick(conn, last_id)
                except Exception:
                    self.log.exception("engine_tick_failed")
                stop_event.wait(self.poll_interval)
        finally:
            conn.close()
            self.log.info("engine_stopped")

    def _tick(self, conn, last_id):
        rows = conn.execute(
            "SELECT * FROM events WHERE id > ? ORDER BY id ASC LIMIT ?",
            (last_id, FETCH_LIMIT),
        ).fetchall()
        for ev in rows:
            self._evaluate_event(conn, ev)
            last_id = ev["id"]
        if rows:
            self._save_checkpoint(conn, last_id)
        return last_id

    def _evaluate_event(self, conn, ev):
        for rule in self.rules_by_type.get(ev["event_type"], []):
            if not rule.enabled:
                continue
            if eval_condition(rule.condition, ev):
                self._fire_alert(conn, rule, ev)

    def _fire_alert(self, conn, rule, ev):
        # 同じ (rule, event) で二重発火しない
        existing = conn.execute(
            "SELECT id FROM alerts WHERE rule_id = ? AND triggered_event_id = ?",
            (rule.id, ev["id"]),
        ).fetchone()
        if existing:
            return

        cur = conn.execute(
            "INSERT INTO alerts "
            "(timestamp, rule_id, rule_title, severity, triggered_event_id, mitre) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (
                time.time(),
                rule.id,
                rule.title,
                rule.severity,
                ev["id"],
                json.dumps(rule.mitre, ensure_ascii=False),
            ),
        )
        alert_id = cur.lastrowid

        self.log.info(
            "alert_fired",
            alert_id=alert_id,
            rule_id=rule.id,
            rule_title=rule.title,
            severity=rule.severity,
            event_id=ev["id"],
            pid=ev["pid"],
            process_name=ev["process_name"],
        )
        self.response_handler.dispatch(conn, rule, alert_id, ev)

    def _load_checkpoint(self, conn):
        row = conn.execute(
            "SELECT value FROM detector_state WHERE key = ?", (CHECKPOINT_KEY,)
        ).fetchone()
        return int(row["value"]) if row else 0

    def _save_checkpoint(self, conn, last_id):
        conn.execute(
            "INSERT INTO detector_state(key, value) VALUES(?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (CHECKPOINT_KEY, str(last_id)),
        )


def eval_condition(node, event):
    """condition ツリーを再帰的に評価する。"""
    if "all" in node:
        return all(eval_condition(c, event) for c in node["all"])
    if "any" in node:
        return any(eval_condition(c, event) for c in node["any"])
    if "not" in node:
        return not eval_condition(node["not"], event)
    # リーフ
    value = extract_field(event, node["field"])
    return OPERATORS[node["op"]](value, node.get("value"))


def extract_field(event, field):
    """非正規化カラム名 or 'raw.<key>[.<key>...]' から値を取り出す。

    存在しないキーは None を返す。
    """
    if field.startswith("raw."):
        try:
            data = json.loads(event["raw_json"])
        except (TypeError, ValueError):
            return None
        for key in field.split(".")[1:]:
            if not isinstance(data, dict):
                return None
            data = data.get(key)
            if data is None:
                return None
        return data
    try:
        return event[field]
    except (KeyError, IndexError):
        return None
