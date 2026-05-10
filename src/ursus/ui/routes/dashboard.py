"""ダッシュボード: イベント推移・種別比率・アラート・ルール別 Top10。

時間範囲は ?since= ?until= で指定（datetime-local 形式の文字列、host の
ローカル時刻として解釈）。?range=1h|6h|24h|7d|30d のショートハンドも可。
何も指定しなければ直近 24 時間。
"""
import time
from datetime import datetime

from fastapi import APIRouter, Query, Request

from ursus.common.db import get_connection

router = APIRouter()

# ?range= で指定できるショートハンド。値は秒数。
RANGE_PRESETS = {
    "1h":  1 * 3600,
    "6h":  6 * 3600,
    "24h": 24 * 3600,
    "7d":  7 * 86400,
    "30d": 30 * 86400,
}
DEFAULT_RANGE_SEC = RANGE_PRESETS["24h"]
BUCKETS = 24  # タイムラインのバケット数（範囲に応じてバケット幅が変わる）


@router.get("/")
async def dashboard(
    request: Request,
    since: str | None = None,
    until: str | None = None,
    range_: str | None = Query(None, alias="range"),
):
    config = request.app.state.config
    templates = request.app.state.templates

    since_ts, until_ts = _resolve_range(since, until, range_)
    range_sec = until_ts - since_ts
    bucket_size = range_sec / BUCKETS

    conn = get_connection(config.database.path)
    try:
        timeline = _timeline(conn, since_ts, until_ts, bucket_size)
        type_counts = _type_counts(conn, since_ts, until_ts)
        recent_alerts = _recent_alerts(conn, since_ts, until_ts, limit=10)
        top_rules = _top_rules(conn, since_ts, until_ts, limit=10)
        totals = _totals(conn, since_ts, until_ts)
    finally:
        conn.close()

    return templates.TemplateResponse(
        request,
        "dashboard.html",
        {
            "active_page": "dashboard",
            "timeline": timeline,
            "timeline_labels": _bucket_labels(since_ts, bucket_size, range_sec),
            "type_counts": type_counts,
            "recent_alerts": recent_alerts,
            "top_rules": top_rules,
            "totals": totals,
            "since_input": _to_local_input(since_ts),
            "until_input": _to_local_input(until_ts),
            "range_label": _format_duration(range_sec),
            "active_preset": range_ if range_ in RANGE_PRESETS else None,
            "presets": list(RANGE_PRESETS.keys()),
        },
    )


# --- range 解決 -------------------------------------------------------------

def _resolve_range(since, until, range_):
    """since/until/range の優先順位を1箇所で決める。"""
    now = time.time()
    if range_ in RANGE_PRESETS:
        return now - RANGE_PRESETS[range_], now

    until_ts = _parse_iso(until)
    since_ts = _parse_iso(since)
    if until_ts is None:
        until_ts = now
    if since_ts is None:
        since_ts = until_ts - DEFAULT_RANGE_SEC
    if since_ts >= until_ts:
        # 不正な範囲は黙って既定にフォールバック。
        since_ts = until_ts - DEFAULT_RANGE_SEC
    return since_ts, until_ts


def _parse_iso(s):
    if not s:
        return None
    try:
        return datetime.fromisoformat(s).timestamp()
    except (TypeError, ValueError):
        return None


def _to_local_input(ts):
    """datetime-local input の value 形式 (YYYY-MM-DDTHH:MM) で返す。"""
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%dT%H:%M")


def _format_duration(sec):
    sec = int(sec)
    if sec % 86400 == 0 and sec >= 86400:
        return f"{sec // 86400}d"
    if sec % 3600 == 0 and sec >= 3600:
        return f"{sec // 3600}h"
    if sec % 60 == 0 and sec >= 60:
        return f"{sec // 60}m"
    return f"{sec}s"


def _bucket_labels(since_ts, bucket_size, range_sec):
    """各バケットの開始時刻を読みやすい形式で返す。"""
    if range_sec <= 24 * 3600:
        fmt = "%H:%M"
    elif range_sec <= 7 * 86400:
        fmt = "%m/%d %H:%M"
    else:
        fmt = "%m/%d"
    return [
        datetime.fromtimestamp(since_ts + i * bucket_size).strftime(fmt)
        for i in range(BUCKETS)
    ]


# --- 集計クエリ -------------------------------------------------------------

def _timeline(conn, since, until, bucket_size):
    """BUCKETS 個 × 4 種別の 2 次元集計。"""
    rows = conn.execute(
        "SELECT CAST((timestamp - ?) / ? AS INTEGER) AS bucket, "
        "       event_type, COUNT(*) AS n "
        "FROM events WHERE timestamp >= ? AND timestamp < ? "
        "GROUP BY bucket, event_type",
        (since, bucket_size, since, until),
    ).fetchall()
    types = ["process", "file", "network", "auth"]
    by_type = {t: [0] * BUCKETS for t in types}
    for r in rows:
        b = max(0, min(BUCKETS - 1, r["bucket"]))
        if r["event_type"] in by_type:
            by_type[r["event_type"]][b] = r["n"]
    return by_type


def _type_counts(conn, since, until):
    rows = conn.execute(
        "SELECT event_type, COUNT(*) AS n FROM events "
        "WHERE timestamp >= ? AND timestamp < ? GROUP BY event_type",
        (since, until),
    ).fetchall()
    return {r["event_type"]: r["n"] for r in rows}


def _recent_alerts(conn, since, until, limit):
    rows = conn.execute(
        "SELECT id, timestamp, rule_id, rule_title, severity "
        "FROM alerts WHERE timestamp >= ? AND timestamp < ? "
        "ORDER BY id DESC LIMIT ?",
        (since, until, limit),
    ).fetchall()
    return [dict(r) for r in rows]


def _top_rules(conn, since, until, limit):
    rows = conn.execute(
        "SELECT rule_id, rule_title, COUNT(*) AS n FROM alerts "
        "WHERE timestamp >= ? AND timestamp < ? "
        "GROUP BY rule_id ORDER BY n DESC LIMIT ?",
        (since, until, limit),
    ).fetchall()
    return [dict(r) for r in rows]


def _totals(conn, since, until):
    n_events = conn.execute(
        "SELECT COUNT(*) AS n FROM events WHERE timestamp >= ? AND timestamp < ?",
        (since, until),
    ).fetchone()["n"]
    n_alerts = conn.execute(
        "SELECT COUNT(*) AS n FROM alerts WHERE timestamp >= ? AND timestamp < ?",
        (since, until),
    ).fetchone()["n"]
    # 未確認アラートもレンジ内に絞る（Range 変更時に連動させるため）。
    n_open = conn.execute(
        "SELECT COUNT(*) AS n FROM alerts "
        "WHERE acknowledged = 0 AND timestamp >= ? AND timestamp < ?",
        (since, until),
    ).fetchone()["n"]
    return {"events": n_events, "alerts": n_alerts, "open_alerts": n_open}
