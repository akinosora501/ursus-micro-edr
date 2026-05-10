"""アラート一覧と詳細。"""
import json

from fastapi import APIRouter, HTTPException, Request

from ursus.common.db import get_connection

router = APIRouter()

PER_PAGE = 50


@router.get("/alerts")
async def alerts_list(
    request: Request,
    severity: str | None = None,
    rule_id: str | None = None,
    # acknowledged / page は HTML フォームから空文字列で来ることがあり、
    # int で受けると FastAPI 422 (raw JSON) を返してしまう。str で受けて変換。
    acknowledged: str | None = None,
    page: str | None = None,
):
    config = request.app.state.config
    templates = request.app.state.templates

    ack_int = _safe_int(acknowledged)
    page_int = max(_safe_int(page) or 1, 1)

    where, params = [], []
    if severity:
        where.append("severity = ?")
        params.append(severity)
    if rule_id:
        where.append("rule_id = ?")
        params.append(rule_id)
    if ack_int is not None:
        where.append("acknowledged = ?")
        params.append(ack_int)
    where_sql = ("WHERE " + " AND ".join(where)) if where else ""

    conn = get_connection(config.database.path)
    try:
        total = conn.execute(
            f"SELECT COUNT(*) FROM alerts {where_sql}", params
        ).fetchone()[0]
        offset = (page_int - 1) * PER_PAGE
        rows = conn.execute(
            f"SELECT * FROM alerts {where_sql} ORDER BY id DESC LIMIT ? OFFSET ?",
            params + [PER_PAGE, offset],
        ).fetchall()
        # ルールIDのプルダウン用に既存ID一覧を取る
        rule_ids = [
            r["rule_id"]
            for r in conn.execute(
                "SELECT DISTINCT rule_id FROM alerts ORDER BY rule_id"
            ).fetchall()
        ]
    finally:
        conn.close()

    pages = max(1, (total + PER_PAGE - 1) // PER_PAGE)

    return templates.TemplateResponse(
        request,
        "alerts.html",
        {
            "active_page": "alerts",
            "alerts": [dict(r) for r in rows],
            "total": total,
            "page": page_int,
            "per_page": PER_PAGE,
            "pages": pages,
            "rule_ids": rule_ids,
            "filters": {
                "severity": severity,
                "rule_id": rule_id,
                "acknowledged": ack_int,
            },
        },
    )


def _safe_int(s):
    """空文字列・None・非数値を許容して int|None を返す。"""
    if s is None or s == "":
        return None
    try:
        return int(s)
    except (TypeError, ValueError):
        return None


@router.get("/alerts/{alert_id}")
async def alert_detail(request: Request, alert_id: int):
    config = request.app.state.config
    templates = request.app.state.templates

    conn = get_connection(config.database.path)
    try:
        alert = conn.execute(
            "SELECT * FROM alerts WHERE id = ?", (alert_id,)
        ).fetchone()
        if alert is None:
            raise HTTPException(status_code=404, detail="alert not found")

        triggered = conn.execute(
            "SELECT * FROM events WHERE id = ?", (alert["triggered_event_id"],)
        ).fetchone()

        # 同 PID の前後 30 秒のイベント
        context_events = []
        if triggered and triggered["pid"] is not None:
            context_events = conn.execute(
                "SELECT * FROM events WHERE pid = ? "
                "AND timestamp BETWEEN ? AND ? ORDER BY timestamp ASC",
                (
                    triggered["pid"],
                    triggered["timestamp"] - 30,
                    triggered["timestamp"] + 30,
                ),
            ).fetchall()

        responses = conn.execute(
            "SELECT * FROM response_log WHERE alert_id = ? ORDER BY id ASC",
            (alert_id,),
        ).fetchall()
    finally:
        conn.close()

    alert_d = dict(alert)
    try:
        alert_d["mitre_list"] = json.loads(alert_d.get("mitre") or "[]")
    except (TypeError, ValueError):
        alert_d["mitre_list"] = []

    triggered_d = None
    if triggered:
        triggered_d = _row_with_raw(triggered, with_pretty=True)

    return templates.TemplateResponse(
        request,
        "alert_detail.html",
        {
            "active_page": "alerts",
            "alert": alert_d,
            "triggered_event": triggered_d,
            "context_events": [_row_with_raw(r) for r in context_events],
            "responses": [dict(r) for r in responses],
        },
    )


def _row_with_raw(row, with_pretty=False):
    """events 行を dict 化し、raw_json をパース済み dict として `raw` に展開する。

    LISTEN の network event のように非正規化カラムだけでは表示できないケースで、
    テンプレートが ev.raw.src_addr 等を参照できるようにする。
    旧キー名 laddr/raddr も src_addr/dst_addr に正規化する（後方互換）。
    """
    d = dict(row)
    try:
        parsed = json.loads(d["raw_json"])
    except (TypeError, ValueError, KeyError):
        parsed = None
    d["raw"] = parsed if isinstance(parsed, dict) else {}
    # 旧キー名 laddr/raddr → src_addr/dst_addr に正規化（既存 DB との後方互換）
    if d.get("event_type") == "network" and d["raw"]:
        raw = d["raw"]
        if "laddr" in raw and "src_addr" not in raw:
            raw["src_addr"] = raw["laddr"]
        if "raddr" in raw and "dst_addr" not in raw:
            raw["dst_addr"] = raw["raddr"]
    if with_pretty:
        if parsed is not None:
            d["raw_pretty"] = json.dumps(parsed, indent=2, ensure_ascii=False)
        else:
            d["raw_pretty"] = d.get("raw_json", "")
    return d
