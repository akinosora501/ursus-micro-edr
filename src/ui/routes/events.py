"""イベント検索ページ。"""
import json
from datetime import datetime

from fastapi import APIRouter, Request

from ursus.common.db import get_connection

router = APIRouter()


@router.get("/events")
async def events(
    request: Request,
    type: str | None = None,
    since: str | None = None,
    until: str | None = None,
    # pid / page は HTML フォームから空文字列で送られてくることがある。
    # int で受けると FastAPI のバリデーションで 422 (raw JSON) になるため、
    # str で受けて関数内で安全に変換する。
    pid: str | None = None,
    process_name: str | None = None,
    file_path: str | None = None,
    page: str | None = None,
):
    config = request.app.state.config
    templates = request.app.state.templates
    per_page = config.ui.events_per_page

    pid_int = _safe_int(pid)
    page_int = max(_safe_int(page) or 1, 1)

    where, params = [], []
    if type:
        where.append("event_type = ?")
        params.append(type)
    if since:
        ts = _parse_iso(since)
        if ts is not None:
            where.append("timestamp >= ?")
            params.append(ts)
    if until:
        ts = _parse_iso(until)
        if ts is not None:
            where.append("timestamp < ?")
            params.append(ts)
    if pid_int is not None:
        where.append("pid = ?")
        params.append(pid_int)
    if process_name:
        where.append("process_name LIKE ?")
        params.append(f"%{process_name}%")
    if file_path:
        where.append("file_path LIKE ?")
        params.append(f"%{file_path}%")

    where_sql = ("WHERE " + " AND ".join(where)) if where else ""

    conn = get_connection(config.database.path)
    try:
        total = conn.execute(
            f"SELECT COUNT(*) FROM events {where_sql}", params
        ).fetchone()[0]
        offset = (page_int - 1) * per_page
        rows = conn.execute(
            f"SELECT * FROM events {where_sql} ORDER BY id DESC LIMIT ? OFFSET ?",
            params + [per_page, offset],
        ).fetchall()
    finally:
        conn.close()

    events_list = []
    for r in rows:
        d = dict(r)
        try:
            parsed = json.loads(r["raw_json"])
        except (TypeError, ValueError):
            parsed = None
        d["raw"] = parsed if isinstance(parsed, dict) else {}
        # 旧キー名 laddr/raddr → src_addr/dst_addr に正規化（既存 DB との後方互換）
        if d.get("event_type") == "network" and d["raw"]:
            _normalize_network_raw(d["raw"])
        if parsed is not None:
            d["raw_pretty"] = json.dumps(parsed, indent=2, ensure_ascii=False)
        else:
            d["raw_pretty"] = r["raw_json"]
        events_list.append(d)

    pages = max(1, (total + per_page - 1) // per_page)

    return templates.TemplateResponse(
        request,
        "events.html",
        {
            "active_page": "events",
            "events": events_list,
            "total": total,
            "page": page_int,
            "per_page": per_page,
            "pages": pages,
            "filters": {
                "type": type,
                "since": since,
                "until": until,
                "pid": pid_int,
                "process_name": process_name,
                "file_path": file_path,
            },
        },
    )


def _normalize_network_raw(raw: dict) -> None:
    """旧キー名 laddr/raddr を src_addr/dst_addr に正規化する。

    network_collector が旧キー名で記録したレコードに対してテンプレートが
    ev.raw.src_addr を参照できるよう、読み取り時に正規化する。
    """
    if "laddr" in raw and "src_addr" not in raw:
        raw["src_addr"] = raw["laddr"]
    if "raddr" in raw and "dst_addr" not in raw:
        raw["dst_addr"] = raw["raddr"]


def _parse_iso(s):
    try:
        return datetime.fromisoformat(s).timestamp()
    except (TypeError, ValueError):
        return None


def _safe_int(s):
    """空文字列や None、数値以外を許容して int|None を返す。

    HTML フォームの GET 送信では未入力の input が空文字列で来るため、
    int で受けると FastAPI のバリデーション 422 (JSON エラー応答) を
    返してしまう。フォームの空欄は単に "未指定" として扱う。
    """
    if s is None or s == "":
        return None
    try:
        return int(s)
    except (TypeError, ValueError):
        return None
