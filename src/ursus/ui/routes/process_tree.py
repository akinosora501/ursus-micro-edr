"""プロセスツリー再構成。

events 表の process イベントから ppid->pid を辿って入れ子辞書を組み立てる。
親不明ノードは仮想ルート [unknown] 配下にまとめる。
"""
from fastapi import APIRouter, Request

from ursus.common.db import get_connection

router = APIRouter()

WINDOW_BEFORE = 300  # 5 分前から
WINDOW_AFTER = 60    # 1 分後まで


@router.get("/process-tree")
async def process_tree(
    request: Request,
    at_timestamp: float | None = None,
    from_alert_id: int | None = None,
):
    config = request.app.state.config
    templates = request.app.state.templates

    target_ts = at_timestamp
    alert_info = None

    conn = get_connection(config.database.path)
    try:
        if from_alert_id is not None:
            row = conn.execute(
                "SELECT a.id AS alert_id, a.rule_id, a.rule_title, a.severity, "
                "       e.timestamp, e.pid, e.process_name "
                "FROM alerts a JOIN events e ON e.id = a.triggered_event_id "
                "WHERE a.id = ?",
                (from_alert_id,),
            ).fetchone()
            if row:
                alert_info = dict(row)
                target_ts = row["timestamp"]

        nodes = []
        if target_ts is not None:
            rows = conn.execute(
                "SELECT id, pid, ppid, process_name, parent_process_name, "
                "       cmdline, user, timestamp "
                "FROM events WHERE event_type='process' "
                "AND timestamp BETWEEN ? AND ? ORDER BY timestamp ASC",
                (target_ts - WINDOW_BEFORE, target_ts + WINDOW_AFTER),
            ).fetchall()
            nodes = [dict(r) for r in rows]
    finally:
        conn.close()

    tree = _build_tree(nodes)
    highlight_pid = alert_info["pid"] if alert_info else None

    return templates.TemplateResponse(
        request,
        "process_tree.html",
        {
            "active_page": "process-tree",
            "tree": tree,
            "target_ts": target_ts,
            "alert_info": alert_info,
            "node_count": len(nodes),
            "highlight_pid": highlight_pid,
        },
    )


def _build_tree(nodes):
    """同じ pid が複数現れたら最後のレコードを採用。親不明は [unknown] へ。"""
    by_pid = {}
    for n in nodes:
        by_pid[n["pid"]] = {**n, "children": []}

    real_roots = []
    orphans = {
        "pid": None,
        "ppid": None,
        "process_name": "[unknown]",
        "cmdline": "親プロセスがイベントウィンドウ外",
        "user": None,
        "timestamp": None,
        "children": [],
    }
    for pid, node in by_pid.items():
        ppid = node["ppid"]
        if ppid in by_pid and ppid != pid:
            by_pid[ppid]["children"].append(node)
        elif ppid is None or ppid == 0:
            real_roots.append(node)
        else:
            orphans["children"].append(node)

    if orphans["children"]:
        return [orphans] + real_roots
    return real_roots
