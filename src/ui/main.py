"""UI エントリポイント。

FastAPI + Jinja2 で SQLite を読み取り専用に閲覧する。bind_host は
config 側で loopback 強制済み。

uvicorn が SIGINT/SIGTERM を捕捉するので、こちらで signal handler は
入れない。
"""
import argparse
from datetime import datetime
from pathlib import Path

import uvicorn
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from ursus.common.config import load_config
from ursus.common.logging import get_logger, setup_logging
from ursus.ui.routes.alerts import router as alerts_router
from ursus.ui.routes.dashboard import router as dashboard_router
from ursus.ui.routes.events import router as events_router
from ursus.ui.routes.process_tree import router as process_tree_router
from ursus.ui.routes.settings import router as settings_router

BASE_DIR = Path(__file__).resolve().parent


def _fmt_ts(ts):
    if ts is None:
        return ""
    return datetime.fromtimestamp(float(ts)).strftime("%Y-%m-%d %H:%M:%S")


def _fmt_ts_short(ts):
    if ts is None:
        return ""
    return datetime.fromtimestamp(float(ts)).strftime("%H:%M:%S")


SEV_BADGE = {
    "low":      "bg-slate-100 text-slate-600",
    "medium":   "bg-amber-100 text-amber-800",
    "high":     "bg-red-100 text-red-800",
    "critical": "bg-red-700 text-white",
}
SEV_BORDER = {
    "low":      "border-l-slate-400",
    "medium":   "border-l-amber-500",
    "high":     "border-l-red-500",
    "critical": "border-l-red-700",
}
TYPE_BADGE = {
    "process": "bg-blue-100 text-blue-700",
    "file":    "bg-emerald-100 text-emerald-700",
    "network": "bg-purple-100 text-purple-700",
    "auth":    "bg-amber-100 text-amber-700",
}


def create_app(config, config_path):
    templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))
    templates.env.filters["fmt_ts"] = _fmt_ts
    templates.env.filters["fmt_ts_short"] = _fmt_ts_short
    templates.env.globals["SEV_BADGE"] = SEV_BADGE
    templates.env.globals["SEV_BORDER"] = SEV_BORDER
    templates.env.globals["TYPE_BADGE"] = TYPE_BADGE

    app = FastAPI(title="ursus", docs_url=None, redoc_url=None, openapi_url=None)
    app.state.config = config
    app.state.config_path = Path(config_path).resolve()
    app.state.templates = templates
    app.mount(
        "/static",
        StaticFiles(directory=str(BASE_DIR / "static")),
        name="static",
    )
    app.include_router(dashboard_router)
    app.include_router(events_router)
    app.include_router(alerts_router)
    app.include_router(process_tree_router)
    app.include_router(settings_router)
    return app


def run():
    parser = argparse.ArgumentParser(prog="ursus-ui")
    parser.add_argument("--config", type=Path, default=Path("config.yml"))
    args = parser.parse_args()

    config = load_config(args.config)
    setup_logging(level=config.logging.level, format=config.logging.format)
    log = get_logger("ui.main")

    # DB スキーマの初期化 (sensor 起動前でも UI が動けるようにする)
    from ursus.common.db import get_connection, init_schema
    conn = get_connection(config.database.path)
    try:
        init_schema(conn)
    finally:
        conn.close()

    app = create_app(config, args.config)
    log.info("ui_starting", host=config.ui.bind_host, port=config.ui.bind_port)
    uvicorn.run(
        app,
        host=config.ui.bind_host,
        port=config.ui.bind_port,
        log_level=config.logging.level.lower(),
        access_log=False,
    )


if __name__ == "__main__":
    run()
