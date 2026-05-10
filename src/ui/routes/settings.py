"""設定ページ。config.yml を GUI から編集する。

- GET /settings: 現在の設定をフォームに展開してレンダリング
- POST /settings: JSON ボディを受け取り Pydantic 検証 → config.yml をアトミック更新

設定変更は **保存後に各プロセスを再起動するまで反映されない**。学習用途
としてはこの "再読み込みを意識する" 体験自体に価値があると考え、ホット
リロードはあえて実装していない。
"""
from pathlib import Path

import yaml
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from pydantic import ValidationError

from ursus.common.config import Config, load_config
from ursus.common.logging import get_logger

router = APIRouter()
log = get_logger("ui.settings")


@router.get("/settings")
async def settings_page(request: Request):
    config_path: Path = request.app.state.config_path
    templates = request.app.state.templates

    # ディスク上の最新を読み直す（プロセス起動後に手動編集された場合に対応）
    try:
        current = load_config(config_path)
    except Exception as e:
        # 既存 config が壊れていても画面は出す（デフォルトで埋める）
        log.exception("config_load_failed", error=str(e))
        current = Config()

    raw_text = ""
    if config_path.exists():
        try:
            raw_text = config_path.read_text(encoding="utf-8")
        except OSError:
            raw_text = ""

    return templates.TemplateResponse(
        request,
        "settings.html",
        {
            "active_page": "settings",
            "cfg": current.model_dump(),
            "config_path": str(config_path),
            "raw_text": raw_text,
        },
    )


@router.post("/settings")
async def save_settings(request: Request):
    config_path: Path = request.app.state.config_path

    try:
        payload = await request.json()
    except Exception:
        return JSONResponse(
            status_code=400,
            content={"ok": False, "error": "invalid_json"},
        )

    # Pydantic で構造を検証。bind_host のループバック制約もここで弾かれる。
    try:
        new_config = Config.model_validate(payload)
    except ValidationError as e:
        return JSONResponse(
            status_code=400,
            content={
                "ok": False,
                "error": "validation",
                "details": [
                    {"loc": ".".join(str(x) for x in err["loc"]), "msg": err["msg"]}
                    for err in e.errors()
                ],
            },
        )

    yaml_text = _dump_config_yaml(new_config)

    # アトミック書き込み。途中で中断しても古い config が残るように tmp → rename。
    try:
        config_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = config_path.with_suffix(config_path.suffix + ".tmp")
        tmp.write_text(yaml_text, encoding="utf-8")
        tmp.replace(config_path)
    except OSError as e:
        log.exception("config_write_failed", path=str(config_path), error=str(e))
        return JSONResponse(
            status_code=500,
            content={"ok": False, "error": "write_failed", "details": str(e)},
        )

    log.info("config_saved", path=str(config_path))
    return JSONResponse({
        "ok": True,
        "message": "保存しました。sensor / detector / ui の各プロセスを再起動すると新しい設定が反映されます。",
    })


# --- YAML 書き出し ---------------------------------------------------------

def _dump_config_yaml(config: Config) -> str:
    """Config モデルを config.yml 形式の文字列に変換する。

    PyYAML は読み書きでコメントを保持できないため、URSUS の正規コメントを
    こちら側で再生成する。学習教材としての可読性を保つための妥協。
    """
    d = config.model_dump()

    parts: list[str] = []
    parts.append("# ursus configuration (managed via Settings UI)")
    parts.append("")
    parts.append(_dump_section({"database": d["database"]}))
    parts.append("")
    parts.append("sensor:")
    parts.append(f"  hostname: {_yaml_str(d['sensor']['hostname'])}")
    parts.append("")
    parts.append("  # プロセス監視: netlink (cn_proc) で exec(2) を購読する。root が必要。")
    parts.append(_dump_subsection({"process": d["sensor"]["process"]}, indent=2))
    parts.append("")
    parts.append("  # ファイル監視: watchdog (inotify) でディレクトリ再帰監視。")
    parts.append(_dump_subsection({"file": d["sensor"]["file"]}, indent=2))
    parts.append("")
    parts.append("  # ネットワーク監視: psutil で TCP 接続テーブルをポーリング。")
    parts.append(_dump_subsection({"network": d["sensor"]["network"]}, indent=2))
    parts.append("")
    parts.append("  # 認証ログ監視: systemd-journald を journalctl 経由で購読する。")
    parts.append(_dump_subsection({"auth": d["sensor"]["auth"]}, indent=2))
    parts.append("")
    parts.append(_dump_section({"detector": d["detector"]}))
    parts.append("")
    parts.append(_dump_section({"ui": d["ui"]}))
    parts.append("")
    parts.append(_dump_section({"logging": d["logging"]}))
    return "\n".join(parts) + "\n"


def _dump_section(obj: dict) -> str:
    return yaml.safe_dump(
        obj, sort_keys=False, allow_unicode=True, default_flow_style=False
    ).rstrip()


def _dump_subsection(obj: dict, indent: int) -> str:
    raw = _dump_section(obj)
    pad = " " * indent
    return "\n".join(pad + line for line in raw.splitlines())


def _yaml_str(s: str) -> str:
    """単一スカラーを YAML 安全表現に変換する。

    safe_dump は単独スカラーに対して "value\\n...\\n" を返すため、末尾の
    YAML doc end (...) と空白を削って 1 行表現にする。
    """
    raw = yaml.safe_dump(s, default_flow_style=True).rstrip()
    if raw.endswith("..."):
        raw = raw[:-3].rstrip()
    return raw
