"""Detector のエントリポイント。

config を読んでルールをロードし、評価エンジンを起動する。
起動時と次回起動時に retention 期限切れの events を消す。
"""
import argparse
import sys
from pathlib import Path

from ursus.common.config import load_config
from ursus.common.db import get_connection, init_schema, purge_old_events
from ursus.common.logging import get_logger, setup_logging
from ursus.common.signals import setup_signal_handlers
from ursus.detector.engine import DetectionEngine
from ursus.detector.responses import ResponseHandler
from ursus.detector.rule_loader import load_rules


def run():
    parser = argparse.ArgumentParser(prog="ursus-detector")
    parser.add_argument("--config", type=Path, default=Path("config.yml"))
    args = parser.parse_args()

    config = load_config(args.config)
    setup_logging(level=config.logging.level, format=config.logging.format)
    log = get_logger("detector.main")

    if not config.detector.enabled:
        log.info("detector_disabled")
        return

    # スキーマ初期化と古いイベントの掃除。
    conn = get_connection(config.database.path)
    try:
        init_schema(conn)
        purged = purge_old_events(conn, config.database.retention_days)
        if purged:
            log.info("retention_purged", count=purged)
    finally:
        conn.close()

    rules = load_rules(config.detector.rules_dir)
    log.info("rules_loaded", count=len(rules))

    response = ResponseHandler(
        dry_run=config.detector.response.dry_run,
        allowed_actions=config.detector.response.allowed_actions,
    )
    if not response.dry_run:
        risky = set(config.detector.response.allowed_actions) - {"alert"}
        if risky:
            log.warning("destructive_actions_enabled", actions=sorted(risky))

    stop_event = setup_signal_handlers()
    engine = DetectionEngine(
        db_path=config.database.path,
        rules=rules,
        response_handler=response,
        poll_interval=config.detector.poll_interval_sec,
    )

    log.info("detector_starting", db_path=config.database.path,
             dry_run=response.dry_run)
    engine.run(stop_event)
    log.info("detector_stopped")
    sys.exit(0)


if __name__ == "__main__":
    run()
