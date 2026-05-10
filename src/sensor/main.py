"""Sensor のエントリポイント。

config を読んで DB スキーマを初期化し、有効なコレクタを別スレッドで起動する。
process / file / network / auth の各 collector を別スレッドで動かす。
"""
import argparse
import sys
import threading
from pathlib import Path

from ursus.common.config import load_config
from ursus.common.db import get_connection, init_schema
from ursus.common.logging import get_logger, setup_logging
from ursus.common.signals import setup_signal_handlers


def _start_process_collector(config, db_path, hostname, stop_event, log):
    from ursus.sensor.process_collector_netlink import NetlinkProcessCollector
    collector = NetlinkProcessCollector(db_path, hostname)
    t = threading.Thread(
        target=collector.run, args=(stop_event,), name="process-collector"
    )
    t.start()
    log.info("collector_started", name="process")
    return t


def _start_file_collector(config, db_path, hostname, stop_event, log):
    from ursus.sensor.file_collector import FileCollector
    collector = FileCollector(
        db_path, hostname,
        watch_paths=config.sensor.file.watch_paths,
        exclude_patterns=config.sensor.file.exclude_patterns,
        modify_debounce_sec=config.sensor.file.modify_debounce_sec,
    )
    t = threading.Thread(
        target=collector.run, args=(stop_event,), name="file-collector"
    )
    t.start()
    log.info(
        "collector_started",
        name="file",
        watch_paths=config.sensor.file.watch_paths,
        exclude_patterns=config.sensor.file.exclude_patterns,
    )
    return t


def _start_network_collector(config, db_path, hostname, stop_event, log):
    from ursus.sensor.network_collector import NetworkCollector
    collector = NetworkCollector(
        db_path, hostname,
        poll_interval_sec=config.sensor.network.poll_interval_sec,
        established_debounce_sec=config.sensor.network.established_debounce_sec,
    )
    t = threading.Thread(
        target=collector.run, args=(stop_event,), name="network-collector"
    )
    t.start()
    log.info(
        "collector_started",
        name="network",
        poll_interval_sec=config.sensor.network.poll_interval_sec,
    )
    return t


def _start_auth_collector(config, db_path, hostname, stop_event, log):
    from ursus.sensor.journal_auth_collector import JournalAuthCollector
    collector = JournalAuthCollector(
        db_path, hostname,
        units=config.sensor.auth.journal_units,
        comms=config.sensor.auth.journal_comms,
    )
    meta = {
        "journal_units": config.sensor.auth.journal_units,
        "journal_comms": config.sensor.auth.journal_comms,
    }
    t = threading.Thread(
        target=collector.run, args=(stop_event,), name="auth-collector"
    )
    t.start()
    log.info("collector_started", name="auth", **meta)
    return t


def run():
    parser = argparse.ArgumentParser(prog="ursus-sensor")
    parser.add_argument("--config", type=Path, default=Path("config.yml"))
    args = parser.parse_args()

    config = load_config(args.config)
    setup_logging(level=config.logging.level, format=config.logging.format)
    log = get_logger("sensor.main")

    hostname = config.sensor.resolved_hostname()
    db_path = config.database.path

    conn = get_connection(db_path)
    try:
        init_schema(conn)
    finally:
        conn.close()

    log.info("sensor_starting", hostname=hostname, db_path=db_path)
    stop_event = setup_signal_handlers()

    threads = []
    if config.sensor.process.enabled:
        threads.append(_start_process_collector(config, db_path, hostname, stop_event, log))
    else:
        log.info("collector_skipped", name="process")

    if config.sensor.file.enabled:
        threads.append(_start_file_collector(config, db_path, hostname, stop_event, log))
    else:
        log.info("collector_skipped", name="file")

    if config.sensor.network.enabled:
        threads.append(_start_network_collector(config, db_path, hostname, stop_event, log))
    else:
        log.info("collector_skipped", name="network")

    if config.sensor.auth.enabled:
        threads.append(_start_auth_collector(config, db_path, hostname, stop_event, log))
    else:
        log.info("collector_skipped", name="auth")

    # シグナル待ち。
    while not stop_event.is_set():
        stop_event.wait(1.0)

    log.info("sensor_stopping")
    for t in threads:
        t.join(timeout=10.0)
        if t.is_alive():
            log.warning("collector_stop_timeout", name=t.name)
    log.info("sensor_stopped")
    sys.exit(0)


if __name__ == "__main__":
    run()
