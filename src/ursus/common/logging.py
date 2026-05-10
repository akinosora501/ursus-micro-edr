"""構造化ログ。

使い方:
    log = get_logger("sensor.process")
    log.info("process_collected", pid=4567, process_name="bash")

format=json なら1行JSON、format=text なら人間可読な1行で出る。
"""
import json
import logging
import sys
from datetime import datetime, timezone


class JSONFormatter(logging.Formatter):
    def format(self, record):
        ts = datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat()
        payload = {
            "ts": ts,
            "level": record.levelname,
            "component": getattr(record, "component", record.name),
            "event": record.getMessage(),
        }
        payload.update(getattr(record, "fields", {}))
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False, default=str)


class TextFormatter(logging.Formatter):
    def format(self, record):
        ts = datetime.fromtimestamp(record.created, tz=timezone.utc).strftime("%H:%M:%S")
        component = getattr(record, "component", record.name)
        fields = getattr(record, "fields", {})
        extras = " ".join(f"{k}={v!r}" for k, v in fields.items())
        line = f"{ts} {record.levelname:<5} {component} {record.getMessage()}"
        if extras:
            line += " " + extras
        if record.exc_info:
            line += "\n" + self.formatException(record.exc_info)
        return line


class StructLogger:
    """stdlib logger に構造化フィールドを乗せる薄いラッパ。"""

    def __init__(self, component):
        self.component = component
        self._logger = logging.getLogger(f"ursus.{component}")

    def _log(self, level, event, fields, exc_info=False):
        self._logger.log(
            level, event,
            extra={"component": self.component, "fields": fields},
            exc_info=exc_info,
        )

    def debug(self, event, **fields): self._log(logging.DEBUG, event, fields)
    def info(self, event, **fields): self._log(logging.INFO, event, fields)
    def warning(self, event, **fields): self._log(logging.WARNING, event, fields)
    def error(self, event, **fields): self._log(logging.ERROR, event, fields)
    def exception(self, event, **fields): self._log(logging.ERROR, event, fields, exc_info=True)


def setup_logging(level="INFO", format="json"):
    root = logging.getLogger()
    for h in list(root.handlers):
        root.removeHandler(h)
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(JSONFormatter() if format == "json" else TextFormatter())
    root.addHandler(handler)
    root.setLevel(level)


def get_logger(component):
    return StructLogger(component)
