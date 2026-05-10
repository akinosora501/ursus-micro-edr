"""rules/*.yml をロードして Rule のリストに変換する。

バリデーションエラーが出たルールはログを出してスキップし、他は読み続ける。
condition の構造は dict のままにする（学習用に余計な内部表現を作らない）。
"""
import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from ursus.common.logging import get_logger
from ursus.detector.operators import OPERATORS

ID_RE = re.compile(r"^R\d{3}$")
SEVERITIES = {"low", "medium", "high", "critical"}
EVENT_TYPES = {"process", "file", "network", "auth"}
MAX_CONDITION_DEPTH = 10


@dataclass
class Rule:
    id: str
    title: str
    severity: str
    event_type: str
    condition: dict
    response: list
    mitre: list = field(default_factory=list)
    enabled: bool = True


def load_rules(rules_dir):
    log = get_logger("detector.loader")
    path = Path(rules_dir)
    if not path.is_dir():
        log.warning("rules_dir_missing", path=str(path))
        return []

    rules = []
    seen = set()
    for yml in sorted(path.glob("*.yml")):
        try:
            data = yaml.safe_load(yml.read_text(encoding="utf-8"))
            rule = _build_rule(data)
        except Exception as e:
            log.error("rule_load_failed", path=str(yml), error=str(e))
            continue

        if rule.id in seen:
            log.error("rule_id_duplicate", path=str(yml), id=rule.id)
            continue
        seen.add(rule.id)
        rules.append(rule)
        log.info("rule_loaded", id=rule.id, title=rule.title, event_type=rule.event_type)
    return rules


def _build_rule(data):
    if not isinstance(data, dict):
        raise ValueError("rule must be a mapping")
    for f in ("id", "title", "severity", "event_type", "condition", "response"):
        if f not in data:
            raise ValueError(f"missing field: {f}")
    if not ID_RE.match(str(data["id"])):
        raise ValueError(f"invalid id (must match R\\d{{3}}): {data['id']}")
    if data["severity"] not in SEVERITIES:
        raise ValueError(f"invalid severity: {data['severity']}")
    if data["event_type"] not in EVENT_TYPES:
        raise ValueError(f"invalid event_type: {data['event_type']}")
    if not data["response"]:
        raise ValueError("response must be a non-empty list")

    _validate_condition(data["condition"], depth=0)

    return Rule(
        id=data["id"],
        title=data["title"],
        severity=data["severity"],
        event_type=data["event_type"],
        condition=data["condition"],
        response=list(data["response"]),
        mitre=list(data.get("mitre") or []),
        enabled=bool(data.get("enabled", True)),
    )


def _validate_condition(node, depth):
    if depth > MAX_CONDITION_DEPTH:
        raise ValueError(f"condition tree too deep (>{MAX_CONDITION_DEPTH})")
    if not isinstance(node, dict):
        raise ValueError("condition node must be a mapping")

    if "all" in node:
        for c in node["all"]:
            _validate_condition(c, depth + 1)
    elif "any" in node:
        for c in node["any"]:
            _validate_condition(c, depth + 1)
    elif "not" in node:
        _validate_condition(node["not"], depth + 1)
    else:
        # リーフノード
        if "field" not in node or "op" not in node:
            raise ValueError("leaf must have 'field' and 'op'")
        if node["op"] not in OPERATORS:
            raise ValueError(f"unknown op: {node['op']}")
