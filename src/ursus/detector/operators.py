"""ルール条件で使う比較演算子。

各演算子は (event_value, rule_value) -> bool の純粋関数。
event_value が None の場合の扱いはオペレータごとに固定。
"""
import re
from functools import lru_cache


@lru_cache(maxsize=256)
def _compile(pattern):
    return re.compile(pattern)


def op_eq(a, b): return a == b
def op_neq(a, b): return a != b
def op_in(a, b): return a in b
def op_not_in(a, b): return a not in b
def op_contains(a, b): return a is not None and b in str(a)
def op_startswith(a, b): return a is not None and str(a).startswith(b)
def op_endswith(a, b): return a is not None and str(a).endswith(b)
def op_exists(a, b): return a is not None


def op_regex(a, b):
    if a is None:
        return False
    return _compile(b).search(str(a)) is not None


def op_gt(a, b):
    try:
        return float(a) > float(b)
    except (TypeError, ValueError):
        return False


def op_lt(a, b):
    try:
        return float(a) < float(b)
    except (TypeError, ValueError):
        return False


OPERATORS = {
    "eq": op_eq,
    "neq": op_neq,
    "in": op_in,
    "not_in": op_not_in,
    "regex": op_regex,
    "contains": op_contains,
    "startswith": op_startswith,
    "endswith": op_endswith,
    "gt": op_gt,
    "lt": op_lt,
    "exists": op_exists,
}
