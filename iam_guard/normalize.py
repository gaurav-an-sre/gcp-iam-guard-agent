"""Tolerant readers for collected inventories.

Collected data comes from JSON fixtures and from proto responses that both happily
carry ``null`` where a list or an object is expected, and numbers where a string is
expected. Every rule engine reads its input through these helpers so a single
malformed record degrades that one rule instead of aborting the whole analysis.
"""

from __future__ import annotations

from typing import Any


def mapping(container: dict[str, Any], key: str) -> dict[str, Any]:
    """Reads ``key`` as an object, tolerating null and scalars."""
    value = container.get(key)
    return value if isinstance(value, dict) else {}


def dicts(container: dict[str, Any], key: str) -> list[dict[str, Any]]:
    """Reads ``key`` as a list of objects, tolerating null, scalars and junk items."""
    value = container.get(key)
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def strings(container: dict[str, Any], key: str) -> list[str]:
    """Reads ``key`` as a list of strings, dropping anything that is not a string."""
    value = container.get(key)
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str)]


def text(container: dict[str, Any], key: str, default: str = "") -> str:
    """Reads ``key`` as a non-empty string, falling back to ``default``."""
    value = container.get(key)
    return value if isinstance(value, str) and value else default


def number(container: dict[str, Any], key: str, default: float = 0.0) -> float:
    """Reads ``key`` as a float, tolerating numeric strings, null and junk."""
    value = container.get(key)
    if isinstance(value, bool):
        return default
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value)
        except ValueError:
            return default
    return default
