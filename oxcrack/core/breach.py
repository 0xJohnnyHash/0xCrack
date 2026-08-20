"""
breach.py  —  DIFFERENTIATOR #2: offline breach check
=====================================================
When 0xCrack recovers a password, it instantly checks it against a bundled list
of the most-leaked passwords in the world (offline, no network). If it's there,
that's a critical finding: the password would fall to *any* attacker's very
first wordlist.

The list ships in `data/common_passwords.txt`. Swap it for the full SecLists
top-N to make the check stronger — the loader auto-detects rank by line order.
"""

from __future__ import annotations

import os
from functools import lru_cache

_DATA = os.path.join(os.path.dirname(__file__), "..", "..", "data",
                     "common_passwords.txt")


@lru_cache(maxsize=1)
def _load() -> dict[str, int]:
    """Return {password: rank} where rank 1 = most common."""
    mapping: dict[str, int] = {}
    try:
        with open(os.path.abspath(_DATA), "r", encoding="utf-8",
                  errors="ignore") as fh:
            rank = 0
            for line in fh:
                pw = line.rstrip("\r\n")
                if not pw:
                    continue
                rank += 1
                mapping.setdefault(pw, rank)
    except OSError:
        pass
    return mapping


def check(password: str) -> int | None:
    """Return the rank (1-based) if the password is in the breach list, else None."""
    if not password:
        return None
    return _load().get(password)


def is_breached(password: str) -> bool:
    return check(password) is not None


def list_size() -> int:
    return len(_load())
