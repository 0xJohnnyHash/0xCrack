"""
estimator.py  —  DIFFERENTIATOR #1: crack-time estimator
========================================================
Before launching an attack, 0xCrack benchmarks how fast the target algorithm
hashes on THIS machine, counts the candidate space (wordlist x rules) and tells
you the worst-case time to exhaust it. After a hash is cracked, it also reports
the theoretical brute-force time of the recovered password (an audit metric).

This turns a blind "let's hope it cracks" into an informed decision.
"""

from __future__ import annotations

import math
import time
from dataclasses import dataclass

from .hashers import make_candidate_checker, ALGORITHMS
from .engine import _rule_variants  # reuse the same mangling expansion


@dataclass
class TimeEstimate:
    algorithm: str
    hashrate: float           # hashes/second measured on this machine
    candidates: int           # total candidates to try (wordlist x rules)
    seconds_worst: float      # time to exhaust the whole space
    is_slow: bool


def benchmark_hashrate(algorithm: str, sample: str = "benchmark123",
                       iterations: int = 20000) -> float:
    """Measure hashes/second for an algorithm on this machine (quick probe)."""
    if algorithm not in ALGORITHMS:
        return 0.0
    # For slow hashes (bcrypt/sha*crypt) we run far fewer iterations.
    is_slow = ALGORITHMS[algorithm]["kind"] == "verify"
    n = 200 if is_slow else iterations

    # The whole probe is wrapped: a benchmark must NEVER crash the run.
    try:
        spec = ALGORITHMS[algorithm]
        if spec["kind"] == "hex":
            target = spec["fn"](sample)
        else:
            # create a real salted hash to verify against
            if algorithm == "bcrypt":
                import bcrypt as _bc
                target = _bc.hashpw(sample.encode("utf-8")[:72],
                                    _bc.gensalt(rounds=8)).decode("utf-8")
            elif algorithm == "sha512crypt":
                from passlib.hash import sha512_crypt
                target = sha512_crypt.using(rounds=5000).hash(sample)
            elif algorithm == "sha256crypt":
                from passlib.hash import sha256_crypt
                target = sha256_crypt.using(rounds=5000).hash(sample)
            else:
                return 0.0
        check = make_candidate_checker(algorithm, target)

        start = time.perf_counter()
        for i in range(n):
            check("warmup_%d" % i)
        elapsed = time.perf_counter() - start
    except Exception:
        return 0.0
    return n / elapsed if elapsed > 0 else 0.0


def count_candidates(wordlist_path: str, rules: set[str] | None) -> int:
    """Count how many candidates the wordlist (with rules) will produce."""
    rules = rules or set()
    if not rules:
        try:
            with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as fh:
                return sum(1 for line in fh if line.strip())
        except OSError:
            return 0
    # With rules we must expand a sample to get the multiplier, then scale.
    total = 0
    try:
        with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                w = line.strip()
                if not w:
                    continue
                total += sum(1 for _ in _rule_variants(w, rules))
    except OSError:
        return 0
    return total


def estimate(algorithm: str, wordlist_path: str,
             rules: set[str] | None) -> TimeEstimate:
    rate = benchmark_hashrate(algorithm)
    candidates = count_candidates(wordlist_path, rules)
    seconds = candidates / rate if rate > 0 else float("inf")
    is_slow = ALGORITHMS.get(algorithm, {}).get("kind") == "verify"
    return TimeEstimate(algorithm, rate, candidates, seconds, is_slow)


def human_time(seconds: float) -> str:
    """Human-friendly duration."""
    if seconds == float("inf"):
        return "unknown"
    if seconds < 1:
        return f"{seconds*1000:.0f} ms"
    if seconds < 60:
        return f"{seconds:.1f} s"
    if seconds < 3600:
        return f"{seconds/60:.1f} min"
    if seconds < 86400:
        return f"{seconds/3600:.1f} h"
    if seconds < 31536000:
        return f"{seconds/86400:.1f} days"
    years = seconds / 31536000
    if years > 1e6:
        return f"{years:.1e} years"
    return f"{years:.1f} years"


def human_rate(rate: float) -> str:
    if rate >= 1e9:
        return f"{rate/1e9:.1f} GH/s"
    if rate >= 1e6:
        return f"{rate/1e6:.1f} MH/s"
    if rate >= 1e3:
        return f"{rate/1e3:.1f} kH/s"
    return f"{rate:.0f} H/s"


# ---- Post-crack strength: theoretical brute-force time of a password --------
def password_bruteforce_time(password: str, guesses_per_sec: float = 1e10) -> str:
    """
    Assuming a fast offline attacker (10 billion guesses/s by default),
    how long to brute-force this exact password? Used in the audit output.
    """
    if not password:
        return "instant"
    charset = 0
    import re
    if re.search(r"[a-z]", password): charset += 26
    if re.search(r"[A-Z]", password): charset += 26
    if re.search(r"[0-9]", password): charset += 10
    if re.search(r"[^a-zA-Z0-9]", password): charset += 33
    charset = max(charset, 1)
    combos = charset ** len(password)
    seconds = combos / guesses_per_sec / 2  # average = half the space
    return human_time(seconds)
