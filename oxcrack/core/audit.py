"""
audit.py
========
EL DIFERENCIADOR de 0xCrack.

hashcat y John te devuelven contrasenas. 0xCrack ademas te dice QUE SIGNIFICAN
para la seguridad de la organizacion: patrones, reuso, debilidad estructural y
cumplimiento de politica. Convierte un ejercicio ofensivo (red team) en un
entregable defensivo (blue team) — el combo que buscan los reclutadores.

Salida: un objeto AuditReport serializable a JSON + un informe HTML autonomo.
"""

from __future__ import annotations

import json
import math
import re
from collections import Counter
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Optional


# ---------------------------------------------------------------------------
# Politica de contrasenas evaluada (configurable). Valores por defecto tipo
# NIST/CIS razonables para una auditoria corporativa.
# ---------------------------------------------------------------------------
@dataclass
class PasswordPolicy:
    min_length: int = 12
    require_upper: bool = True
    require_lower: bool = True
    require_digit: bool = True
    require_symbol: bool = True
    ban_common: bool = True


COMMON_PASSWORDS = {
    "123456", "password", "123456789", "12345678", "12345", "qwerty",
    "abc123", "111111", "1234567", "password1", "admin", "welcome",
    "monkey", "letmein", "dragon", "iloveyou", "sunshine", "princess",
    "qwerty123", "000000", "root", "toor", "changeme", "secret", "p@ssw0rd",
}

_SEASONS = ("spring", "summer", "autumn", "fall", "winter",
            "primavera", "verano", "otono", "invierno")
_KEYBOARD_WALKS = ("qwerty", "asdf", "zxcv", "1234", "qazwsx", "qwertz")


# ---------------------------------------------------------------------------
# Estimacion de fuerza. zxcvbn si esta disponible; si no, entropia por charset.
# ---------------------------------------------------------------------------
def _charset_size(pw: str) -> int:
    size = 0
    if re.search(r"[a-z]", pw):
        size += 26
    if re.search(r"[A-Z]", pw):
        size += 26
    if re.search(r"[0-9]", pw):
        size += 10
    if re.search(r"[^a-zA-Z0-9]", pw):
        size += 33
    return size or 1


def estimate_entropy_bits(pw: str) -> float:
    """Entropia teorica (bits) = longitud * log2(tamano del charset)."""
    if not pw:
        return 0.0
    return round(len(pw) * math.log2(_charset_size(pw)), 1)


def strength_label(bits: float) -> str:
    if bits < 28:
        return "Very weak"
    if bits < 36:
        return "Weak"
    if bits < 60:
        return "Reasonable"
    if bits < 128:
        return "Strong"
    return "Very strong"


# ---------------------------------------------------------------------------
# Analisis por contrasena
# ---------------------------------------------------------------------------
def _analyze_password(pw: str, policy: PasswordPolicy) -> dict:
    lower = pw.lower()
    bits = estimate_entropy_bits(pw)
    issues = []

    if len(pw) < policy.min_length:
        issues.append(f"length < {policy.min_length}")
    if policy.require_upper and not re.search(r"[A-Z]", pw):
        issues.append("no uppercase")
    if policy.require_lower and not re.search(r"[a-z]", pw):
        issues.append("no lowercase")
    if policy.require_digit and not re.search(r"[0-9]", pw):
        issues.append("no digits")
    if policy.require_symbol and not re.search(r"[^a-zA-Z0-9]", pw):
        issues.append("no symbols")
    if policy.ban_common and lower in COMMON_PASSWORDS:
        issues.append("in top common-passwords list")

    patterns = []
    if re.search(r"(19|20)\d{2}", pw):
        patterns.append("contains year")
    if any(s in lower for s in _SEASONS):
        patterns.append("season/month")
    if any(k in lower for k in _KEYBOARD_WALKS):
        patterns.append("keyboard walk")
    if re.search(r"\d{1,4}$", pw) and re.search(r"^[A-Za-z]", pw):
        patterns.append("word + trailing digits")
    if re.match(r"^[A-Z][a-z]+[0-9!@#$]*$", pw):
        patterns.append("Capitalized + suffix (predictable)")

    return {
        "password": pw,
        "length": len(pw),
        "entropy_bits": bits,
        "strength": strength_label(bits),
        "policy_issues": issues,
        "patterns": patterns,
        "compliant": len(issues) == 0,
    }


@dataclass
class AuditReport:
    generated_at: str
    analyst: str
    total_hashes: int
    cracked_count: int
    crack_rate: float
    policy: dict
    per_password: list = field(default_factory=list)
    stats: dict = field(default_factory=dict)
    findings: list = field(default_factory=list)

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(asdict(self), indent=indent, ensure_ascii=False)


def build_report(
    results,                 # list[CrackResult]
    total_hashes: int,
    analyst: str = "Johnny Hash (0xJohnnyHash)",
    policy: Optional[PasswordPolicy] = None,
) -> AuditReport:
    policy = policy or PasswordPolicy()
    cracked = [r for r in results if getattr(r, "cracked", False) and r.password]
    per_pw = [_analyze_password(r.password, policy) for r in cracked]

    # --- Estadisticas agregadas -------------------------------------------
    lengths = [p["length"] for p in per_pw]
    length_dist = dict(sorted(Counter(lengths).items()))
    pattern_counter = Counter()
    for p in per_pw:
        pattern_counter.update(p["patterns"])

    # Reuso: misma contrasena en varias cuentas.
    pw_counter = Counter(p["password"] for p in per_pw)
    reused = {pw: c for pw, c in pw_counter.items() if c > 1}

    avg_bits = round(sum(p["entropy_bits"] for p in per_pw) / len(per_pw), 1) if per_pw else 0.0
    weak = [p for p in per_pw if p["entropy_bits"] < 36]
    noncompliant = [p for p in per_pw if not p["compliant"]]

    # Offline breach check (differentiator): flag cracked passwords that appear
    # in the bundled most-leaked list, and record their rank per password.
    from . import breach
    breached = {}
    for p in per_pw:
        rank = breach.check(p["password"])
        p["breach_rank"] = rank
        if rank:
            breached[p["password"]] = rank

    stats = {
        "length_distribution": length_dist,
        "avg_length": round(sum(lengths) / len(lengths), 1) if lengths else 0,
        "avg_entropy_bits": avg_bits,
        "weak_count": len(weak),
        "noncompliant_count": len(noncompliant),
        "reused_passwords": reused,
        "breached_count": len(breached),
        "breached_passwords": breached,
        "top_patterns": pattern_counter.most_common(8),
        "top_base_words": _top_base_words(cracked),
    }

    findings = _derive_findings(len(cracked), total_hashes, stats, per_pw, policy)

    return AuditReport(
        generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        analyst=analyst,
        total_hashes=total_hashes,
        cracked_count=len(cracked),
        crack_rate=round(100.0 * len(cracked) / total_hashes, 1) if total_hashes else 0.0,
        policy=asdict(policy),
        per_password=per_pw,
        stats=stats,
        findings=findings,
    )


def _top_base_words(cracked) -> list:
    """Extrae la 'raiz' alfabetica de cada contrasena para ver palabras base."""
    counter = Counter()
    for r in cracked:
        base = re.sub(r"[^a-zA-Z]", "", r.password).lower()
        if len(base) >= 3:
            counter[base] += 1
    return counter.most_common(10)


def _derive_findings(cracked, total, stats, per_pw, policy) -> list:
    """Turn raw numbers into prioritized findings with severity + remediation."""
    findings = []

    rate = 100.0 * cracked / total if total else 0.0
    if rate >= 50:
        sev = "CRITICAL"
    elif rate >= 25:
        sev = "HIGH"
    elif rate >= 10:
        sev = "MEDIUM"
    else:
        sev = "LOW"
    findings.append({
        "severity": sev,
        "title": f"{cracked}/{total} hashes cracked ({rate:.1f}%)",
        "detail": "Share of credentials recovered with a dictionary attack. "
                  "A high ratio means predictable passwords or a weak policy.",
        "remediation": "Force a reset on the affected accounts and raise the "
                       "complexity/length policy.",
    })

    if stats["reused_passwords"]:
        findings.append({
            "severity": "HIGH",
            "title": f"{len(stats['reused_passwords'])} passwords reused across accounts",
            "detail": "Reuse enables lateral movement: compromising one account "
                      "compromises every account sharing the password.",
            "remediation": "Ban reuse, enable duplicate detection and consider MFA.",
        })

    if stats.get("breached_count"):
        findings.append({
            "severity": "CRITICAL",
            "title": f"{stats['breached_count']} password(s) found in public breach lists",
            "detail": "These passwords appear in the world's most-leaked lists, "
                      "so they fall to any attacker's very first wordlist.",
            "remediation": "Reset immediately and block these passwords at creation "
                           "time via a breached-password screen.",
        })

    if stats["weak_count"]:
        findings.append({
            "severity": "MEDIUM",
            "title": f"{stats['weak_count']} passwords below 36 bits of entropy",
            "detail": "They crack in seconds/minutes even without a GPU.",
            "remediation": f"Require at least {policy.min_length} characters and "
                           "block common-password lists.",
        })

    if stats["top_patterns"]:
        top = ", ".join(f"{p} ({c})" for p, c in stats["top_patterns"][:3])
        findings.append({
            "severity": "MEDIUM",
            "title": "Dominant predictable patterns",
            "detail": f"Most frequent: {top}. Patterns like 'Word+Year!' shrink "
                      "the search space dramatically.",
            "remediation": "Awareness training + a validator that rejects common "
                           "patterns at password-creation time.",
        })

    order = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    findings.sort(key=lambda f: order.index(f["severity"]), reverse=True)
    return findings
