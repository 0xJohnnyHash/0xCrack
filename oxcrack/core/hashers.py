"""
hashers.py
==========
Funciones de hashing usadas por el motor propio de 0xCrack.

Cada algoritmo soportado expone una funcion `hash(password: str, salt) -> str`
que devuelve el digest en minusculas (hex) o el string completo (para esquemas
con sal embebida como bcrypt / sha512crypt).

El objetivo es didactico y de auditoria: implementamos los algoritmos mas
comunes que un profesional se encuentra al auditar bases de datos filtradas
o volcados de credenciales autorizados.
"""

from __future__ import annotations

import hashlib
from typing import Callable, Optional

from . import _compat  # noqa: F401  (patches bcrypt BEFORE passlib loads it)

try:
    # passlib nos da NTLM, bcrypt y sha*_crypt sin dependencias binarias.
    from passlib.hash import nthash as _nthash
    from passlib.hash import bcrypt as _bcrypt
    from passlib.hash import sha512_crypt as _sha512_crypt
    from passlib.hash import sha256_crypt as _sha256_crypt
    _HAS_PASSLIB = True
except Exception:  # pragma: no cover - passlib deberia estar instalado
    _HAS_PASSLIB = False


# ---------------------------------------------------------------------------
# Algoritmos "crudos" (sin sal): la comparacion se hace contra un digest hex.
# ---------------------------------------------------------------------------
def _simple(algo: str) -> Callable[[str], str]:
    def _fn(password: str) -> str:
        return hashlib.new(algo, password.encode("utf-8")).hexdigest()
    return _fn


def md5(password: str) -> str:
    return hashlib.md5(password.encode("utf-8")).hexdigest()


def sha1(password: str) -> str:
    return hashlib.sha1(password.encode("utf-8")).hexdigest()


def sha224(password: str) -> str:
    return hashlib.sha224(password.encode("utf-8")).hexdigest()


def sha256(password: str) -> str:
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def sha384(password: str) -> str:
    return hashlib.sha384(password.encode("utf-8")).hexdigest()


def sha512(password: str) -> str:
    return hashlib.sha512(password.encode("utf-8")).hexdigest()


def ntlm(password: str) -> str:
    """NTLM = MD4(UTF-16LE(password)). Muy comun en volcados de Windows/AD."""
    if _HAS_PASSLIB:
        return _nthash.hash(password)
    # Fallback: hashlib puede no traer md4 en builds modernos de OpenSSL 3.
    digest = hashlib.new("md4", password.encode("utf-16le")).hexdigest()
    return digest


# ---------------------------------------------------------------------------
# Algoritmos con sal embebida: se verifican, no se comparan por igualdad.
# ---------------------------------------------------------------------------
def _verify_bcrypt(password: str, stored: str) -> bool:
    # Use the `bcrypt` library DIRECTLY (not passlib): passlib's bcrypt backend
    # breaks across bcrypt versions (the __about__ / 72-byte self-test issues).
    # bcrypt.checkpw is the stable, canonical API.
    try:
        import bcrypt
        pw = password.encode("utf-8")[:72]  # bcrypt only uses first 72 bytes
        return bcrypt.checkpw(pw, stored.encode("utf-8"))
    except Exception:
        return False


def _verify_sha512crypt(password: str, stored: str) -> bool:
    if not _HAS_PASSLIB:
        raise RuntimeError("passlib es necesario para sha512crypt")
    try:
        return _sha512_crypt.verify(password, stored)
    except Exception:
        return False


def _verify_sha256crypt(password: str, stored: str) -> bool:
    if not _HAS_PASSLIB:
        raise RuntimeError("passlib es necesario para sha256crypt")
    try:
        return _sha256_crypt.verify(password, stored)
    except Exception:
        return False


# Registro central. `kind`:
#   "hex"    -> comparar digest hex (case-insensitive)
#   "verify" -> usar funcion de verificacion (sal embebida)
ALGORITHMS = {
    "md5":         {"fn": md5,    "kind": "hex", "label": "MD5"},
    "sha1":        {"fn": sha1,   "kind": "hex", "label": "SHA-1"},
    "sha224":      {"fn": sha224, "kind": "hex", "label": "SHA-224"},
    "sha256":      {"fn": sha256, "kind": "hex", "label": "SHA-256"},
    "sha384":      {"fn": sha384, "kind": "hex", "label": "SHA-384"},
    "sha512":      {"fn": sha512, "kind": "hex", "label": "SHA-512"},
    "ntlm":        {"fn": ntlm,   "kind": "hex", "label": "NTLM"},
    "bcrypt":      {"verify": _verify_bcrypt,      "kind": "verify", "label": "bcrypt"},
    "sha512crypt": {"verify": _verify_sha512crypt, "kind": "verify", "label": "sha512crypt ($6$)"},
    "sha256crypt": {"verify": _verify_sha256crypt, "kind": "verify", "label": "sha256crypt ($5$)"},
}


def make_candidate_checker(algo: str, target: str) -> Callable[[str], bool]:
    """
    Devuelve una funcion `check(password) -> bool` optimizada para un hash
    objetivo concreto. Precalcula lo que puede (p. ej. normalizar el hex).
    """
    if algo not in ALGORITHMS:
        raise ValueError(f"Algoritmo no soportado: {algo}")

    spec = ALGORITHMS[algo]

    if spec["kind"] == "hex":
        target_norm = target.strip().lower()
        fn = spec["fn"]

        def check_hex(password: str) -> bool:
            return fn(password) == target_norm

        return check_hex

    # kind == "verify"
    verify = spec["verify"]
    stored = target.strip()

    def check_verify(password: str) -> bool:
        return verify(password, stored)

    return check_verify


def available_algorithms() -> list[str]:
    return list(ALGORITHMS.keys())
