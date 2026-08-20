"""
hash_identifier.py
==================
Auto-deteccion del tipo de hash a partir de su forma.

No es magia: usamos longitud + charset + prefijos de esquema ($2b$, $6$, ...).
Un mismo largo (p. ej. 32 hex) puede ser MD5 o NTLM, asi que devolvemos una
LISTA de candidatos ordenada por probabilidad, no una unica respuesta. La GUI
deja al usuario elegir, que es como trabajan hashid / haiti / hash-identifier.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")


@dataclass
class HashGuess:
    algorithm: str      # clave interna usada por hashers.ALGORITHMS
    label: str          # nombre legible
    confidence: float   # 0..1 heuristico


def _is_hex(s: str) -> bool:
    return bool(_HEX_RE.match(s))


def identify(hash_value: str) -> list[HashGuess]:
    """Devuelve candidatos ordenados de mayor a menor confianza."""
    h = hash_value.strip()
    guesses: list[HashGuess] = []

    # --- Esquemas con prefijo (los mas fiables) ---------------------------
    if h.startswith(("$2a$", "$2b$", "$2y$")):
        return [HashGuess("bcrypt", "bcrypt", 0.99)]
    if h.startswith("$6$"):
        return [HashGuess("sha512crypt", "sha512crypt ($6$)", 0.99)]
    if h.startswith("$5$"):
        return [HashGuess("sha256crypt", "sha256crypt ($5$)", 0.99)]
    if h.startswith("$1$"):
        return [HashGuess("md5crypt", "md5crypt ($1$)", 0.95)]

    # --- Hashes crudos hex por longitud ------------------------------------
    if _is_hex(h):
        n = len(h)
        if n == 32:
            # 32 hex = MD5 o NTLM. NTLM suele venir en volcados de Windows.
            guesses.append(HashGuess("md5", "MD5", 0.6))
            guesses.append(HashGuess("ntlm", "NTLM", 0.55))
        elif n == 40:
            guesses.append(HashGuess("sha1", "SHA-1", 0.8))
        elif n == 56:
            guesses.append(HashGuess("sha224", "SHA-224", 0.8))
        elif n == 64:
            guesses.append(HashGuess("sha256", "SHA-256", 0.85))
        elif n == 96:
            guesses.append(HashGuess("sha384", "SHA-384", 0.85))
        elif n == 128:
            guesses.append(HashGuess("sha512", "SHA-512", 0.85))

    if not guesses:
        guesses.append(HashGuess("unknown", "Desconocido", 0.0))

    guesses.sort(key=lambda g: g.confidence, reverse=True)
    return guesses


def best_guess(hash_value: str) -> HashGuess:
    return identify(hash_value)[0]


def parse_line(line: str) -> tuple[str | None, str]:
    """
    Interpreta una linea de un archivo de hashes. Soporta 'usuario:hash'
    (formato tipico de /etc/shadow, volcados AD, etc.) y 'hash' a secas.
    Devuelve (username|None, hash).
    """
    line = line.strip()
    if not line:
        return None, ""
    # bcrypt / sha512crypt contienen ':' internamente? No, usan '$'. Pero
    # el formato user:hash es comun. Partimos solo en el PRIMER ':'.
    if ":" in line and not line.startswith("$"):
        user, _, rest = line.partition(":")
        # Heuristica: si lo de despues parece un hash, tratamos user:hash.
        if rest:
            return user, rest
    return None, line
