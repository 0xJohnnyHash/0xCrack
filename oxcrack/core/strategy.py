"""
strategy.py
===========
Cerebro del "modo inteligente" de 0xCrack.

Dado un hash, decide automaticamente:
  1. Que tipo de hash es (via hash_identifier).
  2. Cual es el mejor modo de ataque para ese tipo.
  3. Que reglas de mangling conviene activar.
  4. Una justificacion legible para mostrar al usuario.

Filosofia de la recomendacion
------------------------------
Para hashes reales, la fuerza bruta pura es inviable (el espacio crece
exponencialmente). El ataque de DICCIONARIO con reglas es, en la practica, el
que mejor relacion exito/tiempo ofrece — por eso es la estrategia por defecto y
por eso el flujo culmina pidiendo al usuario que cargue su propio diccionario.

Distinguimos ademas hashes "rapidos" (MD5, SHA*, NTLM) de "lentos" (bcrypt,
sha*crypt). En los lentos cada intento cuesta mucho, asi que recomendamos
MENOS reglas para no disparar el tiempo.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from . import hash_identifier as hid
from .hashers import ALGORITHMS


# Hashes cuyo coste por intento es alto (KDF con factor de trabajo o miles de
# iteraciones). Con estos conviene un diccionario acotado y pocas reglas.
SLOW_HASHES = {"bcrypt", "sha256crypt", "sha512crypt", "md5crypt", "argon2", "scrypt"}


@dataclass
class Strategy:
    algorithm: str                       # clave interna (md5, ntlm, bcrypt, …)
    label: str                           # nombre legible
    confidence: float                    # 0..1 de la deteccion
    mode: str                            # 'dictionary' | 'mask' | 'brute'
    rules: set[str] = field(default_factory=set)
    needs_wordlist: bool = True
    is_slow: bool = False
    rationale: str = ""                  # explicacion para la GUI
    alternatives: list[str] = field(default_factory=list)
    supported: bool = True               # False si no sabemos crackearlo


def recommend(hash_value: str) -> Strategy:
    """Devuelve la estrategia recomendada para un hash concreto."""
    guesses = hid.identify(hash_value)
    best = guesses[0]

    # Tipo desconocido o no soportado por nuestro motor.
    if best.algorithm == "unknown" or best.algorithm not in ALGORITHMS:
        return Strategy(
            algorithm=best.algorithm,
            label=best.label,
            confidence=best.confidence,
            mode="dictionary",
            supported=best.algorithm in ALGORITHMS,
            needs_wordlist=True,
            rationale=("Could not identify the hash type with confidence. "
                       "Force the algorithm with -m, or try MD5/NTLM mode "
                       "(both are 32 hex chars)."),
            alternatives=[g.label for g in guesses[:3]],
        )

    is_slow = best.algorithm in SLOW_HASHES

    # --- Eleccion del modo -------------------------------------------------
    # En todos los casos el mejor "modelo" real es diccionario. Ajustamos las
    # reglas segun el coste del hash.
    if is_slow:
        rules = {"capitalize"}  # minimal: each guess is expensive (bcrypt, $6$…)
        rationale = (
            f"Detected {best.label}, a SLOW hash by design (high work factor). "
            f"Brute force is infeasible and too many rules would explode the "
            f"runtime. Optimal strategy: DICTIONARY attack with minimal rules. "
            f"Load a high-quality wordlist (e.g. real leaked passwords)."
        )
    else:
        rules = {"lower", "capitalize", "append_digits"}
        rationale = (
            f"Detected {best.label}, a FAST hash. The best success/time ratio "
            f"comes from a DICTIONARY attack boosted with mangling rules "
            f"(lowercase, Capitalization and digit/year suffixes, which cover "
            f"the most common human patterns). Load your wordlist to start."
        )

    alternatives = []
    if not is_slow:
        alternatives.append("Mask (?l?d…) for short known patterns")
        alternatives.append("Brute force only for lengths <= 6")

    return Strategy(
        algorithm=best.algorithm,
        label=best.label,
        confidence=best.confidence,
        mode="dictionary",
        rules=rules,
        needs_wordlist=True,
        is_slow=is_slow,
        rationale=rationale,
        alternatives=alternatives,
        supported=True,
    )


def humanize(strategy: Strategy) -> str:
    """Short one-line summary for headers/tooltips."""
    conf = f"{strategy.confidence * 100:.0f}%"
    rules = ", ".join(sorted(strategy.rules)) or "no rules"
    return (f"{strategy.label}  ·  confidence {conf}  ·  "
            f"mode {strategy.mode}  ·  rules: {rules}")
