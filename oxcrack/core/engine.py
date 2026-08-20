"""
engine.py
=========
Motor de crackeo propio de 0xCrack (offline, sobre hashes que YA posees).

Soporta dos modos:
  * Diccionario (wordlist) con reglas de mangling opcionales.
  * Mascara / fuerza bruta (charset + longitud), estilo hashcat ?l?d etc.

Emite progreso mediante callbacks para alimentar el dashboard en vivo:
hashrate, intentos, ETA y candidato actual. Es cancelable en cualquier momento.

Diseno pensado para correr en un hilo aparte (QThread) desde la GUI, o de
forma sincrona desde la CLI / los tests.
"""

from __future__ import annotations

import itertools
import time
from dataclasses import dataclass, field
from typing import Callable, Iterable, Iterator, Optional

from .hashers import make_candidate_checker, ALGORITHMS


# ---------------------------------------------------------------------------
# Reglas de mangling: transformaciones baratas que multiplican un diccionario.
# Cada regla toma una palabra y devuelve 0..n variantes.
# ---------------------------------------------------------------------------
_LEET_MAP = str.maketrans({"a": "@", "e": "3", "i": "1", "o": "0", "s": "$"})


def _rule_variants(word: str, rules: set[str]) -> Iterator[str]:
    """Genera variantes de una palabra segun el set de reglas activo."""
    yield word
    if "lower" in rules:
        yield word.lower()
    if "upper" in rules:
        yield word.upper()
    if "capitalize" in rules:
        yield word.capitalize()
    if "reverse" in rules:
        yield word[::-1]
    if "leet" in rules:
        yield word.translate(_LEET_MAP)
    if "append_digits" in rules:
        for d in range(0, 10):
            yield f"{word}{d}"
        # Anios comunes: patron tipico en auditorias reales.
        for y in range(1990, 2031):
            yield f"{word}{y}"
    if "append_bang" in rules:
        yield f"{word}!"
        yield f"{word}123"
        yield f"{word}!"


# Mapa de charsets estilo hashcat para el modo mascara.
MASK_CHARSETS = {
    "l": "abcdefghijklmnopqrstuvwxyz",
    "u": "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "d": "0123456789",
    "s": "!@#$%^&*()-_=+[]{};:,.<>?/",
    "a": ("abcdefghijklmnopqrstuvwxyz"
          "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
          "0123456789"
          "!@#$%^&*()-_=+[]{};:,.<>?/"),
}


@dataclass
class Progress:
    """Instantanea del progreso, enviada a la GUI/CLI periodicamente."""
    attempts: int = 0
    total: Optional[int] = None          # None si es desconocido/ilimitado
    rate: float = 0.0                    # intentos por segundo
    elapsed: float = 0.0                 # segundos
    eta: Optional[float] = None          # segundos estimados restantes
    current: str = ""                    # candidato actual (muestreo)

    @property
    def percent(self) -> Optional[float]:
        if self.total and self.total > 0:
            return min(100.0, 100.0 * self.attempts / self.total)
        return None


@dataclass
class CrackResult:
    """Resultado del intento de crackeo de un unico hash."""
    hash_value: str
    algorithm: str
    cracked: bool = False
    password: Optional[str] = None
    attempts: int = 0
    elapsed: float = 0.0
    username: Optional[str] = None       # opcional (formato user:hash)
    meta: dict = field(default_factory=dict)


ProgressCallback = Callable[[Progress], None]


class CrackEngine:
    """
    Motor sincrono. Instancia una vez por sesion; llama a `crack_*` por hash
    o usa `crack_many` para lotes. `stop()` aborta de forma cooperativa.
    """

    def __init__(self, progress_interval: float = 0.25):
        self._stop = False
        self.progress_interval = progress_interval

    # ------------------------------------------------------------------ ctrl
    def stop(self) -> None:
        self._stop = True

    def reset(self) -> None:
        self._stop = False

    # ------------------------------------------------------- generadores base
    def _dictionary_candidates(
        self, wordlist_path: str, rules: set[str]
    ) -> Iterator[str]:
        with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                word = line.rstrip("\r\n")
                if not word:
                    continue
                if rules:
                    yield from _rule_variants(word, rules)
                else:
                    yield word

    def _mask_candidates(self, mask: str) -> Iterator[str]:
        """
        Interpreta una mascara estilo hashcat: '?l?l?d?d' => 2 letras + 2 digitos.
        Tambien admite literales: 'admin?d?d'.
        """
        pools: list[str] = []
        i = 0
        while i < len(mask):
            ch = mask[i]
            if ch == "?" and i + 1 < len(mask):
                token = mask[i + 1]
                if token in MASK_CHARSETS:
                    pools.append(MASK_CHARSETS[token])
                    i += 2
                    continue
                # '??' => literal '?'
                pools.append("?")
                i += 2
                continue
            pools.append(ch)  # literal
            i += 1
        for combo in itertools.product(*pools):
            yield "".join(combo)

    def _bruteforce_candidates(
        self, charset: str, min_len: int, max_len: int
    ) -> Iterator[str]:
        for length in range(min_len, max_len + 1):
            for combo in itertools.product(charset, repeat=length):
                yield "".join(combo)

    # ---------------------------------------------------------------- crackeo
    def _run(
        self,
        target: str,
        algorithm: str,
        candidates: Iterable[str],
        total: Optional[int],
        on_progress: Optional[ProgressCallback],
        username: Optional[str] = None,
    ) -> CrackResult:
        check = make_candidate_checker(algorithm, target)
        result = CrackResult(hash_value=target, algorithm=algorithm,
                             username=username)

        start = time.perf_counter()
        last_emit = start
        attempts = 0
        last_candidate = ""

        for candidate in candidates:
            if self._stop:
                break
            attempts += 1
            last_candidate = candidate
            if check(candidate):
                result.cracked = True
                result.password = candidate
                break

            # Emision periodica de progreso (no en cada intento: seria lento).
            now = time.perf_counter()
            if on_progress and (now - last_emit) >= self.progress_interval:
                elapsed = now - start
                rate = attempts / elapsed if elapsed > 0 else 0.0
                eta = None
                if total and rate > 0:
                    remaining = max(0, total - attempts)
                    eta = remaining / rate
                on_progress(Progress(attempts=attempts, total=total, rate=rate,
                                     elapsed=elapsed, eta=eta,
                                     current=last_candidate))
                last_emit = now

        elapsed = time.perf_counter() - start
        result.attempts = attempts
        result.elapsed = elapsed

        # Progreso final.
        if on_progress:
            rate = attempts / elapsed if elapsed > 0 else 0.0
            on_progress(Progress(attempts=attempts, total=total, rate=rate,
                                 elapsed=elapsed, eta=0.0,
                                 current=last_candidate))
        return result

    # ------------------------------------------------------------- API alto nivel
    def crack_dictionary(
        self,
        target: str,
        algorithm: str,
        wordlist_path: str,
        rules: Optional[set[str]] = None,
        on_progress: Optional[ProgressCallback] = None,
        username: Optional[str] = None,
    ) -> CrackResult:
        self.reset()
        rules = rules or set()
        # Contamos lineas para estimar total (barato frente a crackear).
        total = None
        try:
            with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as fh:
                base = sum(1 for _ in fh)
            total = base if not rules else None  # con reglas el total es variable
        except OSError:
            total = None
        candidates = self._dictionary_candidates(wordlist_path, rules)
        return self._run(target, algorithm, candidates, total, on_progress,
                         username)

    def crack_mask(
        self,
        target: str,
        algorithm: str,
        mask: str,
        on_progress: Optional[ProgressCallback] = None,
        username: Optional[str] = None,
    ) -> CrackResult:
        self.reset()
        total = self._estimate_mask_total(mask)
        candidates = self._mask_candidates(mask)
        return self._run(target, algorithm, candidates, total, on_progress,
                         username)

    def crack_bruteforce(
        self,
        target: str,
        algorithm: str,
        charset: str,
        min_len: int,
        max_len: int,
        on_progress: Optional[ProgressCallback] = None,
        username: Optional[str] = None,
    ) -> CrackResult:
        self.reset()
        total = sum(len(charset) ** n for n in range(min_len, max_len + 1))
        candidates = self._bruteforce_candidates(charset, min_len, max_len)
        return self._run(target, algorithm, candidates, total, on_progress,
                         username)

    # ------------------------------------------------------------------ utils
    @staticmethod
    def _estimate_mask_total(mask: str) -> Optional[int]:
        total = 1
        i = 0
        while i < len(mask):
            ch = mask[i]
            if ch == "?" and i + 1 < len(mask):
                token = mask[i + 1]
                total *= len(MASK_CHARSETS.get(token, "?"))
                i += 2
                continue
            i += 1  # literal: no multiplica
        return total
