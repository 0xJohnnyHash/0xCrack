"""
Tests del motor de 0xCrack. Ejecutar:  python -m pytest -q
(o sin pytest:  python tests/test_engine.py)
"""
import hashlib
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from oxcrack.core import hashers, hash_identifier as hid
from oxcrack.core.engine import CrackEngine
from oxcrack.core.audit import build_report, estimate_entropy_bits, PasswordPolicy


WORDLIST = os.path.join(os.path.dirname(__file__), "..", "wordlists", "sample.txt")


def test_md5_dictionary():
    target = hashlib.md5(b"password").hexdigest()
    res = CrackEngine().crack_dictionary(target, "md5", WORDLIST)
    assert res.cracked and res.password == "password"


def test_sha256_dictionary():
    target = hashlib.sha256(b"dragon").hexdigest()
    res = CrackEngine().crack_dictionary(target, "sha256", WORDLIST)
    assert res.cracked and res.password == "dragon"


def test_rules_expand():
    # 'Summer2024' esta en la lista, pero probemos reglas sobre 'admin'.
    target = hashlib.md5(b"admin9").hexdigest()
    res = CrackEngine().crack_dictionary(target, "md5", WORDLIST,
                                         rules={"append_digits"})
    assert res.cracked and res.password == "admin9"


def test_mask():
    target = hashlib.md5(b"ab12").hexdigest()
    res = CrackEngine().crack_mask(target, "md5", "?l?l?d?d")
    assert res.cracked and res.password == "ab12"


def test_bruteforce_short():
    target = hashlib.md5(b"cat").hexdigest()
    res = CrackEngine().crack_bruteforce(target, "md5", "abct", 1, 3)
    assert res.cracked and res.password == "cat"


def test_ntlm():
    # NTLM de 'password' es conocido: 8846f7eaee8fb117ad06bdd830b7586c
    target = "8846f7eaee8fb117ad06bdd830b7586c"
    res = CrackEngine().crack_dictionary(target, "ntlm", WORDLIST)
    assert res.cracked and res.password == "password"


def test_identifier():
    assert hid.best_guess("5f4dcc3b5aa765d61d8327deb882cf99").algorithm in ("md5", "ntlm")
    assert hid.best_guess("a" * 64).algorithm == "sha256"
    assert hid.best_guess("$2b$12$" + "x" * 53).algorithm == "bcrypt"


def test_strategy_recommendation():
    from oxcrack.core import strategy as strat
    # Hash rapido -> diccionario con reglas completas.
    st = strat.recommend(hashlib.md5(b"x").hexdigest())
    assert st.mode == "dictionary" and st.needs_wordlist
    assert "append_digits" in st.rules and not st.is_slow
    # bcrypt -> marcado como lento, reglas minimas.
    st2 = strat.recommend("$2b$12$" + "x" * 53)
    assert st2.algorithm == "bcrypt" and st2.is_slow
    assert st2.rules == {"capitalize"}


def test_entropy_and_report():
    assert estimate_entropy_bits("aaaa") < estimate_entropy_bits("Aa1!xYz9")
    target = hashlib.md5(b"password").hexdigest()
    res = CrackEngine().crack_dictionary(target, "md5", WORDLIST)
    report = build_report([res], total_hashes=1, policy=PasswordPolicy())
    assert report.cracked_count == 1
    assert report.crack_rate == 100.0
    assert len(report.findings) >= 1


def test_breach_check():
    from oxcrack.core import breach
    assert breach.check("password") is not None      # ranked in the list
    assert breach.check("qwerty") is not None
    assert breach.check("a-very-unlikely-passphrase-xyz") is None


def test_estimator():
    from oxcrack.core import estimator as est
    assert est.human_time(0.5).endswith("ms")
    assert est.human_time(90).endswith("min")
    n = est.count_candidates(WORDLIST, {"append_digits"})
    base = est.count_candidates(WORDLIST, set())
    assert n > base  # rules expand the space


def test_report_has_breach_count():
    from oxcrack.core.engine import CrackEngine
    target = hashlib.md5(b"password").hexdigest()
    res = CrackEngine().crack_dictionary(target, "md5", WORDLIST)
    report = build_report([res], total_hashes=1)
    assert report.stats["breached_count"] >= 1
    assert any(f["severity"] == "CRITICAL" for f in report.findings)


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    passed = 0
    for fn in fns:
        try:
            fn()
            print(f"PASS  {fn.__name__}")
            passed += 1
        except AssertionError as e:
            print(f"FAIL  {fn.__name__}: {e}")
        except Exception as e:
            print(f"ERROR {fn.__name__}: {e}")
    print(f"\n{passed}/{len(fns)} tests OK")
    sys.exit(0 if passed == len(fns) else 1)
