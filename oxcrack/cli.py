"""
cli.py  —  0xCrack console entry point
======================================
Linux-style command-line password auditor.

Flags
-----
  -T, --target FILE   File with hashes to crack (one per line; user:hash ok)
      --hash HASH     A single hash to crack (instead of -T)
  -S, --source FILE   Dictionary / wordlist source
  -m, --mode TYPE     Force hash type (default: auto-detect)
  -oG FILE            Write HTML audit report
  -oJ FILE            Write JSON audit report
      --rules LIST    Override mangling rules (comma separated)
      --explain       Educational mode: narrate every decision
      --no-estimate   Skip the pre-attack crack-time estimate
      --no-banner     Do not print the ASCII banner
      --no-color      Disable colors / rich UI
      --policy-min N  Min length for the audited policy (default 12)
  -v, --version       Show version
"""

from __future__ import annotations

import argparse
import os
import sys
import time

from . import __version__, __author__
from . import banner
from .core import hash_identifier as hid
from .core import strategy as strat
from .core import estimator as est
from .core import breach
from .core.engine import CrackEngine
from .core.hashers import ALGORITHMS, available_algorithms
from .core.audit import build_report, PasswordPolicy, strength_label, estimate_entropy_bits
from .report import html_report


# --------------------------------------------------------------------------- #
#  Small color helpers (used when rich is unavailable / not a TTY)
# --------------------------------------------------------------------------- #
class C:
    B = "\033[38;5;33m"; G = "\033[32m"; R = "\033[31m"; Y = "\033[33m"
    D = "\033[2m"; BOLD = "\033[1m"; X = "\033[0m"


# Global color switch; set in main() from flags + TTY detection.
_COLOR = True


def _supports_rich(no_color: bool) -> bool:
    if no_color:
        return False
    try:
        from .tui.live import RICH
        return RICH and sys.stdout.isatty()
    except Exception:
        return False


def _p(msg: str):
    print(msg if _COLOR else _strip_ansi(msg))


def _strip_ansi(s: str) -> str:
    import re
    return re.sub(r"\033\[[0-9;]*m", "", s)


# --------------------------------------------------------------------------- #
#  Argument parsing
# --------------------------------------------------------------------------- #
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="0xcrack",
        description="0xCrack — smart console password auditor (by %s)" % __author__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""examples:
  0xcrack -T hashes.txt -S rockyou.txt -oG report.html
  0xcrack --hash 5f4dcc3b5aa765d61d8327deb882cf99 -S wordlist.txt --explain
  0xcrack -T dump.txt -S words.txt -m ntlm -oJ out.json
""")
    src = p.add_argument_group("input")
    src.add_argument("-T", "--target", metavar="FILE",
                     help="file with hashes to crack (one per line; user:hash ok)")
    src.add_argument("--hash", metavar="HASH", help="a single hash to crack")

    atk = p.add_argument_group("attack")
    atk.add_argument("-S", "--source", metavar="FILE",
                     help="dictionary / wordlist source")
    atk.add_argument("-m", "--mode", metavar="TYPE",
                     help="force hash type (default: auto-detect). "
                          "one of: " + ", ".join(available_algorithms()))
    atk.add_argument("--rules", metavar="LIST",
                     help="override mangling rules (comma separated), e.g. "
                          "lower,capitalize,append_digits")

    out = p.add_argument_group("output")
    out.add_argument("-oG", dest="out_html", metavar="FILE",
                     help="write HTML audit report")
    out.add_argument("-oJ", dest="out_json", metavar="FILE",
                     help="write JSON audit report")
    out.add_argument("-oP", dest="out_plain", metavar="FILE",
                     help="write cracked passwords as plain text "
                          "(potfile style: [user:]hash:password)")
    out.add_argument("--policy-min", type=int, default=12, metavar="N",
                     help="min length for the audited policy (default 12)")

    ui = p.add_argument_group("ui")
    ui.add_argument("--explain", action="store_true",
                    help="educational mode: narrate every decision")
    ui.add_argument("--no-estimate", action="store_true",
                    help="skip the pre-attack crack-time estimate")
    ui.add_argument("--no-banner", action="store_true", help="hide the banner")
    ui.add_argument("--no-color", action="store_true", help="disable colors")
    p.add_argument("-v", "--version", action="version",
                   version=f"0xCrack {__version__} — by {__author__}")
    return p


# --------------------------------------------------------------------------- #
#  Target loading
# --------------------------------------------------------------------------- #
def load_targets(args) -> list[tuple[str | None, str]]:
    targets: list[tuple[str | None, str]] = []
    if args.target:
        if not os.path.isfile(args.target):
            sys.exit(f"[!] Target file not found: {args.target}")
        with open(args.target, "r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                user, h = hid.parse_line(line)
                if h:
                    targets.append((user, h))
    if args.hash:
        targets.append((None, args.hash.strip()))
    return targets


# --------------------------------------------------------------------------- #
#  Per-target planning (auto mode)
# --------------------------------------------------------------------------- #
def plan_target(user, h, args, explain):
    """Decide algorithm + rules for one hash."""
    if args.mode:
        algo = args.mode.lower()
        if algo not in ALGORITHMS:
            sys.exit(f"[!] Unsupported --mode '{args.mode}'. "
                     f"Choose one of: {', '.join(available_algorithms())}")
        s = strat.recommend(h)  # still use it for rules default / slow flag
        rules = s.rules
        label = ALGORITHMS[algo]["label"]
        is_slow = ALGORITHMS[algo]["kind"] == "verify"
        if explain:
            _p(f"{C.D}    [explain] forced type = {label}; using rules "
               f"{sorted(rules) or 'none'}{C.X}")
    else:
        s = strat.recommend(h)
        algo, rules, label, is_slow = s.algorithm, s.rules, s.label, s.is_slow
        if explain:
            _p(f"{C.D}    [explain] {s.rationale}{C.X}")

    if args.rules is not None:
        rules = {r.strip() for r in args.rules.split(",") if r.strip()}
        if explain:
            _p(f"{C.D}    [explain] rules overridden -> {sorted(rules)}{C.X}")
    return algo, set(rules), label, is_slow


# --------------------------------------------------------------------------- #
#  Main
# --------------------------------------------------------------------------- #
def _fatal(parser, msg: str, show_help: bool = False):
    """Print a friendly error (no raw ANSI when color is off) and exit."""
    global _COLOR
    text = f"{C.R}[!] {msg}{C.X}" if _COLOR else f"[!] {msg}"
    print(text, file=sys.stderr)
    if show_help:
        print(file=sys.stderr)
        parser.print_help(sys.stderr)
    sys.exit(2)


def main(argv=None):
    parser = build_parser()
    # No arguments at all -> show banner + help instead of an error. This is the
    # friendly path when someone just presses Run/F5 with no parameters.
    raw_args = sys.argv[1:] if argv is None else argv
    args = parser.parse_args(argv)
    global _COLOR
    _COLOR = (not args.no_color) and sys.stdout.isatty()
    use_rich = _supports_rich(args.no_color)
    console = None
    if use_rich:
        from .tui.live import get_console
        console = get_console()

    if not args.no_banner:
        banner.show(console, use_color=not args.no_color)

    if not raw_args:
        print("Run 0xCrack with parameters. Quick start:\n")
        print("  python 0xcrack.py --hash 5f4dcc3b5aa765d61d8327deb882cf99 "
              "-S wordlists/sample.txt --explain")
        print("  python 0xcrack.py -T hashes.txt -S wordlists/sample.txt -oG report.html\n")
        parser.print_help()
        sys.exit(0)

    # Validate input
    targets = load_targets(args)
    if not targets:
        _fatal(parser, "No hashes. Use -T <file> or --hash <hash>.", show_help=True)
    if not args.source:
        _fatal(parser, "No dictionary. Use -S <wordlist>.", show_help=True)
    if not os.path.isfile(args.source):
        _fatal(parser, f"Wordlist not found: {args.source}")

    _p(f"{C.B}[*]{C.X} Loaded {C.BOLD}{len(targets)}{C.X} hash(es) · "
       f"dictionary: {C.BOLD}{os.path.basename(args.source)}{C.X} · "
       f"breach list: {breach.list_size()} entries")

    # Plan every target first (needed for the estimate table).
    plans = []
    for user, h in targets:
        algo, rules, label, is_slow = plan_target(user, h, args, args.explain)
        plans.append(dict(user=user, hash=h, algo=algo, rules=rules,
                          label=label, is_slow=is_slow))

    # ---- DIFFERENTIATOR: pre-attack crack-time estimate ----
    if not args.no_estimate:
        _print_estimates(plans, args.source, console, use_rich)

    # ---- Run the attacks with a live view ----
    results = _run_attacks(plans, args.source, console, use_rich, args.explain)

    # ---- Post-process: breach + strength, then results table ----
    rows = _postprocess(results, console, use_rich)

    # ---- Audit report ----
    policy = PasswordPolicy(min_length=args.policy_min)
    report = build_report(results, total_hashes=len(targets), policy=policy)
    _print_summary(report, console, use_rich)

    if args.out_plain:
        n = _save_plain(results, args.out_plain)
        _p(f"{C.G}[+]{C.X} {n} cracked password(s) saved (plain text) to "
           f"{C.BOLD}{args.out_plain}{C.X}")
    if args.out_html:
        html_report.save(report, args.out_html)
        _p(f"{C.G}[+]{C.X} HTML report saved to {C.BOLD}{args.out_html}{C.X}")
    if args.out_json:
        with open(args.out_json, "w", encoding="utf-8") as fh:
            fh.write(report.to_json())
        _p(f"{C.G}[+]{C.X} JSON report saved to {C.BOLD}{args.out_json}{C.X}")

    cracked = report.cracked_count
    sys.exit(0 if cracked else 2)


def _print_estimates(plans, wordlist, console, use_rich):
    # Benchmark unique algorithms once.
    seen = {}
    for pl in plans:
        if pl["algo"] not in seen and pl["algo"] in ALGORITHMS:
            seen[pl["algo"]] = est.estimate(pl["algo"], wordlist, pl["rules"])
    if use_rich and console is not None:
        from rich.table import Table
        t = Table(title="Crack-time estimate (worst case)",
                  title_style="bold blue")
        t.add_column("Type"); t.add_column("Hashrate", justify="right")
        t.add_column("Candidates", justify="right")
        t.add_column("Max time", justify="right")
        for algo, e in seen.items():
            t.add_row(ALGORITHMS[algo]["label"], est.human_rate(e.hashrate),
                      f"{e.candidates:,}", est.human_time(e.seconds_worst))
        console.print(t)
    else:
        _p(f"{C.B}[*]{C.X} Crack-time estimate (worst case):")
        for algo, e in seen.items():
            _p(f"    {ALGORITHMS[algo]['label']:<14} "
               f"{est.human_rate(e.hashrate):>10} · "
               f"{e.candidates:,} candidates · max {est.human_time(e.seconds_worst)}")


def _run_attacks(plans, wordlist, console, use_rich, explain):
    engine = CrackEngine()
    results = []
    if use_rich and console is not None:
        from .tui.live import LiveCracker
        with LiveCracker(console, len(plans)) as live:
            for i, pl in enumerate(plans):
                live.add(i, pl["algo"], pl["label"])
                res = engine.crack_dictionary(
                    pl["hash"], pl["algo"], wordlist, rules=pl["rules"],
                    on_progress=lambda p, _i=i: live.update(_i, p),
                    username=pl["user"])
                live.finish(i, res.cracked)
                results.append(res)
    else:
        for i, pl in enumerate(plans):
            _p(f"{C.B}[*]{C.X} Attacking {pl['label']} :: {pl['hash'][:24]}…")
            res = engine.crack_dictionary(
                pl["hash"], pl["algo"], wordlist, rules=pl["rules"],
                username=pl["user"])
            tag = (f"{C.G}CRACKED -> {res.password}{C.X}" if res.cracked
                   else f"{C.Y}not found{C.X}")
            _p(f"    {tag}")
            results.append(res)
    return results


def _postprocess(results, console, use_rich):
    rows = []
    for r in results:
        rank = breach.check(r.password) if r.cracked else None
        bits = estimate_entropy_bits(r.password) if r.cracked else 0
        rows.append(dict(user=r.username, hash=r.hash_value, status=r.cracked,
                         password=r.password, breach=rank,
                         strength=strength_label(bits) if r.cracked else ""))
    if use_rich and console is not None:
        from .tui.live import results_table
        console.print(results_table(rows))
    else:
        _p(f"\n{C.BOLD}Results:{C.X}")
        for row in rows:
            if row["status"]:
                b = f" {C.R}[BREACHED #%d]{C.X}" % row["breach"] if row["breach"] else ""
                _p(f"  {C.G}[+]{C.X} {row['hash'][:24]}… -> "
                   f"{C.BOLD}{row['password']}{C.X} ({row['strength']}){b}")
            else:
                _p(f"  {C.Y}[-]{C.X} {row['hash'][:24]}… not cracked")
    return rows


def _save_plain(results, path) -> int:
    """
    Write cracked credentials as plain text (potfile style), one per line:
        user:hash:password   (or  hash:password  when there is no username)
    Returns how many lines were written.
    """
    n = 0
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("# 0xCrack cracked passwords (plain text) — authorized use only\n")
        for r in results:
            if r.cracked and r.password is not None:
                prefix = f"{r.username}:" if r.username else ""
                fh.write(f"{prefix}{r.hash_value}:{r.password}\n")
                n += 1
    return n


def _print_summary(report, console, use_rich):
    _p(f"\n{C.B}[*]{C.X} {C.BOLD}Audit summary{C.X}: "
       f"{report.cracked_count}/{report.total_hashes} cracked "
       f"({report.crack_rate}%) · avg entropy "
       f"{report.stats.get('avg_entropy_bits')} bits")
    for f in report.findings[:5]:
        col = {"CRITICAL": C.R, "HIGH": C.R, "MEDIUM": C.Y, "LOW": C.G}.get(
            f["severity"], C.X)
        _p(f"    {col}[{f['severity']}]{C.X} {f['title']}")


if __name__ == "__main__":
    main()
