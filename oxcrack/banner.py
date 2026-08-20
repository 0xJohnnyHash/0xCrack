"""
banner.py
=========
Blue ASCII-art banner for 0xCrack, shown on every console run.

Works with or without `rich`: if rich is available we use it for truecolor;
otherwise we fall back to raw ANSI escape codes so the banner still shows in
any terminal (Linux, Windows Terminal, macOS).
"""

from __future__ import annotations

from . import __version__

# ANSI Shadow figlet of "0xCrack".
_ART = r"""
 ██████╗ ██╗  ██╗ ██████╗██████╗  █████╗  ██████╗██╗  ██╗
██╔═████╗╚██╗██╔╝██╔════╝██╔══██╗██╔══██╗██╔════╝██║ ██╔╝
██║██╔██║ ╚███╔╝ ██║     ██████╔╝███████║██║     █████╔╝
████╔╝██║ ██╔██╗ ██║     ██╔══██╗██╔══██║██║     ██╔═██╗
╚██████╔╝██╔╝ ██╗╚██████╗██║  ██║██║  ██║╚██████╗██║  ██╗
 ╚═════╝ ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝
"""

_CREDIT = "by Johnny Hash (0xJohnnyHash)"

# ANSI colors
_BLUE = "\033[38;5;33m"     # bright blue
_RED = "\033[38;5;196m"     # bright red
_RESET = "\033[0m"


def render(use_color: bool = True) -> str:
    """Return the banner as a string (used by the plain fallback path)."""
    if not use_color:
        return _ART + f"        {_CREDIT}\n"
    return (f"{_BLUE}{_ART}{_RESET}"
            f"        {_RED}{_CREDIT}{_RESET}\n")


def show(console=None, use_color: bool = True) -> None:
    """
    Print the banner. If a rich Console is provided, use it for crisp blue;
    otherwise print ANSI directly.
    """
    if console is not None:
        try:
            from rich.text import Text
            console.print(Text(_ART, style="bold blue"))
            console.print(f"        [bold red]{_CREDIT}[/]\n")
            return
        except Exception:
            pass
    print(render(use_color))
