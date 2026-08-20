"""
live.py
=======
Rich-powered live console UI for 0xCrack.

Shows an animated progress bar per hash (rate + ETA) and a running results
table. Degrades gracefully: if `rich` isn't installed or stdout isn't a TTY,
callers fall back to plain prints (see cli).
"""

from __future__ import annotations

from ..core.engine import Progress

try:
    from rich.console import Console
    from rich.table import Table
    from rich.progress import (Progress as RichProgress, SpinnerColumn,
                               BarColumn, TextColumn, TimeRemainingColumn)
    from rich.panel import Panel
    RICH = True
except Exception:  # pragma: no cover
    RICH = False


def get_console():
    return Console() if RICH else None


class LiveCracker:
    """
    Wraps a rich Progress. One task per hash; update via on_progress(index, p).
    """

    def __init__(self, console, total_hashes: int):
        self.console = console
        self.total_hashes = total_hashes
        self._progress = RichProgress(
            SpinnerColumn(style="blue"),
            TextColumn("[bold]{task.fields[algo]}[/]"),
            BarColumn(bar_width=30, complete_style="blue", finished_style="green"),
            TextColumn("{task.percentage:>3.0f}%"),
            TextColumn("· {task.fields[rate]}"),
            TextColumn("· try [dim]{task.fields[current]}[/]"),
            TimeRemainingColumn(),
            console=console,
        )
        self._tasks: dict[int, int] = {}

    def __enter__(self):
        self._progress.start()
        return self

    def __exit__(self, *exc):
        self._progress.stop()

    def add(self, index: int, algo: str, label: str):
        tid = self._progress.add_task(
            "crack", total=100, algo=f"{label:<8}", rate="—", current="")
        self._tasks[index] = tid

    def update(self, index: int, p: Progress):
        if index not in self._tasks:
            return
        from ..core.estimator import human_rate
        pct = p.percent if p.percent is not None else 0
        self._progress.update(
            self._tasks[index],
            completed=pct,
            rate=human_rate(p.rate),
            current=(p.current[:14] if p.current else ""),
        )

    def finish(self, index: int, cracked: bool):
        if index in self._tasks:
            self._progress.update(self._tasks[index], completed=100)


def results_table(rows: list[dict]) -> "Table":
    """Build a results table. rows: {user, hash, status, password, breach, bits}."""
    table = Table(title="Results", title_style="bold blue", expand=True)
    table.add_column("User", style="cyan", no_wrap=True)
    table.add_column("Hash", overflow="fold")
    table.add_column("Status", justify="center")
    table.add_column("Password", style="bold")
    table.add_column("Breach", justify="center")
    table.add_column("Strength")
    for r in rows:
        status = "[green]CRACKED[/]" if r["status"] else "[red]—[/]"
        breach = f"[red]#{r['breach']}[/]" if r.get("breach") else "[green]no[/]"
        table.add_row(
            r.get("user") or "—",
            r["hash"][:32] + ("…" if len(r["hash"]) > 32 else ""),
            status,
            r.get("password") or "",
            breach if r["status"] else "—",
            r.get("strength") or "",
        )
    return table
