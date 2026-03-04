"""
VibeCrack CLI - Rich terminal output.

Provides real-time progress display, colored findings, and score tables.
"""

import sys

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
    from rich.text import Text
    from rich import box
    HAS_RICH = True
except ImportError:
    HAS_RICH = False

VERSION = "0.1.0"

SEVERITY_COLORS = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "cyan",
    "info": "blue",
}

GRADE_COLORS = {
    "A+": "bold green",
    "A": "green",
    "B": "yellow",
    "C": "dark_orange",
    "D": "red",
    "F": "bold red",
}


class CLIOutput:
    """Manages terminal output for the CLI scanner."""

    def __init__(self, *, no_color: bool = False, verbose: bool = False):
        self.verbose = verbose
        if HAS_RICH and not no_color:
            self.console = Console()
            self._rich = True
        else:
            self.console = None
            self._rich = False
        self._findings: list[tuple[str, str, str, str]] = []
        self._progress = None
        self._progress_task = None

    def print_banner(self, target: str, modules: list[str]) -> None:
        if self._rich:
            banner = Text()
            banner.append("\n  VibeCrack ", style="bold magenta")
            banner.append(f"Security Scanner v{VERSION}\n", style="dim")
            banner.append(f"\n  Target:  ", style="bold")
            banner.append(f"{target}\n", style="cyan")
            banner.append(f"  Modules: ", style="bold")
            banner.append(f"{', '.join(modules)}\n", style="dim")
            self.console.print(Panel(banner, border_style="magenta", padding=(0, 1)))
        else:
            print(f"\nVibeCrack Security Scanner v{VERSION}")
            print(f"Target:  {target}")
            print(f"Modules: {', '.join(modules)}")
            print("-" * 50)

    def start_progress(self) -> None:
        if self._rich:
            self._progress = Progress(
                SpinnerColumn(),
                TextColumn("[bold blue]{task.description}"),
                BarColumn(bar_width=30),
                TaskProgressColumn(),
                console=self.console,
            )
            self._progress_task = self._progress.add_task("Initializing...", total=100)
            self._progress.start()

    def update_progress(self, progress: int, phase: str) -> None:
        if self._rich and self._progress and self._progress_task is not None:
            self._progress.update(
                self._progress_task,
                completed=progress,
                description=f"Running: {phase}",
            )
        elif not self._rich:
            print(f"  [{progress}%] {phase}", end="\r")

    def stop_progress(self) -> None:
        if self._rich and self._progress:
            self._progress.update(self._progress_task, completed=100, description="Done")
            self._progress.stop()
            self._progress = None

    def on_finding(self, severity: str, title: str, affected_url: str, scanner: str) -> None:
        self._findings.append((severity, title, affected_url, scanner))

    def on_log(self, level: str, message: str, scanner: str) -> None:
        if self.verbose:
            if self._rich:
                color = {"error": "red", "warning": "yellow", "info": "blue"}.get(level, "dim")
                self.console.print(f"  [{scanner}] {message}", style=color)
            else:
                print(f"  [{scanner}] {message}")

    def print_findings(self) -> None:
        if not self._findings:
            if self._rich:
                self.console.print("\n  [green]No vulnerabilities found![/green]\n")
            else:
                print("\n  No vulnerabilities found!\n")
            return

        if self._rich:
            self.console.print("\n")
            table = Table(
                title="Findings",
                box=box.ROUNDED,
                show_lines=False,
                padding=(0, 1),
            )
            table.add_column("Severity", width=10, justify="center")
            table.add_column("Title", min_width=30)
            table.add_column("URL", max_width=40, overflow="ellipsis")
            table.add_column("Scanner", style="dim")

            # Sort: critical first
            order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
            sorted_findings = sorted(self._findings, key=lambda f: order.get(f[0], 5))

            for sev, title, url, scanner in sorted_findings:
                color = SEVERITY_COLORS.get(sev, "white")
                table.add_row(
                    Text(sev.upper(), style=color),
                    title,
                    url or "-",
                    scanner,
                )
            self.console.print(table)
        else:
            print("\nFindings:")
            for sev, title, url, scanner in self._findings:
                print(f"  [{sev.upper():>8}] {title}  ({scanner})")

    def print_score(self, score_data: dict) -> None:
        if not score_data:
            return

        overall = score_data.get("overallScore", 0)
        grade = score_data.get("grade", "?")
        categories = score_data.get("categories", {})

        if self._rich:
            grade_color = GRADE_COLORS.get(grade, "white")
            score_text = Text()
            score_text.append(f"\n  Score: ", style="bold")
            score_text.append(f"{overall}/100 ", style=grade_color)
            score_text.append(f"(Grade: ", style="bold")
            score_text.append(f"{grade}", style=grade_color)
            score_text.append(")", style="bold")
            self.console.print(score_text)

            if categories:
                table = Table(box=box.SIMPLE, padding=(0, 2))
                table.add_column("Category", style="bold")
                table.add_column("Score", justify="right")
                table.add_column("Grade", justify="center")

                CATEGORY_LABELS = {
                    "ssl_tls": "SSL / TLS",
                    "headers": "Security Headers",
                    "injection": "Injection",
                    "authentication": "Authentication",
                    "secrets_exposure": "Secrets Exposure",
                    "configuration": "Configuration",
                    "information_disclosure": "Info Disclosure",
                }

                for cat_key, cat_data in categories.items():
                    cat_label = CATEGORY_LABELS.get(cat_key, cat_key)
                    cat_grade = cat_data.get("grade", "?")
                    cat_score = cat_data.get("score", 0)
                    gc = GRADE_COLORS.get(cat_grade, "white")
                    table.add_row(
                        cat_label,
                        Text(str(cat_score), style=gc),
                        Text(cat_grade, style=gc),
                    )
                self.console.print(table)
        else:
            print(f"\n  Score: {overall}/100 (Grade: {grade})")
            for cat_key, cat_data in categories.items():
                print(f"    {cat_key}: {cat_data.get('score', 0)} ({cat_data.get('grade', '?')})")

    def print_output_files(self, files: dict[str, str]) -> None:
        if not files:
            return
        if self._rich:
            self.console.print()
            for label, path in files.items():
                self.console.print(f"  {label}: [cyan]{path}[/cyan]")
        else:
            for label, path in files.items():
                print(f"  {label}: {path}")

    def print_summary_counts(self) -> None:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for sev, _, _, _ in self._findings:
            counts[sev] = counts.get(sev, 0) + 1

        if self._rich:
            parts = []
            for sev in ["critical", "high", "medium", "low", "info"]:
                if counts[sev] > 0:
                    color = SEVERITY_COLORS[sev]
                    parts.append(f"[{color}]{counts[sev]} {sev}[/{color}]")
            if parts:
                self.console.print(f"\n  Total: {' | '.join(parts)}")
        else:
            non_zero = [f"{c} {s}" for s, c in counts.items() if c > 0]
            if non_zero:
                print(f"\n  Total: {' | '.join(non_zero)}")

    def print_cta(self) -> None:
        if self._rich:
            cta = Text()
            cta.append("\n  Want dashboards, history & team scans?\n", style="bold")
            cta.append("  Try VibeCrack Cloud ", style="dim")
            cta.append("https://vibecrack.com", style="bold magenta underline")
            self.console.print(Panel(cta, border_style="magenta", padding=(0, 1)))
        else:
            print("\n" + "=" * 50)
            print("  Want dashboards, history & team scans?")
            print("  Try VibeCrack Cloud -> https://vibecrack.com")
            print("=" * 50)

    def print_error(self, message: str) -> None:
        if self._rich:
            self.console.print(f"  [bold red]Error:[/bold red] {message}")
        else:
            print(f"  Error: {message}", file=sys.stderr)
