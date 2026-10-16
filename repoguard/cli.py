"""Command-line interface for RepoGuard with Rich terminal output and CI/CD support."""

import argparse
import json
import os
import sys
from typing import Optional

from repoguard import __version__
from repoguard.evaluator import evaluate_repository, evaluate_directory
from repoguard.models import EvaluationResult, Severity, TrustLevel

# Ensure UTF-8 output encoding on Windows consoles
if sys.platform == "win32":
    try:
        if sys.stdout and hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        if sys.stderr and hasattr(sys.stderr, "reconfigure"):
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:  # pragma: no cover
        pass

# Try importing rich for premium console aesthetics
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    HAS_RICH = True
except ImportError:  # pragma: no cover
    HAS_RICH = False


def print_rich_report(result: EvaluationResult, console: "Console") -> None:
    """Renders a beautiful terminal report using Rich."""
    # Score color coding
    if result.trust_level == TrustLevel.TRUSTED:
        score_color = "bold green"
        badge_color = "green"
    elif result.trust_level == TrustLevel.MODERATE:
        score_color = "bold yellow"
        badge_color = "yellow"
    elif result.trust_level == TrustLevel.SUSPICIOUS:
        score_color = "bold dark_orange"
        badge_color = "dark_orange"
    else:
        score_color = "bold red"
        badge_color = "red"

    # Header
    console.print()
    banner = Text("🛡️  RepoGuard ", style="bold cyan")
    banner.append(f"v{__version__}  |  Repository Trust & Security Inspector", style="dim")
    console.print(Panel(banner, border_style="cyan"))

    # Trust Score Panel
    score_text = Text()
    score_text.append(f"{result.score:.1f}", style=score_color)
    score_text.append(" / 10.0   ", style="bold white")
    score_text.append(f"[{result.trust_level.value}]", style=f"bold {badge_color}")

    console.print(Panel(score_text, title=f"Target: [bold]{result.target}[/bold]", subtitle="Final Trust Score", border_style=badge_color))

    # Metadata Table (if present)
    if result.metadata and not result.metadata.get("error"):
        meta = result.metadata
        table = Table(title="Repository Metadata", show_header=True, header_style="bold blue")
        table.add_column("Property", style="dim", width=20)
        table.add_column("Value", style="white")

        table.add_row("Repository", str(meta.get("full_name") or result.target))
        table.add_row("Stars", f"{meta.get('stars', 0):,}")
        table.add_row("Forks", f"{meta.get('forks', 0):,}")
        table.add_row("Open Issues", f"{meta.get('open_issues', 0):,}")
        table.add_row("License", str(meta.get("license") or "[red]None[/red]"))
        table.add_row("Archived", "[red]Yes[/red]" if meta.get("is_archived") else "[green]No[/green]")
        table.add_row("Last Pushed", str(meta.get("pushed_at") or meta.get("last_updated") or "Unknown"))

        console.print(table)
    elif result.metadata and result.metadata.get("error"):
        console.print(f"[yellow]⚠️  Metadata warning: {result.metadata['error']}[/yellow]")

    # Evaluation Reasons Breakdown
    if result.reasons:
        console.print("\n[bold]Scoring Factors & Explanations:[/bold]")
        for reason in result.reasons:
            if "CRITICAL" in reason or "HIGH RISK" in reason or "No open source license" in reason:
                console.print(f"  [red]✖[/red] {reason}")
            elif "Clean" in reason or "Strong" in reason or "Healthy" in reason or "Active" in reason or "Clear open source" in reason:
                console.print(f"  [green]✔[/green] {reason}")
            else:
                console.print(f"  [yellow]•[/yellow] {reason}")

    # Code Scan Results Table
    if result.scan_result:
        scan = result.scan_result
        if scan.error:
            console.print(f"\n[red]Code Scan Error: {scan.error}[/red]")
        else:
            console.print(
                f"\n[bold]Code Scan Summary:[/bold] Scanned [cyan]{scan.scanned_files_count}[/cyan] files  |  "
                f"[bold red]{scan.critical_count} Critical[/bold red], "
                f"[bold yellow]{scan.high_count} High[/bold yellow], "
                f"[cyan]{scan.medium_count} Medium[/cyan], "
                f"[dim]{scan.binary_files_count} Binaries[/dim]"
            )

            if scan.findings:
                f_table = Table(title="Detected Security & Obfuscation Findings", show_header=True, header_style="bold magenta")
                f_table.add_column("Severity", width=12)
                f_table.add_column("File:Line", width=35)
                f_table.add_column("Rule", width=22)
                f_table.add_column("Description", style="white")

                for f in scan.findings[:25]:  # Show top 25 findings to keep output concise
                    sev_style = "bold red" if f.severity == Severity.CRITICAL else "yellow" if f.severity == Severity.HIGH else "cyan"
                    loc = f"{f.filename}:{f.line}" if f.line else f.filename
                    f_table.add_row(f"[{sev_style}]{f.severity.value}[/{sev_style}]", loc, f.rule, f.description)

                console.print(f_table)
                if len(scan.findings) > 25:
                    console.print(f"[dim]... and {len(scan.findings) - 25} more findings omitted for brevity.[/dim]")

    console.print()


def print_plain_report(result: EvaluationResult) -> None:
    """Fallback plain text report when Rich is not available."""
    print("=" * 60)
    print(f"RepoGuard Evaluation: {result.target}")
    print(f"Final Trust Score: {result.score:.1f}/10.0 [{result.trust_level.value}]")
    print("=" * 60)

    if result.reasons:
        print("\nFactors:")
        for r in result.reasons:
            print(f" - {r}")

    if result.scan_result:
        scan = result.scan_result
        print(f"\nCode Scan: {scan.scanned_files_count} files scanned")
        print(f" - Critical: {scan.critical_count}")
        print(f" - High: {scan.high_count}")
        print(f" - Medium: {scan.medium_count}")
        print(f" - Binaries: {scan.binary_files_count}")

        if scan.findings:
            print("\nFindings:")
            for f in scan.findings[:20]:
                loc = f"{f.filename}:{f.line}" if f.line else f.filename
                print(f" [{f.severity.value}] {loc} - {f.rule}: {f.description}")


def run_cli(args_list: Optional[list] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="repoguard",
        description="RepoGuard: Automated trust, safety, and security intelligence for GitHub repositories.",
    )
    parser.add_argument("repo_target", help="GitHub repository URL (e.g. https://github.com/owner/repo) or local folder path")
    parser.add_argument("--token", "-t", default=None, help="GitHub Personal Access Token (defaults to GITHUB_TOKEN env var)")
    parser.add_argument("--local", "-l", action="store_true", help="Evaluate a local directory codebase instead of cloning from GitHub")
    parser.add_argument("--format", "-f", choices=["pretty", "json"], default="pretty", help="Output format (pretty or json)")
    parser.add_argument("--fail-under", type=float, default=None, help="Exit with code 1 if Trust Score is lower than this threshold (useful in CI/CD)")
    parser.add_argument("--skip-scan", action="store_true", help="Skip deep code cloning and static security scan")
    parser.add_argument("--timeout", type=int, default=60, help="Timeout in seconds for git cloning and network queries")
    parser.add_argument("--output", "-o", default=None, help="Save evaluation output to file")
    parser.add_argument("--version", "-v", action="version", version=f"RepoGuard {__version__}")

    args = parser.parse_args(args_list)

    try:
        if args.local or os.path.isdir(args.repo_target):
            # Local directory evaluation
            result = evaluate_directory(args.repo_target)
        else:
            # Remote GitHub repository evaluation
            result = evaluate_repository(
                repo_url=args.repo_target,
                github_token=args.token,
                scan_code=not args.skip_scan,
                scan_timeout=args.timeout,
            )
    except Exception as e:
        sys.stderr.write(f"Error evaluating repository: {e}\n")
        return 2

    # Render output
    if args.format == "json":
        json_output = json.dumps(result.to_dict(), indent=2)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(json_output)
        else:
            print(json_output)
    else:
        if HAS_RICH:
            try:
                console = Console()
                print_rich_report(result, console)
            except Exception:
                print_plain_report(result)
        else:
            print_plain_report(result)

        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                json.dump(result.to_dict(), f, indent=2)

    # Check fail-under threshold
    if args.fail_under is not None and result.score < args.fail_under:
        sys.stderr.write(f"\n[CI FAILURE] Repository Trust Score {result.score:.1f} is below required threshold {args.fail_under:.1f}\n")
        return 1

    return 0


def main() -> None:
    sys.exit(run_cli())


if __name__ == "__main__":  # pragma: no cover
    main()
