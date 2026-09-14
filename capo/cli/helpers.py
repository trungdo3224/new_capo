"""Shared CLI helpers used across command groups."""

import json

import typer

from capo.errors import TargetError
from capo.state import state_manager
from capo.utils.display import (
    console,
    print_error,
    print_success,
    print_warning,
)


def require_target():
    """Exit with error if no target is set. Use for commands that read state only."""
    if not state_manager.target:
        print_error("No target set. Use: capo target set <IP>")
        raise typer.Exit(1)


def ensure_target(target: str | None):
    """Ensure we have a target set (from arg or current state).

    When an explicit target is provided, it always takes effect — even if
    a different target is already stored in state.  This prevents the
    confusing case where ``capo scan quick 10.10.10.200`` silently runs
    against a previously-set 10.10.10.100.

    Prints a clean error and exits if no target is available.
    """
    if target:
        try:
            state_manager.set_target(target)
        except TargetError as e:
            print_error(str(e))
            raise typer.Exit(1)
    elif not state_manager.target:
        print_error("No target set. Use: capo target set <IP>")
        raise typer.Exit(1)


def print_json_data(data):
    """Dump data as JSON and print with Rich syntax highlighting."""
    console.print_json(json.dumps(data, indent=2))


def print_section_header(title: str):
    """Print a styled section header for search result grouping."""
    from rich.rule import Rule
    console.print(Rule(f"[bold cyan]{title}[/bold cyan]", style="dim cyan"))


def display_cheatsheet_results(results, copy: bool = False):
    """Display cheatsheet results with optional interactive selection."""
    from rich.panel import Panel

    for i, entry in enumerate(results, 1):
        injected_cmd = entry.inject_variables()
        source_badge = "[green][Core][/green]" if entry.source == "core" else "[yellow][Custom][/yellow]"

        console.print(Panel(
            f"[bold cyan]{entry.description}[/bold cyan]\n\n"
            f"[white]$ {injected_cmd}[/white]\n\n"
            f"[dim]Tool: {entry.tool}  |  Tags: {', '.join(entry.tags)}  |  "
            f"OS: {entry.os}  |  {source_badge}[/dim]"
            + (f"\n[dim yellow][Note] {entry.notes}[/dim yellow]" if entry.notes else ""),
            title=f"[bold white][{i}] {entry.name}[/bold white]",
            subtitle=f"[dim]{entry.category}[/dim]",
            border_style="cyan",
        ))

    if copy and results:
        try:
            import pyperclip
            # Use InquirerPy for interactive selection if available
            try:
                from InquirerPy import inquirer
                choices = [
                    {"name": f"[{i}] {e.name}: {e.inject_variables()[:60]}...", "value": i - 1}
                    for i, e in enumerate(results, 1)
                ]
                idx = inquirer.select(
                    message="Select command to copy:",
                    choices=choices,
                ).execute()
                if idx is not None:
                    cmd = results[idx].inject_variables()
                    pyperclip.copy(cmd)
                    print_success(f"Copied to clipboard: {cmd}")
            except ImportError:
                # Fallback: copy first result
                cmd = results[0].inject_variables()
                pyperclip.copy(cmd)
                print_success(f"Copied to clipboard: {cmd}")
        except ImportError:
            print_warning("pyperclip not installed. Install with: pip install pyperclip")
