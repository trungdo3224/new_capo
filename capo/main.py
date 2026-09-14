"""C.A.P.O - Context-Aware Pentest Orchestrator.

Main CLI entry point using Typer with Rich formatting.
"""

from capo.cli import app  # noqa: F401

if __name__ == "__main__":
    try:
        app()
    except Exception as e:
        from rich.console import Console
        Console().print(f"\n[bold red]Capo Error:[/bold red] {e}")

