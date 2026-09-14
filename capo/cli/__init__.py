"""C.A.P.O CLI package — registers core command groups."""

import typer

from capo import __version__
from capo.config import ensure_dirs
from capo.utils.display import banner, console

# Initialize Typer app
app = typer.Typer(
    name="capo",
    help="C.A.P.O - Context-Aware Pentest Orchestrator",
    no_args_is_help=True,
    rich_markup_mode="rich",
)


# ─────────────── Global Callback ───────────────

@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    version: bool = typer.Option(False, "--version", "-v", help="show version"),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="suppress banners"),
    verbose: bool = typer.Option(False, "--verbose", help="full output"),
):
    """C.A.P.O - Context-Aware Pentest Orchestrator."""
    ensure_dirs()
    from capo.config import output_config
    if verbose:
        output_config.quiet = False
    elif quiet:
        output_config.quiet = True
    if version:
        console.print(f"C.A.P.O v{__version__}")
        raise typer.Exit()
    if ctx.invoked_subcommand is None:
        banner()


# ─────────────── Register Core Sub-Apps ───────────────

from capo.cli.add import add_app
from capo.cli.scan import scan_app
from capo.cli.state_cmds import state_app
from capo.cli.target import target_app

app.add_typer(target_app, name="target")
app.add_typer(scan_app, name="scan")
app.add_typer(add_app, name="add")
app.add_typer(state_app, name="state")

# Convenient alias for 'capo set target <IP>'
set_app = typer.Typer(help="Set engagement properties", no_args_is_help=True)


@set_app.command("target")
def set_target_cmd(
    ip: str = typer.Argument(..., help="target IP or hostname"),
    domain: str | None = typer.Option(None, "--domain", "-d", help="target domain"),
):
    """Alias to set active target (capo set target <IP>)."""
    from capo.cli.target import target_set
    target_set(ip, domain=domain)


app.add_typer(set_app, name="set")
