"""State inspection & management CLI commands (capo state)."""

import typer

from capo.cli.helpers import print_json_data, require_target
from capo.state import state_manager
from capo.utils.display import (
    console,
    print_credentials_table,
    print_ports_table,
    print_state_table,
    print_warning,
)

state_app = typer.Typer(
    help="State whiteboard inspection commands",
    invoke_without_command=True,
)


@state_app.callback()
def state_main(
    ctx: typer.Context,
    as_json: bool = typer.Option(False, "--json", "-j", help="Output state as JSON"),
):
    """View the Tactical Whiteboard HUD (or raw JSON)."""
    if ctx.invoked_subcommand is None:
        require_target()
        if as_json:
            console.print_json(state_manager.export_state())
        else:
            print_state_table(state_manager.state, mgr=state_manager)


@state_app.command("show")
def state_show(
    as_json: bool = typer.Option(False, "--json", "-j", help="Output state as JSON"),
):
    """Show the Tactical Whiteboard HUD."""
    require_target()
    if as_json:
        console.print_json(state_manager.export_state())
    else:
        print_state_table(state_manager.state, mgr=state_manager)


@state_app.command("ports")
def state_ports(
    as_json: bool = typer.Option(False, "--json", help="output as JSON"),
):
    """Show discovered ports and services."""
    require_target()
    ports = state_manager.get("ports", [])
    if as_json:
        print_json_data(ports)
    elif ports:
        print_ports_table(ports)
    else:
        print_warning("No ports discovered yet. Run: capo scan quick")


@state_app.command("users")
def state_users(
    as_json: bool = typer.Option(False, "--json", help="output as JSON"),
):
    """Show discovered users."""
    require_target()
    users = state_manager.get("users", [])
    if as_json:
        print_json_data(users)
    elif users:
        for u in users:
            console.print(f"  [cyan]•[/cyan] {u}")
    else:
        print_warning("No users discovered yet.")


@state_app.command("creds")
def state_creds(
    as_json: bool = typer.Option(False, "--json", help="output as JSON"),
):
    """Show discovered credentials."""
    require_target()
    creds = state_manager.get("credentials", [])
    if as_json:
        print_json_data(creds)
    elif creds:
        print_credentials_table(creds)
    else:
        print_warning("No credentials discovered yet.")


@state_app.command("shares")
def state_shares(
    as_json: bool = typer.Option(False, "--json", help="output as JSON"),
):
    """Show discovered network shares."""
    require_target()
    shares = state_manager.get("shares", [])
    if as_json:
        print_json_data(shares)
    elif shares:
        from rich.table import Table
        table = Table(title="Discovered Shares", border_style="cyan")
        table.add_column("Share", style="bold green")
        table.add_column("Permissions", style="yellow")
        table.add_column("Comment", style="dim")
        for s in shares:
            table.add_row(s.get("name", ""), s.get("permissions", ""), s.get("comment", ""))
        console.print(table)
    else:
        print_warning("No shares discovered yet.")


@state_app.command("dirs")
def state_dirs(
    as_json: bool = typer.Option(False, "--json", help="output as JSON"),
):
    """Show discovered web directories."""
    require_target()
    dirs = state_manager.get("directories", [])
    if as_json:
        print_json_data(dirs)
    elif dirs:
        from rich.table import Table
        table = Table(title="Discovered Directories", border_style="cyan")
        table.add_column("Path", style="cyan")
        table.add_column("Status", style="green", justify="right")
        for d in dirs:
            table.add_row(d.get("path", ""), str(d.get("status", "")))
        console.print(table)
    else:
        print_warning("No directories discovered yet.")
