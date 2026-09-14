"""Target management CLI commands (capo target)."""

import typer

from capo.campaign import campaign_manager
from capo.cli.helpers import require_target
from capo.errors import TargetError
from capo.state import state_manager
from capo.utils.display import (
    print_directory_tree,
    print_error,
    print_info,
    print_state_table,
    print_success,
)
from capo.utils.typer_helpers import fallback_group


def _target_fallback(args: list[str]):
    """Allow 'capo target 10.10.11.24' directly without typing 'set'."""
    if args:
        target_set(args[0])
    else:
        if not state_manager.target:
            print_info("No target currently set. Set one with: [cyan]capo target <IP>[/cyan]")
        else:
            print_state_table(state_manager.state, mgr=state_manager)


target_app = typer.Typer(
    help="Target management commands",
    cls=fallback_group(_target_fallback),
    invoke_without_command=True,
)


@target_app.callback()
def target_main(ctx: typer.Context):
    """Set or inspect the current engagement target."""
    if ctx.invoked_subcommand is None:
        if not state_manager.target:
            print_info("No target currently set. Set one with: [cyan]capo target <IP>[/cyan]")
        else:
            print_state_table(state_manager.state, mgr=state_manager)


@target_app.command("set")
def target_set(
    ip: str = typer.Argument(..., help="target IP or hostname"),
    domain: str | None = typer.Option(None, "--domain", "-d", help="target domain"),
    campaign: str | None = typer.Option(None, "--campaign", "-c", help="link to a campaign"),
):
    """Set the active target and initialize its workspace."""
    # Handle direct Python function invocation where defaults are OptionInfo
    if not isinstance(domain, str):
        domain = None
    if not isinstance(campaign, str):
        campaign = None

    if campaign:
        campaign_manager.set_campaign(campaign)

    try:
        workspace = state_manager.set_target(ip)
    except TargetError as e:
        print_error(str(e))
        raise typer.Exit(1)

    if domain:
        state_manager.add_domain(domain)

    print_success(f"Target set: [bold white]{ip}[/bold white]")
    if domain:
        print_info(f"Domain: {domain}")
    if campaign_manager.active:
        print_info(f"Campaign Active: {campaign_manager.name}")

    print_info(f"Workspace initialized: {workspace}")
    print_directory_tree(workspace)


@target_app.command("set-domain")
def target_set_domain(
    domain: str = typer.Argument(..., help="domain name"),
    dc_ip: str | None = typer.Option(None, "--dc-ip", help="Domain Controller IP"),
):
    """Add/set domain information for AD engagements."""
    if not state_manager.target and not campaign_manager.active:
        print_error("No target or campaign set.")
        raise typer.Exit(1)

    if campaign_manager.active:
        campaign_manager.update_domain_info(domain_name=domain, dc_ip=dc_ip)
    else:
        state_manager.add_domain(domain)
        if dc_ip:
            info = state_manager.get("domain_info", {})
            info["dc_ip"] = dc_ip
            state_manager.set("domain_info", info)

    print_success(f"Domain set: {domain}")
    domains = state_manager.get("domains", [])
    if len(domains) > 1:
        print_info(f"All domains: {', '.join(domains)}")


@target_app.command("set-lhost")
def target_set_lhost(
    lhost: str = typer.Argument(..., help="your attack machine IP"),
    lport: int = typer.Option(443, "--lport", "-p", help="listener port"),
):
    """Set your local host IP for reverse shells and pivoting."""
    require_target()
    state_manager.set("lhost", lhost)
    state_manager.set("lport", lport)
    print_success(f"LHOST={lhost}, LPORT={lport}")


@target_app.command("campaign")
def target_campaign(
    name: str = typer.Argument(None, help="campaign name"),
    clear: bool = typer.Option(False, "--clear", help="exit the current campaign"),
):
    """Set, show, or clear the active campaign."""
    if clear:
        campaign_manager.clear_campaign()
        print_success("Exited campaign. Operating in single-host mode.")
        return

    if name:
        campaign_manager.set_campaign(name)
        print_success(f"Campaign set: {name}")
        if state_manager.target:
            campaign_manager.add_host(str(state_manager.target))
            print_info(f"Host {state_manager.target} bound to campaign.")
    else:
        if campaign_manager.active:
            print_info(f"Active Campaign: {campaign_manager.name}")
        else:
            print_info("No active campaign. Operating in single-host mode.")
