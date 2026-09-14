"""Automated Scanning CLI commands (capo scan)."""

import typer

from capo.cli.helpers import ensure_target
from capo.modules.wrappers.nmap_wrapper import NmapWrapper
from capo.state import state_manager
from capo.utils.display import print_info, print_state_table

scan_app = typer.Typer(help="Automated Nmap scanning commands")


@scan_app.command("quick")
def scan_quick(
    target: str | None = typer.Argument(None, help="target IP (current if omitted)"),
    profile: str = typer.Option("normal", "--profile", "-p", help="scan profile: aggressive/normal/stealth"),
    dry_run: bool = typer.Option(False, "--dry-run", help="print command without executing"),
):
    """Quick all-ports TCP scan with Nmap (-p- --min-rate)."""
    ensure_target(target)
    nmap = NmapWrapper(profile=profile, dry_run=dry_run)
    nmap.quick_scan(target)
    if not dry_run:
        print_state_table(state_manager.state, mgr=state_manager)


@scan_app.command("detailed")
def scan_detailed(
    ports: str | None = typer.Option(None, "--ports", "-p", help="ports to scan (comma-separated)"),
    target: str | None = typer.Argument(None, help="target IP (current if omitted)"),
    profile: str = typer.Option("normal", "--profile", help="scan profile: aggressive/normal/stealth"),
    dry_run: bool = typer.Option(False, "--dry-run", help="print command without executing"),
):
    """Detailed version and script scan (-sC -sV) on discovered ports."""
    ensure_target(target)
    nmap = NmapWrapper(profile=profile, dry_run=dry_run)
    nmap.detailed_scan(ports, target)
    if not dry_run:
        print_state_table(state_manager.state, mgr=state_manager)


@scan_app.command("udp")
def scan_udp(
    target: str | None = typer.Argument(None, help="target IP (current if omitted)"),
    profile: str = typer.Option("normal", "--profile", help="scan profile: aggressive/normal/stealth"),
    dry_run: bool = typer.Option(False, "--dry-run", help="print command without executing"),
):
    """UDP top-ports scan."""
    ensure_target(target)
    nmap = NmapWrapper(profile=profile, dry_run=dry_run)
    nmap.udp_scan(target)
    if not dry_run:
        print_state_table(state_manager.state, mgr=state_manager)


@scan_app.command("custom")
def scan_custom(
    target: str | None = typer.Argument(None, help="target IP (current if omitted)"),
    nmap_args: str = typer.Option(..., "--args", "-a", help="custom nmap flags, e.g. '-p 80,443 -sC -sV'"),
    dry_run: bool = typer.Option(False, "--dry-run", help="print command without executing"),
):
    """Custom nmap scan — pass any nmap flags while results parse automatically into state."""
    ensure_target(target)
    nmap = NmapWrapper(dry_run=dry_run)
    nmap.custom_scan(nmap_args, target)
    if not dry_run:
        print_state_table(state_manager.state, mgr=state_manager)


@scan_app.command("full")
def scan_full(
    target: str | None = typer.Argument(None, help="target IP (current if omitted)"),
    profile: str = typer.Option("normal", "--profile", help="scan profile: aggressive/normal/stealth"),
    dry_run: bool = typer.Option(False, "--dry-run", help="print command without executing"),
):
    """Run full automated recon pipeline: quick TCP -> detailed -> HUD."""
    ensure_target(target)
    nmap = NmapWrapper(profile=profile, dry_run=dry_run)

    print_info("=== Phase 1: Quick all-ports scan ===")
    nmap.quick_scan(target)

    print_info("=== Phase 2: Detailed scan on open ports ===")
    nmap.detailed_scan(target=target)

    if not dry_run:
        print_state_table(state_manager.state, mgr=state_manager)
