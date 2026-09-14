"""Display utilities using Rich for beautiful terminal output."""

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.tree import Tree

console = Console()


def banner():
    """Print the C.A.P.O banner."""
    banner_text = r"""
   ██████╗ ██╗ █████╗ ██████╗  ██████╗
  ██╔════╝ ██║██╔══██╗██╔══██╗██╔═══██╗
  ██║      ██║███████║██████╔╝██║   ██║
  ██║      ██║██╔══██║██╔═══╝ ██║   ██║
  ╚██████╗ ██║██║  ██║██║     ╚██████╔╝
   ╚═════╝ ╚═╝╚═╝  ╚═╝╚═╝      ╚═════╝
  Context-Aware Pentest Orchestrator
    """
    console.print(Panel(
        Text(banner_text, style="bold cyan"),
        subtitle="[dim]OSCP/CPTS Exam Companion[/dim]",
        border_style="cyan",
    ))


def print_command(command: str):
    """Print command before execution (transparency requirement)."""
    console.print(f"\n[bold yellow][+] Executing:[/bold yellow] [white]{command}[/white]")


def print_success(message: str):
    from capo.config import output_config
    if output_config.quiet:
        return
    console.print(f"[bold green][+][/bold green] {message}")


def print_error(message: str):
    console.print(f"[bold red][-][/bold red] {message}")


def print_warning(message: str):
    console.print(f"[bold yellow][!][/bold yellow] {message}")


def print_info(message: str):
    from capo.config import output_config
    if output_config.quiet:
        return
    console.print(f"[bold blue][*][/bold blue] {message}")


def print_suggestion(title: str, commands: list[str]):
    """Print context-aware suggestions after a scan."""
    from capo.config import output_config
    if output_config.quiet:
        return
    console.print()
    panel_content = ""
    for cmd in commands:
        panel_content += f"  → [cyan]{cmd}[/cyan]\n"
    console.print(Panel(
        panel_content.rstrip(),
        title=f"[bold yellow][Tip] {title}[/bold yellow]",
        border_style="yellow",
    ))


def print_state_table(state: dict, mgr=None):
    """Print the Tactical Whiteboard HUD."""
    _get = mgr.get if mgr is not None else state.get

    ip = state.get("ip", "N/A")
    hostname = state.get("hostname", "")
    os_name = state.get("os", "")
    os_build = state.get("os_build", "")
    arch = state.get("arch", "")
    domain_info = _get("domain_info", {})
    domain_name = domain_info.get("domain_name") or (state.get("domains", [""])[0] if state.get("domains") else "")
    is_dc = domain_info.get("is_dc", False)

    # 1. Target Card
    os_str = " | ".join(filter(None, [os_name, os_build, arch])) or "Unknown"
    dom_str = (domain_name + (" [bold red](Domain Controller)[/bold red]" if is_dc else "")) if domain_name else "None"
    host_str = f" ({hostname})" if hostname else ""

    target_table = Table(box=None, show_header=False, pad_edge=False)
    target_table.add_column("Key", style="bold cyan", width=12)
    target_table.add_column("Val", style="white")
    target_table.add_row("Target:", f"[bold white]{ip}[/bold white]{host_str}")
    target_table.add_row("OS:", f"[green]{os_str}[/green]")
    target_table.add_row("Domain:", f"[yellow]{dom_str}[/yellow]")

    console.print()
    console.print(Panel(target_table, title="[bold cyan]TARGET CARD[/bold cyan]", border_style="cyan"))

    # 2. Service Matrix
    ports = state.get("ports", [])
    open_ports = [p for p in ports if p.get("state") == "open"]
    shares = _get("shares", [])
    dirs = state.get("directories", [])
    vhosts = state.get("vhosts", [])

    if open_ports:
        svc_table = Table(title="[bold blue]SERVICE MATRIX[/bold blue]", border_style="blue", show_lines=False)
        svc_table.add_column("Port", style="bold white", justify="right")
        svc_table.add_column("Proto", style="dim", width=5)
        svc_table.add_column("Service", style="cyan")
        svc_table.add_column("Version", style="yellow")
        svc_table.add_column("Findings / Details", style="white")

        for p in sorted(open_ports, key=lambda x: x.get("port", 0)):
            port_num = p.get("port")
            proto = p.get("protocol", "tcp")
            svc_name = p.get("service", "")
            version = p.get("version", "")

            # Compile findings for this port
            details = []
            if svc_name == "smb" or port_num in (139, 445):
                for s in shares:
                    s_name = s.get("name", "") if isinstance(s, dict) else str(s)
                    s_perm = s.get("permissions", "") if isinstance(s, dict) else ""
                    perm_str = f" [{s_perm}]" if s_perm else ""
                    details.append(f"Share: [green]{s_name}[/green]{perm_str}")

            if "http" in svc_name or port_num in (80, 443, 8080, 8443):
                for d in dirs[:5]:
                    d_path = d.get("path", "") if isinstance(d, dict) else str(d)
                    d_code = d.get("status", "") if isinstance(d, dict) else ""
                    details.append(f"Dir: [cyan]{d_path}[/cyan] ({d_code})")
                if len(dirs) > 5:
                    details.append(f"... and {len(dirs) - 5} more dirs")
                for v in vhosts:
                    details.append(f"vHost: [magenta]{v}[/magenta]")

            detail_str = "\n".join(details) if details else "-"
            svc_table.add_row(str(port_num), proto, svc_name, version or "-", detail_str)
        console.print(svc_table)
    else:
        console.print("\n[dim]No open ports recorded yet. Run [cyan]capo scan quick[/cyan] or [cyan]capo add port <num>[/cyan][/dim]")

    # 3. Intel & Loot Vault
    users = _get("users", [])
    creds = _get("credentials", [])
    hashes = _get("hashes", [])
    flags = state.get("flags", {})

    has_loot = users or creds or hashes or any(flags.values())
    if has_loot:
        loot_table = Table(title="[bold yellow]INTEL & LOOT VAULT[/bold yellow]", border_style="yellow", show_lines=False)
        loot_table.add_column("Type", style="bold yellow", width=12)
        loot_table.add_column("Items", style="white")

        if users:
            user_str = ", ".join(f"[bold cyan]{u}[/bold cyan]" for u in users)
            loot_table.add_row("Users", user_str)
        if creds:
            cred_lines = []
            for c in creds:
                u = c.get("username", "?")
                pw = c.get("password", "?")
                svc = f" on {c['service']}" if c.get("service") else ""
                adm = " [bold red](Admin)[/bold red]" if c.get("is_admin") else ""
                cred_lines.append(f"{u}:{pw}{svc}{adm}")
            loot_table.add_row("Credentials", "\n".join(cred_lines))
        if hashes:
            hash_lines = [f"{h.get('username', '?')}: {h.get('hash', str(h))[:32]}..." if isinstance(h, dict) else str(h)[:32] + "..." for h in hashes]
            loot_table.add_row("Hashes", "\n".join(hash_lines))

        user_flag = flags.get("user_txt") or flags.get("local_txt")
        root_flag = flags.get("proof_txt")
        flag_parts = []
        flag_parts.append(f"user.txt: [bold green]{user_flag}[/bold green]" if user_flag else "user.txt: [dim]Not captured[/dim]")
        flag_parts.append(f"root.txt: [bold green]{root_flag}[/bold green]" if root_flag else "root.txt: [dim]Not captured[/dim]")
        loot_table.add_row("Flags", " | ".join(flag_parts))

        console.print(loot_table)

    # 4. Scratchpad Notes
    notes = state.get("notes", [])
    if notes:
        notes_table = Table(title="[bold white]SCRATCHPAD NOTES[/bold white]", border_style="dim white", show_lines=False)
        notes_table.add_column("#", style="dim", width=3)
        notes_table.add_column("Note", style="white")
        for i, n in enumerate(notes, 1):
            text = n.get("note", str(n)) if isinstance(n, dict) else str(n)
            notes_table.add_row(str(i), text)
        console.print(notes_table)
    console.print()


def print_ports_table(ports: list[dict]):
    """Print detailed port/service table."""
    from capo.config import output_config
    if output_config.quiet:
        return
    table = Table(title="Open Ports & Services", border_style="cyan")
    table.add_column("Port", style="bold white", justify="right")
    table.add_column("Proto", style="dim")
    table.add_column("State", style="green")
    table.add_column("Service", style="cyan")
    table.add_column("Version", style="yellow")

    for p in sorted(ports, key=lambda x: x.get("port", 0)):
        if p.get("state") == "open":
            table.add_row(
                str(p["port"]),
                p.get("protocol", "tcp"),
                p.get("state", ""),
                p.get("service", ""),
                p.get("version", ""),
            )
    console.print(table)


def print_credentials_table(creds: list[dict]):
    """Print credentials table."""
    table = Table(title="Discovered Credentials", border_style="red")
    table.add_column("Username", style="bold white")
    table.add_column("Password", style="red")
    table.add_column("Service", style="cyan")

    for c in creds:
        table.add_row(c.get("username", ""), c.get("password", ""), c.get("service", ""))
    console.print(table)


def print_directory_tree(workspace_path):
    """Print workspace directory tree."""
    from pathlib import Path

    workspace_path = Path(workspace_path)
    if not workspace_path.is_dir():
        print_warning(f"Directory not found: {workspace_path}")
        return

    tree = Tree(f"[Dir] {workspace_path.name}", style="bold cyan")
    try:
        for item in sorted(workspace_path.iterdir()):
            if item.is_dir():
                branch = tree.add(f"[Dir] {item.name}")
                try:
                    for sub in sorted(item.iterdir()):
                        branch.add(f"[File] {sub.name}")
                except PermissionError:
                    branch.add("[dim red][Denied] access denied[/dim red]")
            else:
                tree.add(f"[File] {item.name}")
    except PermissionError:
        print_warning(f"Permission denied: {workspace_path}")
        return
    console.print(tree)
