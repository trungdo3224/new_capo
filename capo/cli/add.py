"""Manual whiteboard logging CLI commands (capo add)."""

import typer

from capo.cli.helpers import require_target
from capo.state import state_manager
from capo.utils.display import print_success, print_warning

add_app = typer.Typer(
    help="Add findings and facts to the target state whiteboard",
    no_args_is_help=True,
)


@add_app.command("os")
def add_os(
    os_name: str = typer.Argument(..., help="Operating system family/name (e.g. Windows, Linux)"),
):
    """Record target OS name or family."""
    require_target()
    state_manager.set_os(os_name)
    print_success(f"Target OS set to: [bold]{os_name}[/bold]")


@add_app.command("os-build")
def add_os_build(
    build: str = typer.Argument(..., help="OS build/kernel details (e.g. 'Server 2019 Build 17763')"),
):
    """Record target OS build or exact version."""
    require_target()
    state_manager.set_os_build(build)
    print_success(f"Target OS build set to: [bold]{build}[/bold]")


@add_app.command("domain")
def add_domain(
    domain_name: str = typer.Argument(..., help="Domain name (e.g. CORP.LOCAL)"),
    dc: bool = typer.Option(False, "--dc", help="Mark target as Domain Controller for this domain"),
):
    """Record Active Directory domain name."""
    require_target()
    state_manager.set_domain(domain_name, is_dc=dc)
    dc_str = " (Domain Controller)" if dc else ""
    print_success(f"Domain added: [bold]{domain_name}[/bold]{dc_str}")


@add_app.command("hostname")
def add_hostname(
    hostname: str = typer.Argument(..., help="Target hostname/computer name (e.g. DC01)"),
):
    """Record target hostname."""
    require_target()
    state_manager.set_hostname(hostname)
    print_success(f"Hostname set to: [bold]{hostname}[/bold]")


@add_app.command("arch")
def add_arch(
    arch: str = typer.Argument(..., help="Target architecture (x64, x86, arm)"),
):
    """Record target CPU architecture."""
    require_target()
    state_manager.set_arch(arch)
    print_success(f"Architecture set to: [bold]{arch}[/bold]")


@add_app.command("port")
def add_port(
    port: int = typer.Argument(..., help="Port number"),
    protocol: str = typer.Argument("tcp", help="Protocol (tcp/udp)"),
    service: str = typer.Argument("", help="Service name (e.g. http, smb)"),
    version: str = typer.Argument("", help="Software product and version"),
):
    """Record an open port and service."""
    require_target()
    state_manager.add_port(port, protocol.lower(), service.lower(), version)
    desc = f" ({service} - {version})" if version else (f" ({service})" if service else "")
    print_success(f"Port added: [bold]{port}/{protocol}[/bold]{desc}")


@add_app.command("user")
def add_user(
    username: str = typer.Argument(..., help="Discovered username"),
):
    """Record a valid username."""
    require_target()
    state_manager.add_user(username)
    print_success(f"User added: [bold]{username}[/bold]")


@add_app.command("cred")
def add_cred(
    username: str = typer.Argument(..., help="Username"),
    password: str = typer.Argument(..., help="Password"),
    service: str = typer.Argument("", help="Service where credential was found/verified (e.g. smb, ssh)"),
    admin: bool = typer.Option(False, "--admin", "-a", help="Credential has admin/privileged rights"),
):
    """Record discovered credentials."""
    require_target()
    state_manager.add_credential(username, password, service, is_admin=admin)
    admin_str = " [Pwn3d! / Admin]" if admin else ""
    svc_str = f" for {service}" if service else ""
    print_success(f"Credential added: [bold]{username}[/bold]:[cyan]{password}[/cyan]{svc_str}{admin_str}")


@add_app.command("hash")
def add_hash(
    hash_value: str = typer.Argument(..., help="Password hash string"),
    username: str = typer.Argument("", help="Associated username (optional)"),
    type_: str = typer.Option("", "--type", "-t", help="Hash type (e.g. ntlm, kerberos, sha512)"),
):
    """Record a password hash."""
    require_target()
    state_manager.add_hash(hash_value, username=username)
    user_str = f" for {username}" if username else ""
    print_success(f"Hash added{user_str}: {hash_value[:32]}...")


@add_app.command("share")
def add_share(
    name: str = typer.Argument(..., help="Share name (e.g. backups, IPC$)"),
    permissions: str = typer.Argument("READ", help="Permissions (READ, WRITE, READ/WRITE)"),
    comment: str = typer.Argument("", help="Share comment or notes"),
):
    """Record a network share."""
    require_target()
    state_manager.add_share(name, permissions=permissions, comment=comment)
    print_success(f"Share added: [bold]{name}[/bold] [{permissions}]")


@add_app.command("dir")
def add_dir(
    path: str = typer.Argument(..., help="Discovered web directory path (e.g. /admin)"),
    status: int = typer.Argument(200, help="HTTP status code (default: 200)"),
):
    """Record a discovered web directory."""
    require_target()
    state_manager.add_directory(path, status_code=status)
    print_success(f"Directory added: [bold]{path}[/bold] (Status: {status})")


@add_app.command("vhost")
def add_vhost(
    vhost: str = typer.Argument(..., help="Discovered virtual host / subdomain"),
):
    """Record a discovered virtual host."""
    require_target()
    state_manager.add_vhost(vhost)
    print_success(f"vHost added: [bold]{vhost}[/bold]")


@add_app.command("flag")
def add_flag(
    flag_type: str = typer.Argument(..., help="Flag type: user (local) or root (proof)"),
    value: str = typer.Argument(..., help="Flag content / hash string"),
):
    """Record a captured flag (user.txt or root.txt)."""
    require_target()
    state_manager.set_flag(flag_type, value)
    print_success(f"Flag captured [{flag_type}]: [bold]{value}[/bold]")


@add_app.command("note")
def add_note(
    text: str = typer.Argument(..., help="Note text"),
):
    """Add a quick scratchpad note for the target."""
    require_target()
    state_manager.add_note(text)
    print_success("Note added to scratchpad.")
