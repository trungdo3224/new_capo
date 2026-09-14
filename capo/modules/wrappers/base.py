"""Base wrapper class for all tool integrations.

Every tool wrapper inherits from this base and provides:
- Transparent command printing before execution
- Raw output saving to workspace
- State updates from parsed output
- Rate limiting via scan profiles
"""

import shlex
import shutil
import subprocess
import threading
import time
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from rich.status import Status

from capo.config import SCAN_PROFILES
from capo.errors import TargetError, ToolNotFoundError
from capo.state import state_manager
from capo.utils.display import (
    console,
    print_command,
    print_error,
    print_success,
    print_warning,
)


def _show_next_steps(wrapper: "BaseWrapper"):
    """Display top next-step suggestions after a scan completes."""
    try:
        suggestions = wrapper.get_suggestions()
        if suggestions:
            console.print()
            console.print("[bold yellow][Tip] Suggested next steps:[/bold yellow]")
            for title, cmd in suggestions[:3]:
                console.print(f"   [dim]→[/dim] {title}: [cyan]{cmd}[/cyan]")
            console.print()
    except Exception:
        pass  # never fail on suggestion display


def _auto_check_methodologies():
    """Auto-complete methodology steps after a scan finishes."""
    try:
        from capo.modules.methodology import methodology_engine

        methodology_engine.load_all()
        results = methodology_engine.auto_check_all_active()
        if results:
            console.print()
            for mname, sids in results.items():
                meth = methodology_engine.get(mname)
                step_map = {s.id: s for s in meth.steps} if meth else {}
                for sid in sids:
                    sn = step_map.get(sid)
                    label = sn.name if sn else sid
                    console.print(f"   [green]✓[/green] [bold]{mname}[/bold]: {label}")
    except Exception:
        pass  # never fail on methodology check


class BaseWrapper(ABC):
    """Abstract base class for tool wrappers."""

    tool_name: str = "unknown"
    binary_name: str = "unknown"

    def __init__(self, profile: str = "normal", dry_run: bool = False):
        self.profile = profile
        self.dry_run = dry_run
        self.profile_config = SCAN_PROFILES.get(profile, SCAN_PROFILES["normal"])

    def is_available(self) -> bool:
        """Check if the tool binary is installed."""
        return shutil.which(self.binary_name) is not None

    def _check_target(self) -> bool:
        """Ensure a target is set. Raises TargetError if not."""
        if state_manager.target is None:
            raise TargetError("No target set. Use: capo target set <IP>")
        return True

    @staticmethod
    def _resolve_target(target: str | None) -> str:
        """Return *target* if given, otherwise fall back to state."""
        resolved = target or state_manager.target
        if not resolved:
            raise TargetError("No target set. Use: capo target set <IP>")
        return resolved

    def _output_dir(self) -> Path:
        """Get the scan output directory for the current target."""
        if state_manager.workspace is None:
            raise TargetError("No target set. Use: capo target set <IP>")
        return state_manager.workspace / "scans"

    def _output_file(self, suffix: str = "") -> Path:
        """Generate a timestamped output filename."""
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        name = f"{self.tool_name}_{ts}"
        if suffix:
            name += f"_{suffix}"
        return self._output_dir() / name

    def execute(self, cmd_args: list[str], output_file: Path | None = None,
                parse_output: bool = True, timeout: int = 0,
                dry_run: bool = False,
                stream_output: bool = False) -> subprocess.CompletedProcess | None:
        """Execute a command with transparency and logging.

        1. Prints the full command (OSCP compliance)
        2. Runs the command (unless dry_run=True)
        3. Saves raw output
        4. Optionally parses and updates state

        When stream_output=True, stdout/stderr are printed in real-time
        instead of buffered (useful for long-running tools like nmap).

        Raises TargetError if no target is set.
        Raises ToolNotFoundError if the binary is not in PATH.
        """
        self._check_target()

        cmd_str = " ".join(shlex.quote(a) for a in cmd_args)
        print_command(cmd_str)

        if dry_run or self.dry_run:
            print_warning("[DRY-RUN] Command not executed.")
            return None

        if not self.is_available():
            raise ToolNotFoundError(self.binary_name)

        try:
            t0 = time.monotonic()

            if stream_output:
                result = self._execute_streaming(cmd_args, timeout)
            else:
                kwargs: dict[str, Any] = {
                    "capture_output": True,
                    "text": True,
                }
                if timeout > 0:
                    kwargs["timeout"] = timeout

                with Status(
                    f"[bold cyan]Running {self.tool_name}...[/bold cyan]",
                    console=console,
                    spinner="dots",
                ):
                    result = subprocess.run(cmd_args, **kwargs)  # noqa: S603

            elapsed = time.monotonic() - t0

            # Save raw output
            if output_file:
                output_file.parent.mkdir(parents=True, exist_ok=True)
                with open(output_file, "w", encoding="utf-8") as f:
                    f.write(f"# Command: {cmd_str}\n")
                    f.write(f"# Timestamp: {datetime.now(timezone.utc).isoformat()}\n")
                    f.write(f"# Exit Code: {result.returncode}\n\n")
                    f.write("=== STDOUT ===\n")
                    f.write(result.stdout or "")
                    f.write("\n=== STDERR ===\n")
                    f.write(result.stderr or "")

            # Record scan in state
            state_manager.add_scan_record(
                tool=self.tool_name,
                command=cmd_str,
                output_file=str(output_file) if output_file else "",
                duration=round(elapsed, 1),
            )

            # Record in session database (no-op if no active session)
            from capo.modules.session_db import session_db
            session_db.record_command(
                tool=self.tool_name,
                command=cmd_str,
                output_file=str(output_file) if output_file else "",
                exit_code=result.returncode,
                duration=round(elapsed, 1),
            )

            if result.returncode == 0:
                print_success(f"{self.tool_name} completed in {elapsed:.1f}s")
            else:
                print_warning(f"{self.tool_name} exited with code {result.returncode} ({elapsed:.1f}s)")
                if result.stderr:
                    for line in result.stderr.strip().split("\n")[:5]:
                        print_warning(f"  {line}")

            if parse_output and result.returncode == 0:
                self.parse_output(result, output_file)
                from capo.config import output_config
                if not output_config.quiet:
                    _show_next_steps(self)
                    _auto_check_methodologies()

            return result

        except subprocess.TimeoutExpired:
            print_error(f"{self.tool_name} timed out after {timeout}s")
            return None
        except FileNotFoundError:
            print_error(f"{self.binary_name} binary not found")
            return None

    def _execute_streaming(self, cmd_args: list[str], timeout: int) -> subprocess.CompletedProcess:
        """Run a command and print stdout/stderr lines as they arrive."""
        stdout_chunks: list[str] = []
        stderr_chunks: list[str] = []

        def _reader(stream, chunks, style: str = ""):
            for line in iter(stream.readline, ""):
                chunks.append(line)
                text = line.rstrip()
                if text:
                    console.print(text if not style else f"[{style}]{text}[/{style}]")
            stream.close()

        proc = subprocess.Popen(  # noqa: S603
            cmd_args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )

        t_out = threading.Thread(target=_reader, args=(proc.stdout, stdout_chunks))
        t_err = threading.Thread(target=_reader, args=(proc.stderr, stderr_chunks, "dim red"))
        t_out.start()
        t_err.start()

        try:
            proc.wait(timeout=timeout if timeout > 0 else None)
        except subprocess.TimeoutExpired:
            proc.kill()
            raise
        finally:
            t_out.join()
            t_err.join()

        return subprocess.CompletedProcess(
            args=cmd_args,
            returncode=proc.returncode,
            stdout="".join(stdout_chunks),
            stderr="".join(stderr_chunks),
        )

    @abstractmethod
    def parse_output(self, result: subprocess.CompletedProcess, output_file: Path | None):
        """Parse tool output and update state. Must be implemented by subclasses."""
        ...

    @abstractmethod
    def get_suggestions(self) -> list[tuple[str, str]]:
        """Return context-aware suggestions based on current state.

        Returns list of (title, command_hint) tuples.
        """
        ...
