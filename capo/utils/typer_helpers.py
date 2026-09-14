"""Shared Typer utilities."""

from collections.abc import Callable

import click
import typer


def fallback_group(callback: Callable[[list[str]], None]) -> type[typer.core.TyperGroup]:
    """Create a TyperGroup subclass that routes unknown subcommands to *callback*.

    Usage:
        def _my_fallback(args: list[str]):
            ...

        app = typer.Typer(cls=fallback_group(_my_fallback))
    """

    class _FallbackGroup(typer.core.TyperGroup):
        def resolve_command(self, ctx, args):
            if not args:
                return super().resolve_command(ctx, args)
            cmd_name = click.utils.make_str(args[0])
            cmd = self.get_command(ctx, cmd_name)
            if cmd is not None:
                return super().resolve_command(ctx, args)
            callback(list(args))
            return "_fallback", click.Command("_fallback", callback=lambda: None), []

    return _FallbackGroup
