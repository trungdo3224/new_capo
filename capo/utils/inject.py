"""Variable injection for command templates.

Replaces ``{VAR}`` placeholders (e.g. ``{IP}``, ``{USER}``, ``{DOMAIN}``)
with values from a :class:`~capo.state.StateManager` instance.
"""

import re


def inject_vars(text: str, state_manager=None) -> str:
    """Replace ``{VAR}`` placeholders using *state_manager*.

    If *state_manager* is ``None`` the global singleton is used.
    """
    if state_manager is None:
        from capo.state import state_manager as _sm
        state_manager = _sm

    for var in re.findall(r"\{(\w+)\}", text):
        val = state_manager.get_var(var)
        if val:
            text = text.replace(f"{{{var}}}", val)
    return text
