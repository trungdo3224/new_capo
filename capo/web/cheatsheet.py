"""Offline quick references derived from the same rules used by the web cycle."""

from copy import deepcopy

from .playbooks import BOOKS, BY_ID


def select(topic=None, query=None, advanced_only=False):
    """Return independent snapshots; unknown topics never silently select all rules."""
    if topic and topic not in BY_ID:
        raise ValueError(f"Unknown topic: {topic}. Use capo web cheatsheet to list topic IDs.")
    books = [BY_ID[topic]] if topic else BOOKS
    if advanced_only:
        books = [b for b in books if b.get("category") == "advanced"]
    words = (query or "").casefold().split()
    matches = [b for b in books if all(w in str(b).casefold() for w in words)]
    if not matches:
        raise ValueError("No matching cheatsheets. Use capo web cheatsheet to list topic IDs.")
    return deepcopy(matches)


def markdown(books):
    lines = [
        "# Capo web pentesting cheatsheet",
        "",
        "Observe -> hypothesize -> select a test -> compare evidence -> assess -> revisit.",
        "",
        "Keep method, body, headers and identity consistent except for the variable under test.",
        "Record requests, responses, identity, object ownership and resulting application state.",
        "Tool matches remain signals. Record a conclusion with evidence before confirming.",
        "",
    ]
    for b in books:
        prerequisites = {
            "request": "A captured working request with the intended identity.",
            "two_owned_identities": "Two separate test accounts and known objects owned by each.",
        }
        lines.extend([
            f"## {b['title']} ({b['id']})",
            "",
            f"Playbook version: {b['version']}",
            "",
            "### Look for",
            "",
            ", ".join(b["triggers"]) if b["id"] != "mapping" else "Every scoped application.",
            "",
            "### Before testing",
            "",
            *[prerequisites.get(p, p) for p in b["prerequisites"]],
            "Record the expected behavior and verify a working session where required.",
            "",
            "### Test procedure",
            "",
            b["procedure"],
            "",
            "### Controlled comparison",
            "",
            b["comparison"],
            "",
            "### Confirmation criteria",
            "",
            b["confirmation"],
            "",
            "### Common mistakes",
            "",
            b["pitfalls"],
            "",
            "### Tools and evidence",
            "",
            (
                "Manual procedure: use a browser, proxy or protocol-aware test client; "
                "Capo adapters cannot execute this technique."
                if b.get("manual_only") else
                f"Available adapter: {b['tool']}. Use capo web suggest to select an action; "
                "capo web run ACTION_ID --tool TOOL --dry-run previews its request. "
                "Replay does not automatically perform the comparisons described above."
            ),
            "Attach browser/proxy evidence using:",
            'capo web observe "Observation" --action ACTION_ID --file FILE',
            "Assess the attempt with capo web assess, then run capo web suggest again.",
            "",
            "### Revisit next",
            "",
            ", ".join(f"{BY_ID[key]['title']} ({key})" for key in b["followups"]),
            "",
            "### Knowledge references",
            "",
            *[
                f"- [{reference}]({reference})" if reference.startswith("https://")
                else f"- {reference}" for reference in b["references"]
            ],
            "",
            "Local paths identify knowledge documents; use capo web knowledge search for indexed",
            "passages. External links are references only and are not fetched automatically.",
            "",
        ])
    return "\n".join(lines)
