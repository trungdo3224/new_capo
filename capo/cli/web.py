"""Human-directed web testing CLI. All persistence belongs to Capo."""

import json
import sqlite3
from functools import wraps
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from capo.web import cheatsheet
from capo.web.cycle import describe, suggestions
from capo.web.knowledge import Knowledge
from capo.web.knowledge import explain as explain_question
from capo.web.store import Engagement, digest, home
from capo.web.tools import TOOLS, build, execute
from capo.web.tools import doctor as tool_doctor
from capo.web.traffic import import_har, import_raw, ingest_results

web_app = typer.Typer(help="Evidence-driven, repeating web testing cycle.", no_args_is_help=True)
knowledge_app = typer.Typer(help="Independent read-only Markdown retrieval.", no_args_is_help=True)
web_app.add_typer(knowledge_app, name="knowledge")
console = Console()


def guarded(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        try:
            return function(*args, **kwargs)
        except (ValueError, OSError, sqlite3.Error, KeyError, TypeError, AttributeError) as exc:
            console.print(f"Error: {exc}", style="red", markup=False)
            raise typer.Exit(1) from exc

    return wrapper


def emit(value):
    typer.echo(json.dumps(value, indent=2, ensure_ascii=False, default=str))


@web_app.command("cheatsheet")
@guarded
def show_cheatsheet(
    topic: str | None = typer.Argument(None, help="Playbook ID, such as sqli, idor or graphql."),
    search: str | None = typer.Option(None, "--search", help="Search all cheatsheet fields."),
    all_topics: bool = typer.Option(False, "--all", help="Show every complete cheatsheet."),
    as_json: bool = typer.Option(False, "--json", help="Return structured playbooks."),
    output: Path | None = typer.Option(None, "--output", help="Export Markdown; never overwrite."),
):
    """List, search, read or export web testing references without an active engagement."""
    books = cheatsheet.select(topic, search)
    display_cheatsheets(books, topic, search, all_topics, as_json, output, "cheatsheet")


def display_cheatsheets(books, topic, search, all_topics, as_json, output, command):
    if output:
        with output.open("x", encoding="utf-8") as file:
            file.write(cheatsheet.markdown(books))
        typer.echo(str(output.resolve()))
    elif as_json:
        emit(books)
    elif topic or search or all_topics:
        typer.echo(cheatsheet.markdown(books))
    else:
        typer.echo(f"Web references - use capo web {command} TOPIC to read a topic.\n")
        for book in books:
            typer.echo(f"{book['id']:10} {book['title']}")
        typer.echo("\nUse --search TEXT, --all, --json or --output FILE.md.")


@web_app.command("advanced")
@guarded
def advanced(
    topic: str | None = typer.Argument(None, help="Advanced topic ID, e.g. cache-poisoning."),
    search: str | None = typer.Option(None, "--search"),
    all_topics: bool = typer.Option(False, "--all"),
    as_json: bool = typer.Option(False, "--json"),
    output: Path | None = typer.Option(None, "--output", help="Export Markdown; never overwrite."),
):
    """Read advanced technique playbooks; use suggest --advanced for engagement tests."""
    books = cheatsheet.select(topic, search, advanced_only=True)
    display_cheatsheets(books, topic, search, all_topics, as_json, output, "advanced")


@web_app.command("init")
@guarded
def initialize(
    name: str,
    url: list[str] = typer.Option(
        ..., "--url", help="Exact allowed origin; repeat for additional applications."
    ),
):
    """Create and select an isolated web engagement."""
    engagement = Engagement.create(name, url)
    emit(
        {
            "engagement": name,
            "scope": engagement.scope,
            "workspace": engagement.path,
            "next": "capo web suggest",
        }
    )


@web_app.command("use")
@guarded
def use(name: str):
    """Resume a named engagement without resetting its records."""
    Engagement(name).use()
    typer.echo(f"Active web engagement: {name}")


@web_app.command("status")
@guarded
def status(as_json: bool = typer.Option(False, "--json")):
    engagement = Engagement()
    kinds = (
        "endpoint",
        "request",
        "identity",
        "hypothesis",
        "attempt",
        "assessment",
        "finding",
        "capability",
        "chain",
        "note",
    )
    counts = {kind: len(engagement.records(kind)) for kind in kinds}
    attempts = engagement.records("attempt")
    assessments = engagement.records("assessment")
    pending = [a["id"] for a in attempts if not any(c["attempt"] == a["id"] for c in assessments)]
    emit(
        {
            "engagement": engagement.name,
            "scope": engagement.scope,
            "counts": counts,
            "awaiting_assessment": pending,
            "workspace": engagement.path,
        }
    )


@web_app.command("import")
@guarded
def import_file(
    file: Path,
    format: str = typer.Option(
        ..., "--format", help="har, request, curl, ffuf, katana, sqlmap or nuclei"
    ),
    url: str | None = typer.Option(None, "--url"),
    identity: str = typer.Option("anonymous", "--identity"),
):
    """Import traffic or scanner output; never infer confirmed findings."""
    engagement = Engagement()
    if format not in {"har", "request", *TOOLS}:
        raise ValueError("Unsupported import format.")
    data = file.read_bytes()
    evidence = engagement.evidence(data, f"Imported {file.name}", file.suffix or ".bin")
    if format == "har":
        result = import_har(engagement, data, identity, evidence)
    elif format == "request":
        result = {"request": import_raw(engagement, data, url, identity, evidence)}
    else:
        result = ingest_results(engagement, format, data.decode("utf-8"), evidence, url)
    emit({"evidence": evidence, **result})


@web_app.command("observe")
@guarded
def observe(
    text: str,
    url: str | None = typer.Option(None, "--url"),
    evidence_file: Path | None = typer.Option(None, "--file"),
    evidence: list[str] | None = typer.Option(None, "--evidence"),
    action: str | None = typer.Option(
        None, "--action", help="Attach a manual test attempt to this action."
    ),
    identity: str | None = typer.Option(None, "--identity"),
    role: str = typer.Option("user", "--role"),
    objects: list[str] | None = typer.Option(
        None, "--object", help="Known owned object; repeat as needed."
    ),
):
    """Record an observation, manual test, or named identity with owned objects."""
    engagement = Engagement()
    if identity:
        prior = next((r for r in engagement.records("identity") if r["name"] == identity), None)
        data = {"name": identity, "role": role, "objects": objects or [], "description": text}
        if prior:
            engagement.update(prior["id"], **data)
            emit({"identity": prior["id"]})
        else:
            emit({"identity": engagement.put("identity", data, key=identity)})
        return
    if action:
        selected = engagement.get(action, "action")
        if url and engagement.check_url(url) != selected["url"]:
            raise ValueError("Observation URL does not match the selected action.")
        url = selected["url"]
    if not url:
        raise ValueError("Supply --url or --action (or register an --identity).")
    url = engagement.check_url(url)
    evidence = list(evidence or [])
    for item in evidence:
        engagement.evidence_path(item)
    if evidence_file:
        evidence.append(
            engagement.evidence(
                evidence_file.read_bytes(), evidence_file.name, evidence_file.suffix or ".bin"
            )
        )
    if not evidence:
        evidence.append(engagement.evidence(text, "Manual observation"))
    engagement.put("endpoint", {"url": url, "method": "GET"}, key=url)
    observation = engagement.put(
        "observation",
        {"url": url, "text": text, "evidence": evidence, "action": action},
        key=digest([url, text, evidence, action]),
    )
    result = {"observation": observation, "evidence": evidence}
    if action:
        result["attempt"] = engagement.put(
            "attempt",
            {
                "action": action,
                "execution": "manual",
                "evidence": evidence,
                "observation": observation,
            },
        )
    emit(result)


@web_app.command("note")
@guarded
def note(text: str):
    """Add a note included in this engagement's explanation context."""
    emit({"note": Engagement().put("note", {"text": text})})


@web_app.command("next", hidden=True)
@web_app.command("suggest")
@guarded
def next_actions(
    all_actions: bool = typer.Option(False, "--all"),
    as_json: bool = typer.Option(False, "--json"),
    advanced_only: bool = typer.Option(False, "--advanced", help="Only advanced technique tests."),
):
    """Recompute relevant tests; completed unchanged tests stay suppressed."""
    rows = suggestions(Engagement(), all_actions)
    if advanced_only:
        rows = [row for row in rows if row["category"] == "advanced"]
    if as_json:
        emit(rows)
        return
    table = Table(title="Suggested web tests")
    for label in ("Action", "Test", "URL", "Reason / prerequisites"):
        table.add_column(label)
    from rich.text import Text

    for row in rows[:30]:
        reason = "; ".join(row["missing"]) or row["reason"]
        if row["suppressed"]:
            reason = "Already attempted / awaiting review. " + reason
        if row["manual_only"]:
            reason = "Manual procedure. " + reason
        table.add_row(*[Text(str(v)) for v in (row["id"], row["title"], row["url"], reason)])
    console.print(table)
    typer.echo("Use capo web show ACTION to inspect procedure, controls and expected evidence.")
    if len(rows) > 30:
        typer.echo(f"Showing 30 of {len(rows)}; use --json for all actions.")


@web_app.command("show")
@guarded
def show(identifier: str):
    """Inspect an action, source evidence, finding or any other record."""
    engagement = Engagement()
    row = engagement.get(identifier)
    emit(describe(engagement, identifier) if row["kind"] == "action" else row)


@web_app.command("run")
@guarded
def run(
    action_id: str,
    tool: str = typer.Option("curl", "--tool"),
    request: str | None = typer.Option(None, "--request"),
    parameter: str | None = typer.Option(None, "--parameter"),
    comparison: str | None = typer.Option(None, "--comparison"),
    wordlist: Path | None = typer.Option(None, "--wordlist"),
    template: Path | None = typer.Option(None, "--template"),
    rate: int = typer.Option(2, "--rate"),
    timeout: int = typer.Option(60, "--timeout"),
    dry_run: bool = typer.Option(False, "--dry-run"),
):
    """Execute only the selected test, or preview without writing/executing anything."""
    engagement = Engagement()
    action = engagement.get(action_id, "action")
    command = build(
        engagement, action, tool, request, parameter, comparison, wordlist, template, rate, timeout
    )
    emit(command.preview())
    if dry_run:
        return
    result = execute(engagement, action, command)
    emit(result)
    typer.echo(
        "Review evidence with capo web show; record a conclusion with capo web assess. "
        "Then use capo web suggest."
    )
    if result["execution"] != "completed" or result.get("parse_error"):
        raise typer.Exit(1)


@web_app.command("assess")
@guarded
def assess(
    attempt: str,
    outcome: str,
    conclusion: str,
    evidence: list[str] = typer.Option(..., "--evidence"),
    capability: str | None = typer.Option(None, "--capability"),
):
    """Record supported, contradicted, inconclusive, blocked or failed, with evidence."""
    emit({"assessment": Engagement().assess(attempt, outcome, conclusion, evidence, capability)})


@web_app.command("chain")
@guarded
def chain(
    source: str,
    destination: str,
    explanation: str,
    evidence: list[str] | None = typer.Option(None, "--evidence"),
):
    """Link capabilities or hypotheses; unproven links remain hypotheses."""
    engagement = Engagement()
    left, right = engagement.get(source), engagement.get(destination)
    if any(r["kind"] not in {"capability", "hypothesis"} for r in (left, right)):
        raise ValueError("Chain endpoints must be capability or hypothesis IDs.")
    for item in evidence or []:
        engagement.evidence_path(item)
    proven = all(r["kind"] == "capability" for r in (left, right)) and bool(evidence)
    emit(
        {
            "chain": engagement.put(
                "chain",
                {
                    "source": source,
                    "destination": destination,
                    "explanation": explanation,
                    "evidence": evidence or [],
                    "status": "demonstrated" if proven else "hypothesis",
                },
            )
        }
    )


@knowledge_app.command("index")
@guarded
def index(
    source: list[str] | None = typer.Option(
        None, "--source", help="Markdown directory or file; repeat. Saved for later reindexing."
    ),
    embed: bool = typer.Option(False, "--embed"),
):
    emit(Knowledge().index(source, embed))


@knowledge_app.command("search")
@guarded
def search(query: str, semantic: bool = typer.Option(False, "--semantic")):
    emit(Knowledge().search(query, semantic))


@web_app.command("explain")
@guarded
def explain(query: str, ai: bool = typer.Option(False, "--ai")):
    """Retrieve sources; explicitly enable local Gemma with --ai."""
    emit(explain_question(Engagement(), query, ai))


@web_app.command("doctor")
@guarded
def doctor():
    emit(
        {
            "tools": [tool_doctor(tool) for tool in TOOLS],
            "config": home() / "config.json",
            "knowledge_index": home() / "knowledge.sqlite3",
        }
    )


@web_app.command("export")
@guarded
def export(file: Path):
    """Export methodology, conclusions and evidence references as Markdown."""
    engagement = Engagement()
    if file.exists():
        raise ValueError("Export destination exists; choose a new filename.")
    lines = [f"# Web engagement: {engagement.name}", "", "Scope: " + ", ".join(engagement.scope)]
    for kind in (
        "note",
        "identity",
        "hypothesis",
        "attempt",
        "assessment",
        "finding",
        "capability",
        "chain",
    ):
        lines.extend(["", f"## {kind.title()}", ""])
        for row in engagement.records(kind):
            lines.extend(
                [
                    f"### {row['id']}",
                    "",
                    "```json",
                    json.dumps(row, ensure_ascii=False, indent=2).replace("```", "` ` `"),
                    "```",
                    "",
                ]
            )
    lines.extend(["## Evidence", ""])
    for row in engagement.records("evidence"):
        lines.append(
            f"- {row['id']}: {row['label']} — {engagement.evidence_path(row['id'])} "
            f"(SHA256 {row['sha256']})"
        )
    file.write_text("\n".join(lines), encoding="utf-8")
    typer.echo(str(file.resolve()))
