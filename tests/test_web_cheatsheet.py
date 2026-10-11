"""Cheatsheets cover the live rule set without requiring an engagement or tools."""

import json

from typer.testing import CliRunner

from capo.cli import app
from capo.web.cheatsheet import markdown, select
from capo.web.playbooks import BOOKS

runner = CliRunner()


def test_offline_scope_and_detail(isolated_capo):
    result = runner.invoke(app, ["web", "cheatsheet", "--json"])
    assert result.exit_code == 0, result.output
    assert {b["id"] for b in json.loads(result.output)} == {b["id"] for b in BOOKS}
    assert not (isolated_capo / "web").exists()
    detail = runner.invoke(app, ["web", "cheatsheet", "idor"])
    assert detail.exit_code == 0
    assert "two distinct accounts" in detail.output
    assert "Controlled comparison" in detail.output
    assert "Knowledge references" in detail.output
    assert "public object" in detail.output


def test_search_and_bad_topic(isolated_capo):
    assert select(query="graphql resolver")[0]["id"] == "graphql"
    bad = runner.invoke(app, ["web", "cheatsheet", "unknown"])
    assert bad.exit_code == 1 and "Unknown topic" in bad.output
    empty = runner.invoke(app, ["web", "cheatsheet", "--search", "nonexistentxyz"])
    assert empty.exit_code == 1 and "No matching" in empty.output
    listing = runner.invoke(app, ["web", "cheatsheet"])
    assert listing.exit_code == 0
    for book in BOOKS:
        assert book["title"] in listing.output


def test_export_spaces_no_overwrite_and_complete_content(isolated_capo):
    destination = isolated_capo / "web reference.md"
    args = ["web", "cheatsheet", "--output", str(destination)]
    result = runner.invoke(app, args)
    assert result.exit_code == 0, result.output
    content = destination.read_text(encoding="utf-8")
    for book in BOOKS:
        for field in ("procedure", "comparison", "confirmation", "pitfalls"):
            assert book[field] in content
        for reference in book["references"]:
            assert reference in content
    result = runner.invoke(app, args)
    assert result.exit_code == 1
    assert destination.read_text(encoding="utf-8") == content


def test_snapshots_do_not_modify_rules():
    snapshot = select("sqli")
    snapshot[0]["references"].clear()
    assert select("sqli")[0]["references"]
    assert "One occurrence of 49 is insufficient" in markdown(select("ssti"))
