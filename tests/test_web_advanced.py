"""Advanced references and suggestions use the existing evidence cycle."""

import json

import pytest
from typer.testing import CliRunner

from capo.cli import app
from capo.web.cheatsheet import markdown, select
from capo.web.cycle import describe, suggestions
from capo.web.playbooks import BOOKS, BY_ID
from capo.web.store import Engagement
from capo.web.tools import build
from capo.web.traffic import add_request, import_har

runner = CliRunner()
ADVANCED = {b["id"] for b in BOOKS if b.get("category") == "advanced"}
EXPECTED = {
    "cache-poisoning", "cache-deception", "smuggling", "host-header", "deserialization",
    "race", "jwt", "oauth", "nosql", "prototype", "dom", "cors", "websocket", "postmessage",
}


def action_for(engagement, topic):
    return next(a for a in suggestions(engagement) if a["playbook"] == topic)


def attempt(engagement, action, outcome):
    evidence = engagement.evidence("Controlled comparison transcript", "comparison")
    identifier = engagement.put(
        "attempt", {"action": action["id"], "execution": "manual", "evidence": [evidence]}
    )
    assessment = engagement.assess(identifier, outcome, "Recorded comparison result", [evidence])
    return assessment


def test_catalog_offline_export_and_search(isolated_capo):
    assert ADVANCED == EXPECTED
    result = runner.invoke(app, ["web", "advanced", "--json"])
    assert result.exit_code == 0, result.output
    assert {b["id"] for b in json.loads(result.output)} == EXPECTED
    assert not (isolated_capo / "web").exists()
    result = runner.invoke(app, ["web", "advanced", "--search", "cache"])
    assert result.exit_code == 0 and "Web Cache Poisoning" in result.output
    assert "Web Cache Deception" in result.output
    assert runner.invoke(app, ["web", "advanced", "sqli"]).exit_code == 1
    assert runner.invoke(app, ["web", "advanced", "unknown"]).exit_code == 1
    path = isolated_capo / "advanced notes.md"
    result = runner.invoke(app, ["web", "advanced", "--output", str(path)])
    assert result.exit_code == 0, result.output
    content = path.read_text(encoding="utf-8")
    for key in EXPECTED:
        assert BY_ID[key]["title"] in content
        assert BY_ID[key]["references"][0] in content
    assert runner.invoke(app, ["web", "advanced", "--output", str(path)]).exit_code == 1
    assert content == path.read_text(encoding="utf-8")
    assert "Capo adapters cannot execute" in content
    assert "Available adapter: manual" not in content


@pytest.mark.parametrize("topic", sorted(EXPECTED))
def test_each_rule_participates_in_cycle(isolated_capo, topic):
    engagement = Engagement.create("advanced-test", ["http://example.test/"])
    rule = BY_ID[topic]
    engagement.put("observation", {"url": engagement.scope[0] + "/", "text": rule["triggers"][0]})
    first = action_for(engagement, topic)
    assert first["missing"]  # ordinary captured request is required
    add_request(engagement, "GET", first["url"], [], b"")
    ready = action_for(engagement, topic)
    assert not ready["missing"] and ready["id"] != first["id"]
    assert describe(engagement, ready["id"])["guidance"]["comparison"]
    attempt(engagement, ready, "inconclusive")
    revised = action_for(engagement, topic)
    assert revised["revision"] and revised["id"] != ready["id"]
    attempt(engagement, revised, "contradicted")
    assert not any(a["playbook"] == topic for a in suggestions(engagement))
    engagement.put("observation", {"url": ready["url"], "text": "Independent new behavior"})
    assert action_for(Engagement("advanced-test"), topic)["id"] != revised["id"]
    assert not engagement.records("finding")


def test_suggest_alias_and_advanced_filter(isolated_capo):
    runner.invoke(app, ["web", "init", "practice", "--url", "http://example.test/"])
    runner.invoke(app, ["web", "observe", "Shared cache observed", "--url", "http://example.test/"])
    current = runner.invoke(app, ["web", "suggest", "--json"])
    legacy = runner.invoke(app, ["web", "next", "--json"])
    assert current.exit_code == legacy.exit_code == 0
    assert json.loads(current.output) == json.loads(legacy.output)
    result = runner.invoke(app, ["web", "suggest", "--advanced", "--json"])
    assert result.exit_code == 0
    rows = json.loads(result.output)
    assert rows and all(row["category"] == "advanced" for row in rows)
    help_text = runner.invoke(app, ["web", "--help"]).output
    assert "suggest" in help_text and "advanced" in help_text


@pytest.mark.parametrize("topic", sorted(k for k in EXPECTED if BY_ID[k]["manual_only"]))
def test_manual_techniques_do_not_execute_normalized_adapters(isolated_capo, topic):
    engagement = Engagement.create("manual-test", ["http://example.test/"])
    fake_action = {"playbook": topic, "url": "http://example.test/"}
    for tool in ("curl", "ffuf", "katana", "nuclei", "sqlmap"):
        with pytest.raises(ValueError, match="manual"):
            build(engagement, fake_action, tool)
    assert not engagement.records("attempt")


def test_har_cache_signal_and_identity_change_reopens(isolated_capo):
    engagement = Engagement.create("cache-test", ["http://example.test/"])
    har = {"log": {"entries": [{
        "request": {"method": "GET", "url": "http://example.test/", "headers": []},
        "response": {"status": 200, "headers": [{"name": "X-Cache", "value": "HIT"}]},
    }]}}
    import_har(engagement, json.dumps(har))
    ready = action_for(engagement, "cache-deception")
    assert action_for(engagement, "cache-poisoning")
    assert not engagement.records("finding")
    attempt(engagement, ready, "contradicted")
    engagement.put("identity", {"name": "alice", "role": "user", "objects": ["profile/1"]})
    assert action_for(engagement, "cache-deception")["id"] != ready["id"]


def test_capability_opens_followup_without_keyword_and_stays_in_origin(isolated_capo):
    engagement = Engagement.create("followup", ["http://example.test/", "http://other.test/"])
    url = "http://example.test/"
    add_request(engagement, "GET", url, [], b"")
    add_request(engagement, "GET", "http://other.test/", [], b"")
    engagement.put("observation", {"url": url, "text": "cache"})
    action = action_for(engagement, "cache-poisoning")
    assert not any(a["playbook"] == "dom" for a in suggestions(engagement))
    evidence = engagement.evidence("Cache persistence and security effect comparison", "comparison")
    identifier = engagement.put(
        "attempt", {"action": action["id"], "execution": "manual", "evidence": [evidence]}
    )
    engagement.assess(identifier, "supported", "Controlled security effect", [evidence],
                      "Control a cached resource import")
    rows = suggestions(engagement)
    dom = next(a for a in rows if a["playbook"] == "dom")
    assert dom["url"] == url and "capability" in dom["reason"]
    assert not any(a["playbook"] == "dom" and a["url"] == "http://other.test/" for a in rows)
    assert len(engagement.records("finding")) == 1


def test_corroboration_guidance():
    # Piped native Windows output can use a legacy encoding instead of UTF-8.
    markdown(select(advanced_only=True)).encode("cp1252")
    assert "separate clean client" in select("cache-poisoning")[0]["procedure"]
    assert "unauthenticated" in select("cache-deception")[0]["procedure"]
    assert "One timeout is insufficient" in select("smuggling")[0]["pitfalls"]
    assert "read sensitive authenticated" in select("cors")[0]["confirmation"]
