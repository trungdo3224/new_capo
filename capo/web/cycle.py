"""Deterministic recommendations driven by engagement evidence and prerequisites."""

import re

from .playbooks import BOOKS, BY_ID
from .store import digest, origin


def suggestions(engagement, include_suppressed=False):
    endpoints = engagement.records("endpoint")
    observations = engagement.records("observation")
    identities = engagement.records("identity")
    capabilities = engagement.records("capability")
    requests = engagement.records("request")
    attempts = engagement.records("attempt")
    assessments = engagement.records("assessment")
    actions = []
    for endpoint in endpoints:
        url = endpoint["url"]
        relevant = [o for o in observations if o.get("url") == url]
        captured = [r for r in requests if r["url"] == url]
        words = set(
            re.findall(
                r"[a-z0-9_-]+",
                " ".join(
                    [
                        url,
                        str(endpoint.get("tags", [])),
                        *[o["text"] for o in relevant],
                        *[str(r.get("parameters", [])) for r in captured],
                        *[str(r.get("headers", [])) for r in captured],
                    ]
                ).lower(),
            )
        )
        for rule in BOOKS:
            matches = sorted(words.intersection(rule["triggers"]))
            applicable_capabilities = []
            for capability in capabilities:
                source = (
                    engagement.get(capability["action"], "action")
                    if capability.get("action")
                    else None
                )
                if (
                    source and origin(source["url"]) == origin(url)
                    and rule["id"] in BY_ID[source["playbook"]]["followups"]
                ):
                    applicable_capabilities.append(capability["id"])
            if rule["id"] != "mapping" and not matches and not applicable_capabilities:
                continue
            context = {
                "observations": [o["id"] for o in relevant if not o.get("action")],
                "requests": [r["id"] for r in captured],
                "identities": identities
                if rule["id"] in {"idor", "api", "auth", "csrf", "graphql", "logic"}
                or rule.get("identity_sensitive")
                else [],
                "capabilities": applicable_capabilities,
            }
            signature = digest(context)
            hypothesis = engagement.put(
                "hypothesis",
                {"url": url, "playbook": rule["id"], "question": rule["title"]},
                key=f"{url}:{rule['id']}",
            )
            previous = [
                a
                for a in engagement.records("action")
                if a.get("hypothesis") == hypothesis and a["context"] == signature
            ]
            previous_ids = {a["id"] for a in previous}
            tested = [a for a in attempts if a["action"] in previous_ids]
            conclusions = [a for a in assessments if a["action"] in previous_ids]
            latest = conclusions[-1] if conclusions else None
            pending = [a for a in tested if not any(c["attempt"] == a["id"] for c in conclusions)]
            suppressed = bool(
                pending
                or (
                    latest
                    and latest["outcome"] in {"supported", "contradicted", "blocked", "failed"}
                )
            )
            if suppressed and not include_suppressed:
                continue
            missing = []
            if "request" in rule["prerequisites"] and not captured:
                missing.append("Capture a working request with its authentication context.")
            if (
                "two_owned_identities" in rule["prerequisites"]
                and len({i["name"] for i in identities if i.get("objects")}) < 2
            ):
                missing.append("Record two distinct identities and their known owned objects.")
            followup = latest["id"] if latest and latest["outcome"] == "inconclusive" else None
            payload = {
                "url": url,
                "hypothesis": hypothesis,
                "playbook": rule["id"],
                "context": signature,
                "revision": followup,
                "missing": missing,
                "reason": f"Observed terms: {', '.join(matches)}"
                if matches
                else (
                    "A demonstrated capability enables this follow-up test."
                    if applicable_capabilities
                    else "Establish application behavior and discover inputs."
                ),
                "score": 100
                + min(len(matches), 5) * 10
                - len(missing) * 50
                + (25 if followup else 0)
                - rule.get("cost", 0),
                "category": rule.get("category", "core"),
                "manual_only": rule.get("manual_only", False),
                "request": captured[-1]["id"] if captured else None,
            }
            action_id = engagement.put("action", payload, key=digest(payload))
            actions.append(dict(payload, id=action_id, title=rule["title"], suppressed=suppressed))
    return sorted(actions, key=lambda a: (-a["score"], a["url"], a["playbook"]))


def describe(engagement, action_id):
    action = engagement.get(action_id, "action")
    rule = BY_ID[action["playbook"]]
    result = dict(action, guidance=rule)
    if action.get("revision"):
        result["refinement"] = (
            "Previous evidence was inconclusive. Recheck session validity and the comparison "
            "request, change one variable, and repeat before concluding."
        )
        result["previous_assessment"] = engagement.get(action["revision"], "assessment")
    return result
