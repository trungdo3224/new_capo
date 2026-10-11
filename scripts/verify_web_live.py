"""Explicit local Ollama smoke check; run from the repository with PYTHONPATH=."""

import hashlib
import json
import tempfile
from pathlib import Path

from capo import config
from capo.web.knowledge import Knowledge, explain
from capo.web.store import Engagement


def main():
    kb = Knowledge()
    with kb.connect() as db:
        documents = db.execute("SELECT path,hash FROM documents").fetchall()
        passages = db.execute("SELECT count(*) FROM passages").fetchone()[0]
        embedded = db.execute("SELECT count(*) FROM passages WHERE vector IS NOT NULL").fetchone()[
            0
        ]
    changed = [
        r["path"]
        for r in documents
        if hashlib.sha256(Path(r["path"]).read_text(encoding="utf-8-sig").encode()).hexdigest()
        != r["hash"]
    ]
    if changed:
        raise AssertionError(f"Indexed source content has changed: {changed}")
    with tempfile.TemporaryDirectory(prefix="capo-live-") as scratch:
        original = config.CAPO_HOME
        try:
            config.CAPO_HOME = Path(scratch)
            engagement = Engagement.create("local-check", ["http://example.test/"])
            engagement.put(
                "note",
                {
                    "text": (
                        "Authorized local lab: Alice owns invoice 318; Bob owns invoice 492. "
                        "GET /api/invoices/318 requires login. Expected policy: owners only. "
                        "A 200 response has been observed but its contents have not been compared."
                    )
                },
            )
        finally:
            config.CAPO_HOME = original
        result = explain(
            engagement, "How should I verify suspected IDOR in this invoice API?", ai=True
        )
        if not result["answer"]:
            raise AssertionError(result["warning"])
        print(
            json.dumps(
                {
                    "documents": len(documents),
                    "passages": passages,
                    "embedded": embedded,
                    "source_integrity": "unchanged",
                    "retrieved": len(result["sources"]),
                    "warning": result["warning"],
                    "context_truncated": result["context_truncated"],
                    "answer": result["answer"],
                },
                indent=2,
            )
        )


if __name__ == "__main__":
    main()
