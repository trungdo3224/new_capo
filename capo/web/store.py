"""Transactional engagement records; raw evidence is kept outside the database."""

import hashlib
import json
import re
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from urllib.parse import urlsplit, urlunsplit

from capo import config


def now():
    return datetime.now(timezone.utc).isoformat()


def digest(value):
    raw = value if isinstance(value, bytes) else json.dumps(value, sort_keys=True).encode()
    return hashlib.sha256(raw).hexdigest()


def home():
    return config.CAPO_HOME / "web"


def canonical_url(url):
    p = urlsplit(url)
    if p.scheme not in ("http", "https") or not p.hostname or p.username or p.password:
        raise ValueError("Use an HTTP(S) URL without embedded credentials.")
    if any(ord(c) < 32 for c in url) or "\\" in url:
        raise ValueError("Invalid URL characters.")
    host = p.hostname.lower().encode("idna").decode()
    if ":" in host:
        host = f"[{host}]"
    port = p.port
    authority = host + (f":{port}" if port and port != (443 if p.scheme == "https" else 80) else "")
    return urlunsplit((p.scheme, authority, p.path or "/", p.query, ""))


def origin(url):
    p = urlsplit(canonical_url(url))
    return f"{p.scheme}://{p.netloc}"


def valid_name(name):
    if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}", name):
        raise ValueError("Engagement name must be 1–64 letters, digits, underscores or hyphens.")
    if name.split(".")[0].upper() in {
        "CON",
        "PRN",
        "AUX",
        "NUL",
        *[f"COM{i}" for i in range(10)],
        *[f"LPT{i}" for i in range(10)],
    }:
        raise ValueError("Reserved engagement name.")
    return name


class Engagement:
    def __init__(self, name=None):
        if not name:
            pointer = home() / "current"
            if not pointer.exists():
                raise ValueError("Create an engagement with: capo web init NAME --url URL")
            name = pointer.read_text(encoding="utf-8").strip()
        self.name = valid_name(name)
        self.path = home() / "engagements" / self.name
        self.db_path = self.path / "engagement.sqlite3"
        if not self.db_path.exists():
            raise ValueError(f"Unknown web engagement: {name}")

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.db_path, timeout=15)
        db.row_factory = sqlite3.Row
        try:
            with db:
                yield db
        finally:
            db.close()

    @classmethod
    def create(cls, name, urls):
        name = valid_name(name)
        scopes = sorted({origin(u) for u in urls})
        if not scopes:
            raise ValueError("At least one application URL is required.")
        path = home() / "engagements" / name
        path.mkdir(parents=True, exist_ok=False)
        (path / "evidence").mkdir()
        with sqlite3.connect(path / "engagement.sqlite3") as db:
            db.executescript("""
                PRAGMA journal_mode=WAL;
                CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
                CREATE TABLE records(id TEXT PRIMARY KEY, kind TEXT NOT NULL,
                    data TEXT NOT NULL, created TEXT NOT NULL, unique_key TEXT UNIQUE);
                CREATE INDEX record_kind ON records(kind);
                INSERT INTO meta VALUES('schema_version','1');
            """)
            db.execute("INSERT INTO meta VALUES('scope',?)", (json.dumps(scopes),))
        db.close()
        engagement = cls(name)
        for url in urls:
            engagement.put(
                "endpoint", {"url": canonical_url(url), "method": "GET"}, key=canonical_url(url)
            )
        engagement.use()
        return engagement

    def use(self):
        pointer = home() / "current"
        tmp = pointer.with_name(f"current-{uuid.uuid4().hex}.tmp")
        tmp.write_text(self.name, encoding="utf-8")
        tmp.replace(pointer)

    @property
    def scope(self):
        with self.connect() as db:
            return json.loads(db.execute("SELECT value FROM meta WHERE key='scope'").fetchone()[0])

    def check_url(self, url):
        url = canonical_url(url)
        if origin(url) not in self.scope:
            raise ValueError(f"URL is outside the engagement's explicit origins: {url}")
        return url

    def put(self, kind, data, key=None):
        identifier = f"{kind[:3]}-{uuid.uuid4().hex[:12]}"
        unique_key = f"{kind}:{key}" if key is not None else None
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            if unique_key:
                existing = db.execute(
                    "SELECT id FROM records WHERE unique_key=?", (unique_key,)
                ).fetchone()
                if existing:
                    return existing[0]
            db.execute(
                "INSERT INTO records VALUES(?,?,?,?,?)",
                (identifier, kind, json.dumps(data), now(), unique_key),
            )
        return identifier

    def get(self, identifier, kind=None):
        with self.connect() as db:
            row = db.execute("SELECT * FROM records WHERE id=?", (identifier,)).fetchone()
        if row is None or (kind and row["kind"] != kind):
            raise ValueError(f"Unknown {kind or 'record'}: {identifier}")
        return dict(json.loads(row["data"]), id=row["id"], kind=row["kind"], created=row["created"])

    def records(self, kind):
        with self.connect() as db:
            rows = db.execute(
                "SELECT * FROM records WHERE kind=? ORDER BY created,id", (kind,)
            ).fetchall()
        return [
            dict(json.loads(r["data"]), id=r["id"], kind=r["kind"], created=r["created"])
            for r in rows
        ]

    def update(self, identifier, **changes):
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT data FROM records WHERE id=?", (identifier,)).fetchone()
            if row is None:
                raise ValueError(f"Unknown record: {identifier}")
            data = json.loads(row[0])
            data.update(changes)
            db.execute("UPDATE records SET data=? WHERE id=?", (json.dumps(data), identifier))

    def evidence(self, data, label, suffix=".txt"):
        if not isinstance(data, bytes):
            data = data.encode("utf-8")
        sha = digest(data)
        path = self.path / "evidence" / f"{sha}{suffix}"
        if not path.exists():
            path.write_bytes(data)
        return self.put(
            "evidence",
            {"path": str(path.relative_to(self.path)), "sha256": sha, "label": label},
            key=sha,
        )

    def evidence_path(self, identifier):
        record = self.get(identifier, "evidence")
        path = (self.path / record["path"]).resolve()
        if not path.is_relative_to(self.path.resolve()) or not path.is_file():
            raise ValueError("Evidence file is missing or outside the engagement.")
        return path

    def assess(self, attempt_id, outcome, conclusion, evidence, capability=None):
        if outcome not in {"supported", "contradicted", "inconclusive", "blocked", "failed"}:
            raise ValueError("Invalid assessment outcome.")
        attempt = self.get(attempt_id, "attempt")
        action = self.get(attempt["action"], "action")
        for item in evidence:
            self.evidence_path(item)
        if not conclusion.strip() or not evidence:
            raise ValueError("Assessment requires a conclusion and evidence IDs.")
        if attempt.get("execution") in {"failed", "timeout", "cancelled"} and outcome in {
            "supported",
            "contradicted",
        }:
            raise ValueError(
                "A failed execution cannot confirm or contradict a vulnerability. "
                "Record a manual attempt."
            )
        if capability and outcome != "supported":
            raise ValueError("A demonstrated capability requires a supported assessment.")
        # Assessment, finding and capability become visible together.
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            if any(
                json.loads(r[0]).get("attempt") == attempt_id
                for r in db.execute("SELECT data FROM records WHERE kind='assessment'")
            ):
                raise ValueError(
                    "This attempt is already assessed. "
                    "Record a new attempt to revise the conclusion."
                )

            def insert(kind, payload):
                ident = f"{kind[:3]}-{uuid.uuid4().hex[:12]}"
                db.execute(
                    "INSERT INTO records VALUES(?,?,?,?,NULL)",
                    (ident, kind, json.dumps(payload), now()),
                )
                return ident

            assessment = insert(
                "assessment",
                {
                    "attempt": attempt_id,
                    "action": attempt["action"],
                    "outcome": outcome,
                    "conclusion": conclusion,
                    "evidence": evidence,
                },
            )
            if outcome == "supported" and action["playbook"] != "mapping":
                finding = insert(
                    "finding",
                    {
                        "assessment": assessment,
                        "action": attempt["action"],
                        "conclusion": conclusion,
                        "evidence": evidence,
                        "status": "confirmed",
                    },
                )
                if capability:
                    insert(
                        "capability",
                        {
                            "name": capability,
                            "finding": finding,
                            "action": attempt["action"],
                            "evidence": evidence,
                        },
                    )
        return assessment
