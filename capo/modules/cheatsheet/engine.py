"""Cheatsheet Engine - YAML-based command database with variable injection.

Supports:
- Core cheatsheets (shipped with C.A.P.O)
- Custom cheatsheets (user-created in ~/.capo/custom_cheatsheets/)
- Variable injection from state ({IP}, {DOMAIN}, {USER}, etc.)
- Merge with user overrides taking priority
- Fuzzy search across all commands
"""

import re
from pathlib import Path
from typing import Any

import yaml

from capo.config import CORE_CHEATSHEETS_DIR, CUSTOM_CHEATSHEETS_DIR
from capo.state import state_manager
from capo.utils.display import print_info, print_warning


class CheatsheetEntry:
    """A single cheatsheet command entry."""

    def __init__(self, data: dict[str, Any], category: str = "", source: str = "core"):
        self.name: str = data.get("name", "")
        self.description: str = data.get("description", "")
        self.command: str = data.get("command", "")
        self.category: str = category or data.get("category", "")
        self.tags: list[str] = data.get("tags", [])
        self.os: str = data.get("os", "any")  # linux, windows, any
        self.tool: str = data.get("tool", "")
        self.references: list[str] = data.get("references", [])
        self.notes: str = data.get("notes", "")
        self.source: str = source  # core or custom
        self.exam: list[str] = data.get("exam", ["oscp", "cpts"])  # which exams it's relevant for

    def inject_variables(self) -> str:
        """Replace template variables with values from state. Multi-expands for credentials."""
        from capo.campaign import campaign_manager

        cmd_template = self.command
        # Find all {VARIABLE} patterns
        variables = set(re.findall(r"\{(\w+)\}", cmd_template))

        # If both USER and PASS are requested, expand all known valid credentials
        if "USER" in variables and "PASS" in variables:
            if campaign_manager.active:
                creds = [c for c in campaign_manager.get("credentials", []) if c.get("username") and c.get("password")]
            else:
                creds = [c for c in state_manager.get("credentials", []) if c.get("username") and c.get("password")]

            if creds:
                expanded_cmds = []
                for cred in creds:
                    cmd = cmd_template
                    cmd = cmd.replace("{USER}", cred["username"])
                    cmd = cmd.replace("{PASS}", cred["password"])

                    # Inject remaining variables
                    for var in variables - {"USER", "PASS"}:
                        value = state_manager.get_var(var)
                        if value:
                            cmd = cmd.replace(f"{{{var}}}", value)
                    expanded_cmds.append(cmd)
                return "\n".join(expanded_cmds)

        # Standard fallback for single variable injection
        cmd = cmd_template
        for var in variables:
            value = state_manager.get_var(var)
            if value:
                cmd = cmd.replace(f"{{{var}}}", value)
        return cmd

    def matches(self, query: str) -> bool:
        """Check if this entry matches a search query (case-insensitive)."""
        query_lower = query.lower()
        searchable = " ".join([
            self.name, self.description, self.category,
            " ".join(self.tags), self.tool, self.command,
        ]).lower()
        # All query words must appear somewhere
        return all(word in searchable for word in query_lower.split())

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "description": self.description,
            "command": self.command,
            "category": self.category,
            "tags": self.tags,
            "os": self.os,
            "tool": self.tool,
            "notes": self.notes,
        }


class CheatsheetEngine:
    """Manages loading, merging, and querying cheatsheet databases."""

    def __init__(self):
        self._entries: dict[str, CheatsheetEntry] = {}
        self._categories: dict[str, list[str]] = {}

    @property
    def entries(self) -> dict[str, CheatsheetEntry]:
        return self._entries

    @property
    def categories(self) -> list[str]:
        return sorted(self._categories.keys())

    def load_all(self):
        """Load and merge core + custom cheatsheets."""
        self._entries.clear()
        self._categories.clear()

        # Load core first
        if CORE_CHEATSHEETS_DIR.exists():
            self._load_directory(CORE_CHEATSHEETS_DIR, source="core")

        # Then load custom (overrides core entries with same name)
        if CUSTOM_CHEATSHEETS_DIR.exists():
            self._load_directory(CUSTOM_CHEATSHEETS_DIR, source="custom")

        print_info(
            f"Loaded {len(self._entries)} commands across "
            f"{len(self._categories)} categories."
        )

    def _load_directory(self, directory: Path, source: str):
        """Load all YAML files from a directory."""
        for yaml_file in sorted(directory.glob("**/*.yaml")):
            self._load_file(yaml_file, source)
        for yaml_file in sorted(directory.glob("**/*.yml")):
            self._load_file(yaml_file, source)

    def _load_file(self, filepath: Path, source: str):
        """Load a single YAML cheatsheet file."""
        try:
            data = yaml.safe_load(filepath.read_text(encoding="utf-8"))
        except (yaml.YAMLError, OSError) as e:
            print_warning(f"Failed to load {filepath}: {e}")
            return

        if not isinstance(data, dict):
            return

        category = data.get("category", filepath.stem)
        commands = data.get("commands", [])

        if not isinstance(commands, list):
            return

        for cmd_data in commands:
            if not isinstance(cmd_data, dict):
                continue
            entry = CheatsheetEntry(cmd_data, category=category, source=source)
            if entry.name:
                # Custom overrides core
                self._entries[entry.name] = entry
                self._categories.setdefault(category, []).append(entry.name)

    def search(self, query: str, limit: int = 20) -> list[CheatsheetEntry]:
        """Search cheatsheets by query string."""
        results = []
        for entry in self._entries.values():
            if entry.matches(query):
                results.append(entry)
        return results[:limit]

    def fuzzy_search(self, query: str, limit: int = 20) -> list[CheatsheetEntry]:
        """Fuzzy search using thefuzz library."""
        try:
            from thefuzz import fuzz
        except ImportError:
            return self.search(query, limit)

        scored = []
        for entry in self._entries.values():
            searchable = f"{entry.name} {entry.description} {' '.join(entry.tags)}"
            score = max(
                fuzz.partial_ratio(query.lower(), searchable.lower()),
                fuzz.token_set_ratio(query.lower(), searchable.lower()),
            )
            if score > 40:
                scored.append((score, entry))

        scored.sort(key=lambda x: x[0], reverse=True)
        return [entry for _, entry in scored[:limit]]

    def get_by_category(self, category: str) -> list[CheatsheetEntry]:
        """Get all entries in a category."""
        names = self._categories.get(category, [])
        return [self._entries[n] for n in names if n in self._entries]

    def get_by_tool(self, tool: str) -> list[CheatsheetEntry]:
        """Get all entries that use a specific tool (case-insensitive)."""
        tool_lower = tool.lower()
        return [e for e in self._entries.values() if e.tool.lower() == tool_lower]

    def get_by_tag(self, tag: str) -> list[CheatsheetEntry]:
        """Get all entries with a specific tag."""
        return [e for e in self._entries.values() if tag.lower() in [t.lower() for t in e.tags]]

    def get_for_exam(self, exam: str) -> list[CheatsheetEntry]:
        """Get entries relevant for a specific exam (oscp/cpts)."""
        return [e for e in self._entries.values() if exam.lower() in e.exam]

    def get_for_service(self, service: str) -> list[CheatsheetEntry]:
        """Get entries for a specific service/tool."""
        return self.search(service)

    def get_entry(self, name: str) -> CheatsheetEntry | None:
        """Get a specific entry by name."""
        return self._entries.get(name)


# Global singleton
cheatsheet_engine = CheatsheetEngine()
