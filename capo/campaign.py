"""Campaign manager for engagement-wide data (Active Directory, etc.).

Handles cross-host mapping of users, hashes, credentials, and domain info.
"""

import json
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from filelock import FileLock

from capo import config
from capo.errors import StateError

CURRENT_SCHEMA_VERSION = 2


class CampaignManager:
    """Manages the current active campaign state."""

    def __init__(self):
        self._name: str | None = None
        self._dir: Path | None = None
        self._state: dict[str, Any] = {}
        self._load_current_campaign()

    @property
    def name(self) -> str | None:
        return self._name

    @property
    def active(self) -> bool:
        return self._name is not None

    @property
    def campaign_dir(self) -> Path | None:
        return self._dir

    def get(self, key: str, default: Any = None) -> Any:
        """Get a value from campaign state by key."""
        return self._state.get(key, default)

    def _state_file(self) -> Path:
        if not self._dir:
            raise StateError("Campaign not set")
        return self._dir / "campaign.json"

    def _lock_file(self) -> FileLock:
        return FileLock(str(self._state_file()) + ".lock", timeout=5)

    def set_campaign(self, name: str):
        """Set the active campaign and initialize its directory."""
        self._name = name
        self._dir = config.CAMPAIGNS_DIR / name
        self._dir.mkdir(parents=True, exist_ok=True)
        (self._dir / "loot").mkdir(exist_ok=True)

        config.CURRENT_CAMPAIGN_FILE.write_text(name, encoding="utf-8")
        self._load_state()

    def clear_campaign(self):
        """Clear the active campaign (return to single-host mode)."""
        self._name = None
        self._dir = None
        self._state = {}
        if config.CURRENT_CAMPAIGN_FILE.exists():
            config.CURRENT_CAMPAIGN_FILE.unlink()

    def _load_current_campaign(self):
        if config.CURRENT_CAMPAIGN_FILE.exists():
            name = config.CURRENT_CAMPAIGN_FILE.read_text(encoding="utf-8").strip()
            if name:
                self.set_campaign(name)

    def _fresh_state(self) -> dict[str, Any]:
        return {
            "schema_version": CURRENT_SCHEMA_VERSION,
            "campaign_name": self._name,
            "domain_info": {
                "domain_name": "",
                "dc_ip": "",
                "dns_name": "",
            },
            "users": [],
            "hashes": [],
            "credentials": [],
            "hosts": [],  # List of IPs bound to this campaign
            "created_at": datetime.now(timezone.utc).isoformat(),
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }

    def _load_state(self):
        if not self._dir:
            return

        sf = self._state_file()
        if sf.exists():
            try:
                self._state = json.loads(sf.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                self._state = self._fresh_state()
        else:
            self._state = self._fresh_state()
            self._save_state()

        # Ensure schema
        fresh = self._fresh_state()
        for k, v in fresh.items():
            self._state.setdefault(k, v)
        self._migrate_state()

    def _migrate_state(self):
        version = self._state.get("schema_version", 1)
        if version >= CURRENT_SCHEMA_VERSION:
            return
        if version < 2:
            self._state["schema_version"] = 2
        self._save_state()

    def _merge_state(self, disk_state: dict) -> dict:
        merged = dict(disk_state)
        for key, mem_val in self._state.items():
            disk_val = merged.get(key)
            if isinstance(mem_val, list) and isinstance(disk_val, list):
                seen: list = list(disk_val)
                for item in mem_val:
                    if item not in seen:
                        seen.append(item)
                merged[key] = seen
            elif isinstance(mem_val, dict) and isinstance(disk_val, dict):
                merged[key] = {**disk_val, **mem_val}
            else:
                merged[key] = mem_val
        return merged

    def _save_state(self):
        if not self._dir:
            return
        self._state["updated_at"] = datetime.now(timezone.utc).isoformat()
        sf = self._state_file()

        with self._lock_file():
            if sf.exists():
                try:
                    disk = json.loads(sf.read_text(encoding="utf-8"))
                    self._state = self._merge_state(disk)
                except (json.JSONDecodeError, OSError):
                    pass

            tmp = sf.with_suffix(".tmp")
            tmp.write_text(json.dumps(self._state, indent=2, default=str), encoding="utf-8")
            shutil.move(str(tmp), str(sf))

    def _write_list_file(self, filename: str, items: list[str]):
        """Write a list of items to a loot file in the campaign dir."""
        if not self._dir:
            return
        outfile = self._dir / filename
        outfile.write_text("\n".join(items) + "\n", encoding="utf-8")

    # --- Public Setters & Getters ---

    def add_host(self, ip: str):
        self._state.setdefault("hosts", [])
        if ip not in self._state["hosts"]:
            self._state["hosts"].append(ip)
            self._save_state()

    def add_user(self, username: str):
        self._state.setdefault("users", [])
        if username and username not in self._state["users"]:
            self._state["users"].append(username)
            self._save_state()
            self._write_list_file("loot/users.txt", self._state["users"])

    def add_hash(self, hash_str: str, username: str = ""):
        self._state.setdefault("hashes", [])
        entry = {"hash": hash_str, "username": username}
        if entry not in self._state["hashes"]:
            self._state["hashes"].append(entry)
            self._save_state()
            hashes = [h["hash"] for h in self._state["hashes"]]
            self._write_list_file("loot/hashes.txt", hashes)

    def add_credential(self, username: str, password: str, service: str = ""):
        self._state.setdefault("credentials", [])
        cred = {"username": username, "password": password, "service": service}
        if cred not in self._state["credentials"]:
            self._state["credentials"].append(cred)
            self._save_state()
            passwords = [c["password"] for c in self._state["credentials"] if c.get("password")]
            # Dedup passwords before writing
            seen_pass = []
            for p in passwords:
                if p not in seen_pass:
                    seen_pass.append(p)
            self._write_list_file("loot/passwords.txt", seen_pass)

    def update_domain_info(self, **kwargs):
        """Update domain information properties."""
        self._state.setdefault("domain_info", {})
        dirty = False
        allowed = {"domain_name", "dc_ip", "dns_name"}
        for k, v in kwargs.items():
            if k in allowed and v:
                if self._state["domain_info"].get(k) != v:
                    self._state["domain_info"][k] = v
                    dirty = True
        if dirty:
            self._save_state()

    def get_var(self, var_name: str) -> str:
        """Resolve campaign-level variables."""
        if var_name == "DOMAIN":
            return self._state.get("domain_info", {}).get("domain_name", "")
        if var_name == "DC_IP":
            return self._state.get("domain_info", {}).get("dc_ip", "")
        if var_name == "DNS_NAME":
            return self._state.get("domain_info", {}).get("dns_name", "")
        if var_name == "USER":
            creds = [c for c in self._state.get("credentials", []) if c.get("password") and c.get("username")]
            if creds:
                return creds[0]["username"]
            return self._state.get("users", [""])[0] if self._state.get("users") else ""
        if var_name == "PASS":
            creds = [c for c in self._state.get("credentials", []) if c.get("password") and c.get("username")]
            return creds[0]["password"] if creds else ""
        if var_name == "USERFILE":
            f = self._dir / "loot" / "users.txt" if self._dir else None
            return str(f) if f and f.exists() else ""
        if var_name == "PASSFILE":
            f = self._dir / "loot" / "passwords.txt" if self._dir else None
            return str(f) if f and f.exists() else ""
        return ""


# Global singleton instance
campaign_manager = CampaignManager()
