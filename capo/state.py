"""State Manager - The memory/brain of C.A.P.O.

Manages per-target state in JSON files, tracking discovered intelligence:
- Target IP/domain, OS
- Open ports and services
- Discovered users, hashes, credentials
- Web directories, vhosts
- Notes and flags
"""

import json
import re
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from filelock import FileLock

from capo import campaign, config
from capo.errors import TargetError

# Schema version for state.json — bump when adding/changing fields.
# Migration logic in StateManager._migrate_state() handles upgrades.
CURRENT_SCHEMA_VERSION = 5

# Matches IPv4 addresses or hostnames (alphanumeric + dots/hyphens)
_TARGET_RE = re.compile(
    r"^(?:\d{1,3}\.){3}\d{1,3}$"          # IPv4
    r"|^[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$"  # hostname/FQDN
)


def _current_target_file() -> Path:
    return config.CAPO_HOME / ".current_target"


class StateManager:
    """Manages target state stored in JSON files under the workspace."""

    def __init__(self):
        self._target: str | None = None
        self._state: dict[str, Any] = {}
        self._workspace: Path | None = None
        self._auto_load()

    def _auto_load(self):
        """Auto-load the last used target on startup."""
        ctf = _current_target_file()
        if ctf.exists():
            target = ctf.read_text(encoding="utf-8").strip()
            if target:
                safe_name = target.replace("/", "_").replace(":", "_")
                ws = config.WORKSPACES_DIR / safe_name
                if (ws / "state.json").exists():
                    self._target = target
                    self._workspace = ws
                    self._load_state()

    @property
    def target(self) -> str | None:
        return self._target

    @property
    def workspace(self) -> Path | None:
        return self._workspace

    @property
    def state(self) -> dict[str, Any]:
        return self._state

    def set_target(self, target: str) -> Path:
        """Set current target and load/create its workspace.

        Returns the workspace path.
        Raises ValueError if target format is invalid.
        """
        if not _TARGET_RE.match(target):
            raise TargetError(
                f"Invalid target format: '{target}'. "
                "Expected an IPv4 address (e.g. 10.10.10.100) or hostname."
            )
        self._target = target
        safe_name = target.replace("/", "_").replace(":", "_")
        self._workspace = config.WORKSPACES_DIR / safe_name

        if campaign.campaign_manager.active:
            campaign.campaign_manager.add_host(str(self._target))

        self._init_workspace()
        self._load_state()
        # Persist current target for cross-invocation recall
        config.CAPO_HOME.mkdir(parents=True, exist_ok=True)
        _current_target_file().write_text(target, encoding="utf-8")
        return self._workspace

    def _init_workspace(self):
        """Create OSCP-standard workspace structure."""
        dirs = ["scans", "loot", "exploits", "evidence"]
        for d in dirs:
            (self._workspace / d).mkdir(parents=True, exist_ok=True)

        # Create notes template if not exists
        notes_file = self._workspace / "notes.md"
        if not notes_file.exists():
            template = self._generate_notes_template()
            notes_file.write_text(template, encoding="utf-8")

    def _generate_notes_template(self) -> str:
        """Generate OSCP-style notes template."""
        return f"""# Target: {self._target}
## Date: {datetime.now(timezone.utc).strftime('%Y-%m-%d')}

## Summary
- **IP:** {self._target}
- **OS:** Unknown
- **Difficulty:** Unknown

## Recon

### Port Scan
```
(Paste Nmap output here)
```

### Service Enumeration
| Port | Service | Version | Notes |
|------|---------|---------|-------|
|      |         |         |       |

## Initial Foothold
- **Vulnerability:**
- **Exploit/Method:**
- **Proof:**

## Privilege Escalation
- **Vector:**
- **Method:**
- **Proof:**

## Flags
- **local.txt:**
- **proof.txt:**

## Credentials Found
| Username | Password/Hash | Service | Notes |
|----------|---------------|---------|-------|
|          |               |         |       |

## Loot
- Files:
- SSH Keys:

## Timeline
| Time | Action | Result |
|------|--------|--------|
|      |        |        |
"""

    def _state_file(self) -> Path:
        return self._workspace / "state.json"

    def _load_state(self):
        """Load state from JSON or create fresh state."""
        sf = self._state_file()
        if sf.exists():
            try:
                self._state = json.loads(sf.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                from rich.console import Console
                Console().print(f"[red]Warning: {sf} is malformed or empty. Starting fresh state temporarily.[/red]")
                self._state = self._fresh_state()
        else:
            self._state = self._fresh_state()
            self._save_state()

        # Ensure base schema
        fresh = self._fresh_state()
        for k, v in fresh.items():
            self._state.setdefault(k, v)

        # Run schema migration for older state files
        self._migrate_state()

    def _fresh_state(self) -> dict[str, Any]:
        return {
            "schema_version": CURRENT_SCHEMA_VERSION,
            "target": self._target,
            "ip": self._target,
            "hostname": "",
            "os": "",
            "os_build": "",
            "arch": "",
            "domains": [],
            "domain_info": {
                "domain_name": "",
                "dc_ip": "",
                "dns_name": "",
                "is_domain_joined": False,
                "is_dc": False,
            },
            "ports": [],
            "services": {},
            "shares": [],
            "directories": [],
            "vhosts": [],
            "users": [],
            "hashes": [],
            "credentials": [],
            "notes": [],
            "flags": {
                "user_txt": "",
                "proof_txt": "",
                "local_txt": "",
            },
            "nse_results": [],
            "vulnerabilities": [],
            "banners": {},
            "scan_history": [],
            "created_at": datetime.now(timezone.utc).isoformat(),
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }

    def _migrate_state(self):
        """Upgrade older state files to the current schema version."""
        version = self._state.get("schema_version", 1)
        if version >= CURRENT_SCHEMA_VERSION:
            return  # already up-to-date

        # v1 → v2: add schema_version field + methodology_progress
        if version < 2:
            self._state.setdefault("vhosts", [])
            self._state.setdefault("shares", [])
            self._state["schema_version"] = 2

        # v2 → v3: single "domain" string → "domains" list
        if version < 3:
            old_domain = self._state.pop("domain", "")
            domains = self._state.get("domains", [])
            if old_domain and old_domain not in domains:
                domains.insert(0, old_domain)
            self._state["domains"] = domains
            self._state["schema_version"] = 3

        # v3 → v4: add nse_results, vulnerabilities, banners
        if version < 4:
            self._state.setdefault("nse_results", [])
            self._state.setdefault("vulnerabilities", [])
            self._state.setdefault("banners", {})
            self._state["schema_version"] = 4

        # v4 → v5: add os_build, arch, is_domain_joined, is_dc
        if version < 5:
            self._state.setdefault("os_build", "")
            self._state.setdefault("arch", "")
            di = self._state.setdefault("domain_info", {})
            di.setdefault("is_domain_joined", bool(self._state.get("domains")))
            di.setdefault("is_dc", False)
            flags = self._state.setdefault("flags", {})
            if "local_txt" in flags and "user_txt" not in flags:
                flags["user_txt"] = flags.get("local_txt", "")
            self._state["schema_version"] = 5

        # Direct write during migration — bypass _save_state() merge
        # to avoid re-introducing removed keys (e.g. "domain") from disk.
        self._state["updated_at"] = datetime.now(timezone.utc).isoformat()
        sf = self._state_file()
        with self._lock_file():
            tmp = sf.with_suffix(".tmp")
            tmp.write_text(
                json.dumps(self._state, indent=2, default=str),
                encoding="utf-8",
            )
            shutil.move(str(tmp), str(sf))

    def _lock_file(self) -> FileLock:
        """Return a FileLock for the state file (created lazily)."""
        return FileLock(str(self._state_file()) + ".lock", timeout=5)

    def _merge_state(self, disk_state: dict) -> dict:
        """Merge in-memory state with on-disk state.

        Lists are deduplicated-union'd so concurrent processes accumulate
        findings. Dicts are shallow-merged. Scalars use in-memory value.
        """
        merged = dict(disk_state)
        for key, mem_val in self._state.items():
            disk_val = merged.get(key)
            if isinstance(mem_val, list) and isinstance(disk_val, list):
                if key == "ports" and all(isinstance(x, dict) for x in mem_val + disk_val):
                    mem_keys = {(p.get("port"), p.get("protocol")) for p in mem_val}
                    merged_list = list(disk_val)
                    # Replace disk dicts with newer mem dicts
                    for i, p in enumerate(merged_list):
                        if (p.get("port"), p.get("protocol")) in mem_keys:
                            # Replace with the memory version
                            merged_list[i] = next(m for m in mem_val if m.get("port") == p.get("port") and m.get("protocol") == p.get("protocol"))
                    # Add remaining mem dicts
                    disk_keys = {(p.get("port"), p.get("protocol")) for p in disk_val}
                    for m in mem_val:
                        if (m.get("port"), m.get("protocol")) not in disk_keys:
                            merged_list.append(m)
                    merged[key] = merged_list

                elif key == "credentials" and all(isinstance(x, dict) for x in mem_val + disk_val):
                    disk_keys = {(c.get("username"), c.get("password"), c.get("service")) for c in disk_val}
                    merged_list = list(disk_val)
                    for c in mem_val:
                        if (c.get("username"), c.get("password"), c.get("service")) not in disk_keys:
                            merged_list.append(c)
                    merged[key] = merged_list

                elif key == "hashes" and all(isinstance(x, dict) for x in mem_val + disk_val):
                    disk_keys = {(h.get("hash"), h.get("username")) for h in disk_val}
                    merged_list = list(disk_val)
                    for h in mem_val:
                        if (h.get("hash"), h.get("username")) not in disk_keys:
                            merged_list.append(h)
                    merged[key] = merged_list

                elif key == "nse_results" and all(isinstance(x, dict) for x in mem_val + disk_val):
                    disk_keys = {(r.get("port"), r.get("script_id"), r.get("protocol")) for r in disk_val}
                    merged_list = list(disk_val)
                    for r in mem_val:
                        rkey = (r.get("port"), r.get("script_id"), r.get("protocol"))
                        if rkey not in disk_keys:
                            merged_list.append(r)
                        else:
                            # Update output for existing entries
                            for d in merged_list:
                                if (d.get("port"), d.get("script_id"), d.get("protocol")) == rkey:
                                    d["output"] = r["output"]
                                    break
                    merged[key] = merged_list

                elif key == "vulnerabilities" and all(isinstance(x, dict) for x in mem_val + disk_val):
                    disk_keys = {(v.get("id"), v.get("port")) for v in disk_val}
                    merged_list = list(disk_val)
                    for v in mem_val:
                        if (v.get("id"), v.get("port")) not in disk_keys:
                            merged_list.append(v)
                    merged[key] = merged_list

                else:
                    # Deduplicated union preserving order for generic lists
                    seen = list(disk_val)
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
        """Persist state to JSON file with file-locking and merge.

        Acquires a file lock, re-reads from disk, merges in-memory
        changes with any concurrent updates, and writes back.
        """
        if self._workspace is None:
            return
        self._state["updated_at"] = datetime.now(timezone.utc).isoformat()
        sf = self._state_file()

        with self._lock_file():
            # Re-read disk version to pick up concurrent changes
            if sf.exists():
                try:
                    disk_state = json.loads(sf.read_text(encoding="utf-8"))
                    self._state = self._merge_state(disk_state)
                except (json.JSONDecodeError, OSError):
                    pass  # disk is corrupt or missing — just write ours

            # Atomic write via temp file
            tmp = sf.with_suffix(".tmp")
            tmp.write_text(json.dumps(self._state, indent=2, default=str), encoding="utf-8")
            shutil.move(str(tmp), str(sf))

    # --- Public Getters ---

    def get(self, key: str, default: Any = None) -> Any:
        """Get a state value by key, merging with campaign data if active.

        Special key "domain" returns the first domain from the "domains" list
        for backward compatibility.
        """
        # Backward-compat: "domain" → first entry in "domains" list
        if key == "domain":
            domains = self._state.get("domains", [])
            if campaign.campaign_manager.active:
                camp_domain = campaign.campaign_manager.get_var("DOMAIN")
                if camp_domain:
                    return camp_domain
            return domains[0] if domains else (default if default is not None else "")

        local_val = self._state.get(key, default)

        if not campaign.campaign_manager.active:
            return local_val

        if key in ("users", "hashes", "credentials"):
            camp_list = campaign.campaign_manager.get(key, [])
            local_list = local_val if isinstance(local_val, list) else []
            # For credentials/hashes (dicts), simple "not in" isn't perfect but sufficient for simple display uniqueness
            # A more robust union could be done, but lists of dicts usually have proper dedup at insert time anyway.
            # To be safe against duplicates, we return campaign items first, then local items not in campaign list
            merged = list(camp_list)
            for item in local_list:
                if item not in merged:
                    merged.append(item)
            return merged

        if key == "domain_info":
            camp_di = campaign.campaign_manager.get("domain_info", {})
            local_di = local_val if isinstance(local_val, dict) else {}
            return {**local_di, **camp_di}

        return local_val

    def get_var(self, var_name: str) -> str:
        """Get a variable value for template injection.

        Supports: {IP}, {DOMAIN}, {USER}, {PASS}, {DC_IP}, {HOSTNAME}, etc.
        """
        # Campaign fields take precedence if campaign is active
        domains = self._state.get("domains", [])
        domain = campaign.campaign_manager.get_var("DOMAIN") if campaign.campaign_manager.active else (domains[0] if domains else "")
        dc_ip = campaign.campaign_manager.get_var("DC_IP") if campaign.campaign_manager.active else self._state.get("domain_info", {}).get("dc_ip", "")
        dns_name = campaign.campaign_manager.get_var("DNS_NAME") if campaign.campaign_manager.active else self._state.get("domain_info", {}).get("dns_name", "")

        if campaign.campaign_manager.active:
            user = campaign.campaign_manager.get_var("USER")
            users_file = campaign.campaign_manager.get_var("USERFILE")
            hashes_file = str(campaign.campaign_manager.campaign_dir / "loot" / "hashes.txt") if campaign.campaign_manager.campaign_dir else ""
            pass_file = campaign.campaign_manager.get_var("PASSFILE")
            password = campaign.campaign_manager.get_var("PASS")
        else:
            creds = [c for c in self._state.get("credentials", []) if c.get("password") and c.get("username")]
            if creds:
                user = creds[0]["username"]
                password = creds[0]["password"]
            else:
                user = self._state.get("users", [""])[0] if self._state.get("users") else ""
                password = ""
            users_file = str(self._workspace / "loot" / "users.txt") if self._workspace else ""
            hashes_file = str(self._workspace / "loot" / "hashes.txt") if self._workspace else ""
            pass_file = str(self._workspace / "loot" / "passwords.txt") if self._workspace else ""

        var_map = {
            "IP": self._state.get("ip", ""),
            "RHOST": self._state.get("ip", ""),
            "TARGET": self._state.get("ip", ""),
            "DOMAIN": domain,
            "HOSTNAME": self._state.get("hostname", ""),
            "DC_IP": dc_ip,
            "DNS_NAME": dns_name,
            "USER": user,
            "PASS": password,
            "PASSWORD": password,
            "USERS_FILE": users_file,
            "USERFILE": users_file,
            "HASHES_FILE": hashes_file,
            "HASHFILE": hashes_file,
            "PASSFILE": pass_file,
            "OS": self._state.get("os", ""),
            "OS_BUILD": self._state.get("os_build", ""),
            "ARCH": self._state.get("arch", ""),
            "LHOST": "",  # User must set manually
            "LPORT": "443",
            "WORDLIST": "/usr/share/seclists/Discovery/Web-Content/raft-small-words.txt",
        }
        return var_map.get(var_name.upper(), "")

    # --- Public Setters ---

    def set(self, key: str, value: Any):
        """Set a state value and persist."""
        self._state[key] = value
        self._save_state()

    def add_domain(self, domain: str):
        """Add a domain name to the domains list (deduplicated)."""
        if not domain:
            return
        self._state.setdefault("domains", [])
        if domain not in self._state["domains"]:
            self._state["domains"].append(domain)
            self._save_state()
            # Also update domain_info primary domain if empty
            di = self._state.setdefault("domain_info", {})
            if not di.get("domain_name"):
                di["domain_name"] = domain
                self._save_state()

    def add_port(self, port: int, protocol: str = "tcp", service: str = "",
                 version: str = "", state: str = "open"):
        """Add a discovered port to state."""
        port_entry = {
            "port": port,
            "protocol": protocol,
            "service": service,
            "version": version,
            "state": state,
        }
        # Update existing or add new
        existing = [p for p in self._state["ports"] if p["port"] == port and p["protocol"] == protocol]
        if existing:
            existing[0].update(port_entry)
        else:
            self._state["ports"].append(port_entry)
        # Also update services dict
        self._state["services"][f"{port}/{protocol}"] = {
            "service": service,
            "version": version,
        }
        self._save_state()

    def add_user(self, username: str):
        """Add a discovered username."""
        if campaign.campaign_manager.active:
            campaign.campaign_manager.add_user(username)
        else:
            self._state.setdefault("users", [])
            if username and username not in self._state["users"]:
                self._state["users"].append(username)
                self._save_state()
                # Also write to users.txt for tool consumption
                self._write_list_file("loot/users.txt", self._state["users"])

    def add_hash(self, hash_str: str, username: str = ""):
        """Add a discovered hash."""
        if campaign.campaign_manager.active:
            campaign.campaign_manager.add_hash(hash_str, username)
        else:
            self._state.setdefault("hashes", [])
            entry = {"hash": hash_str, "username": username}
            if entry not in self._state["hashes"]:
                self._state["hashes"].append(entry)
                self._save_state()
                # Write hashes to file
                hashes = [h["hash"] for h in self._state["hashes"]]
                self._write_list_file("loot/hashes.txt", hashes)

    def set_os(self, os_name: str):
        """Set target operating system (e.g. Windows, Linux)."""
        self._state["os"] = os_name
        self._save_state()

    def set_os_build(self, build: str):
        """Set target OS build / version (e.g. Server 2019 Build 17763)."""
        self._state["os_build"] = build
        self._save_state()

    def set_hostname(self, hostname: str):
        """Set target hostname / machine name."""
        self._state["hostname"] = hostname
        self._save_state()

    def set_arch(self, arch: str):
        """Set target architecture (e.g. x64, x86)."""
        self._state["arch"] = arch
        self._save_state()

    def set_domain(self, domain_name: str, is_dc: bool = False):
        """Set primary domain name and DC status."""
        self.add_domain(domain_name)
        di = self._state.setdefault("domain_info", {})
        di["domain_name"] = domain_name
        di["is_domain_joined"] = True
        if is_dc:
            di["is_dc"] = True
        self._save_state()

    def add_credential(self, username: str, password: str, service: str = "", is_admin: bool = False):
        """Add discovered credentials."""
        if campaign.campaign_manager.active:
            campaign.campaign_manager.add_credential(username, password, service)
        else:
            self._state.setdefault("credentials", [])
            cred = {"username": username, "password": password, "service": service, "is_admin": is_admin}
            existing = next((c for c in self._state["credentials"] if c.get("username") == username and c.get("password") == password and c.get("service") == service), None)
            if existing:
                if is_admin:
                    existing["is_admin"] = True
            else:
                self._state["credentials"].append(cred)
            self._save_state()
            passwords = [c["password"] for c in self._state["credentials"] if c.get("password")]
            # Dedup passwords before writing
            seen_pass = []
            for p in passwords:
                if p not in seen_pass:
                    seen_pass.append(p)
            self._write_list_file("loot/passwords.txt", seen_pass)

    def add_directory(self, path: str, status_code: int = 200):
        """Add a discovered web directory."""
        self._state.setdefault("directories", [])
        entry = {"path": path, "status": status_code}
        if entry not in self._state["directories"]:
            self._state["directories"].append(entry)
            self._save_state()

    def add_software(self, name: str, version: str, source: str = ""):
        """Add a discovered software+version pair (e.g. from whatweb, page scrape)."""
        if not name or not version:
            return
        self._state.setdefault("software", [])
        # Dedup by name+version
        for existing in self._state["software"]:
            if existing["name"].lower() == name.lower() and existing["version"] == version:
                return
        self._state["software"].append(
            {"name": name, "version": version, "source": source}
        )
        self._save_state()

    def add_vhost(self, vhost: str):
        """Add a discovered virtual host."""
        self._state.setdefault("vhosts", [])
        if vhost and vhost not in self._state["vhosts"]:
            self._state["vhosts"].append(vhost)
            self._save_state()

    def add_share(self, share_name: str, permissions: str = "", comment: str = ""):
        """Add a discovered SMB share."""
        entry = {"name": share_name, "permissions": permissions, "comment": comment}
        existing = [s for s in self._state["shares"] if s["name"] == share_name]
        if existing:
            existing[0].update(entry)
        else:
            self._state["shares"].append(entry)
        self._save_state()

    def add_nse_result(self, port: int, script_id: str, output: str,
                       protocol: str = "tcp"):
        """Add an NSE script result."""
        self._state.setdefault("nse_results", [])
        entry = {
            "port": port,
            "protocol": protocol,
            "script_id": script_id,
            "output": output,
        }
        # Deduplicate by port+script_id — update output if already exists
        existing = next(
            (r for r in self._state["nse_results"]
             if r.get("port") == port and r.get("script_id") == script_id
             and r.get("protocol") == protocol),
            None,
        )
        if existing:
            existing["output"] = output
        else:
            self._state["nse_results"].append(entry)
        self._save_state()

    def add_vulnerability(self, vuln_id: str, title: str, port: int = 0,
                          script: str = "", state: str = "VULNERABLE",
                          refs: list[str] | None = None):
        """Add a discovered vulnerability."""
        self._state.setdefault("vulnerabilities", [])
        entry = {
            "id": vuln_id,
            "title": title,
            "port": port,
            "script": script,
            "state": state,
            "refs": refs or [],
        }
        # Deduplicate by vuln_id + port
        existing = next(
            (v for v in self._state["vulnerabilities"]
             if v.get("id") == vuln_id and v.get("port") == port),
            None,
        )
        if existing:
            existing.update(entry)
        else:
            self._state["vulnerabilities"].append(entry)
        self._save_state()

    def update_banner(self, port: int, protocol: str = "tcp", **fields):
        """Update banner info for a port.

        Example: update_banner(80, http_title="WordPress Site",
                               cpe=["cpe:/a:apache:http_server:2.4.49"])
        """
        self._state.setdefault("banners", {})
        key = f"{port}/{protocol}"
        existing = self._state["banners"].get(key, {})
        for k, v in fields.items():
            if isinstance(v, list) and isinstance(existing.get(k), list):
                # Merge lists (deduplicated)
                merged = list(existing[k])
                for item in v:
                    if item not in merged:
                        merged.append(item)
                existing[k] = merged
            else:
                existing[k] = v
        self._state["banners"][key] = existing
        self._save_state()

    def add_scan_record(self, tool: str, command: str, output_file: str = "",
                        duration: float = 0.0):
        """Record a scan execution in history."""
        record = {
            "tool": tool,
            "command": command,
            "output_file": output_file,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "duration": duration,
        }
        self._state["scan_history"].append(record)
        self._save_state()

    def add_note(self, note: str):
        """Add a freeform note."""
        entry = {
            "note": note,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        self._state["notes"].append(entry)
        self._save_state()

    def set_flag(self, flag_type: str, value: str):
        """Set user.txt / local.txt or proof.txt / root.txt flag."""
        k = flag_type.lower()
        if k in ("user", "user.txt", "local", "local.txt"):
            self._state.setdefault("flags", {})["user_txt"] = value
            self._state["flags"]["local_txt"] = value
        elif k in ("root", "root.txt", "proof", "proof.txt"):
            self._state.setdefault("flags", {})["proof_txt"] = value
        else:
            self._state.setdefault("flags", {})[flag_type] = value
        self._save_state()

    def _write_list_file(self, relative_path: str, items: list[str]):
        """Write a list of strings to a file in the workspace."""
        if self._workspace is None:
            return
        fpath = self._workspace / relative_path
        fpath.parent.mkdir(parents=True, exist_ok=True)
        fpath.write_text("\n".join(str(i) for i in items) + "\n", encoding="utf-8")

    # --- Display helpers ---

    def get_open_ports(self) -> list[int]:
        """Get list of open port numbers."""
        return [p["port"] for p in self._state.get("ports", []) if p.get("state") == "open"]

    def get_open_ports_proto(self):
        """Get set of (port, protocol) tuples for open ports."""
        return {
            (p["port"], p.get("protocol", "tcp"))
            for p in self._state.get("ports", [])
            if p.get("state") == "open"
        }

    def get_services_summary(self) -> dict[int, str]:
        """Get port -> service name mapping."""
        result = {}
        for p in self._state.get("ports", []):
            if p.get("state") == "open":
                result[p["port"]] = p.get("service", "unknown")
        return result

    def has_service(self, service_name: str) -> bool:
        """Check if a specific service was discovered."""
        for p in self._state.get("ports", []):
            if service_name.lower() in p.get("service", "").lower():
                return True
        return False

    def export_state(self) -> str:
        """Export current state as formatted JSON string."""
        return json.dumps(self._state, indent=2, default=str)

    # --- Methodology progress ---

    def get_methodology_progress(self, name: str) -> dict:
        """Get progress for a specific methodology."""
        return self._state.setdefault("methodology_progress", {}).get(name, {})

    def start_methodology(self, name: str):
        """Initialize tracking for a methodology."""
        progress = self._state.setdefault("methodology_progress", {})
        if name not in progress:
            progress[name] = {"started_at": datetime.now(timezone.utc).isoformat(), "completed_steps": []}
            self._save_state()

    def complete_methodology_step(self, name: str, step_id: str):
        """Mark a methodology step as complete."""
        progress = self._state.setdefault("methodology_progress", {})
        if name not in progress:
            progress[name] = {"started_at": datetime.now(timezone.utc).isoformat(), "completed_steps": []}
        if step_id not in progress[name]["completed_steps"]:
            progress[name]["completed_steps"].append(step_id)
            self._save_state()

    def refresh_notes(self) -> Path | None:
        """Regenerate notes.md with current state data."""
        if self._workspace is None:
            return None
        notes_file = self._workspace / "notes.md"
        ports = self._state.get("ports", [])
        users = self._state.get("users", [])
        creds = self._state.get("credentials", [])
        hashes = self._state.get("hashes", [])
        notes = self._state.get("notes", [])
        flags = self._state.get("flags", {})

        port_rows = ""
        for p in ports:
            if p.get("state") == "open":
                port_rows += f"| {p['port']} | {p.get('service','')} | {p.get('version','')} | |\n"

        cred_rows = ""
        for c in creds:
            cred_rows += f"| {c['username']} | {c['password']} | {c.get('service','')} | |\n"
        for h in hashes:
            cred_rows += f"| {h.get('username','')} | {h['hash'][:40]}... | hash | |\n"

        notes_text = ""
        for n in notes:
            notes_text += f"- [{n.get('timestamp','')[:19]}] {n['note']}\n"

        content = f"""# Target: {self._state.get('target', '')}
## Date: {self._state.get('created_at', '')[:10]}

## Summary
- **IP:** {self._state.get('ip', '')}
- **OS:** {self._state.get('os', 'Unknown')}
- **Hostname:** {self._state.get('hostname', '')}
- **Domains:** {', '.join(self._state.get('domains', [])) or 'N/A'}

## Recon

### Service Enumeration
| Port | Service | Version | Notes |
|------|---------|---------|-------|
{port_rows}
## Users ({len(users)})
{chr(10).join(f'- {u}' for u in users) if users else '(none yet)'}

## Initial Foothold
- **Vulnerability:**
- **Exploit/Method:**
- **Proof:**

## Privilege Escalation
- **Vector:**
- **Method:**
- **Proof:**

## Flags
- **local.txt:** {flags.get('local_txt', '')}
- **proof.txt:** {flags.get('proof_txt', '')}

## Credentials Found
| Username | Password/Hash | Service | Notes |
|----------|---------------|---------|-------|
{cred_rows}
## Notes
{notes_text if notes_text else '(none yet)'}
"""
        notes_file.write_text(content, encoding="utf-8")
        return notes_file


# Global singleton
state_manager = StateManager()
