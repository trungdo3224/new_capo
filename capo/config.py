"""Global configuration and paths for C.A.P.O."""

import json
import os
from pathlib import Path

# Base directories
CAPO_HOME = Path(os.environ.get("CAPO_HOME", Path.home() / ".capo"))
CUSTOM_CHEATSHEETS_DIR = CAPO_HOME / "custom_cheatsheets"
WORKSPACES_DIR = CAPO_HOME / "workspaces"
CAMPAIGNS_DIR = CAPO_HOME / "campaigns"
CONFIG_FILE = CAPO_HOME / "config.json"
CURRENT_CAMPAIGN_FILE = CAPO_HOME / "current_campaign.txt"

# Core cheatsheets shipped with the tool
CORE_CHEATSHEETS_DIR = Path(__file__).parent / "core_cheatsheets"


# Default wordlist paths (common locations)
WORDLISTS = {
    "dir_small": "/usr/share/seclists/Discovery/Web-Content/raft-small-words.txt",
    "dir_medium": "/usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt",
    "dir_large": "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt",
    "dns_sub": "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
    "users": "/usr/share/seclists/Usernames/xato-net-10-million-usernames-dup.txt",
    "rockyou": "/usr/share/wordlists/rockyou.txt",
}

# Scan profiles
SCAN_PROFILES = {
    "aggressive": {
        "nmap_rate": 5000,
        "nmap_timing": "-T4",
        "ffuf_threads": 80,
        "ffuf_rate": 0,  # unlimited
        "nxc_threads": 10,
    },
    "normal": {
        "nmap_rate": 1000,
        "nmap_timing": "-T3",
        "ffuf_threads": 40,
        "ffuf_rate": 0,
        "nxc_threads": 5,
    },
    "stealth": {
        "nmap_rate": 300,
        "nmap_timing": "-T2",
        "ffuf_threads": 10,
        "ffuf_rate": 50,
        "nxc_threads": 2,
    },
}

# Operating modes
MODE_OSCP = "oscp"
MODE_CPTS = "cpts"

# Exam tool restrictions for OSCP
OSCP_RESTRICTED_TOOLS = [
    "sqlmap", "autosploit", "metasploit",  # MSF only allowed for 1 machine
    "burp_pro", "nessus", "openvas",
]

OSCP_ALLOWED_TOOLS = [
    "nmap", "ffuf", "feroxbuster", "gobuster", "dirb",
    "netexec", "crackmapexec", "enum4linux-ng",
    "nikto", "wpscan", "hydra", "hashcat", "john",
    "chisel", "ligolo-ng", "sshuttle",
    "impacket", "bloodhound", "ldapsearch",
    "curl", "wget", "nc", "socat",
]




class OutputConfig:
    """Global output verbosity control.

    Reads persistent preference from ~/.capo/config.json and can be
    overridden per-invocation with ``capo -q`` / ``capo --verbose``.
    """

    def __init__(self):
        self.quiet: bool = False
        self._load()

    def _load(self):
        if CONFIG_FILE.exists():
            try:
                data = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
                self.quiet = data.get("quiet", False)
            except (json.JSONDecodeError, OSError):
                pass

    def save(self):
        CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
        data: dict = {}
        if CONFIG_FILE.exists():
            try:
                data = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                pass
        data["quiet"] = self.quiet
        CONFIG_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")


output_config = OutputConfig()


def ensure_dirs():
    """Create necessary directories on first run."""
    CAPO_HOME.mkdir(parents=True, exist_ok=True)
    CUSTOM_CHEATSHEETS_DIR.mkdir(parents=True, exist_ok=True)
    WORKSPACES_DIR.mkdir(parents=True, exist_ok=True)
    CAMPAIGNS_DIR.mkdir(parents=True, exist_ok=True)
