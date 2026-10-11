# C.A.P.O — Context-Aware Pentest Orchestrator

> **The Pentester's Tactical Whiteboard & Heads-Up Display (HUD)**  
> Minimalist, stateful, and strictly human-in-the-loop. Keeps track of your attack surface, verified secrets, and loot while you focus on hacking.

```text
  ██████╗ ██╗ █████╗ ██████╗  ██████╗
 ██╔════╝ ██║██╔══██╗██╔══██╗██╔═══██╗
 ██║      ██║███████║██████╔╝██║   ██║
 ██║      ██║██╔══██║██╔═══╝ ██║   ██║
 ╚██████╗ ██║██║  ██║██║     ╚██████╔╝
  ╚═════╝ ╚═╝╚═╝  ╚═╝╚═╝      ╚═════╝
```

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)

---

## The Philosophy: Why C.A.P.O?

Most penetration testing tools either try to automate everything (and break in real-world scenarios) or leave you managing notes across chaotic terminal tabs and markdown files.

**C.A.P.O takes a human-in-the-loop approach:**
- **No Fragile Auto-Pwn:** You make all the tactical decisions. C.A.P.O does not force linear checklists or run destructive exploits autonomously.
- **The Tactical Whiteboard:** An interactive HUD in your terminal summarizing the 4 essential questions of any engagement:
  1. *What is the target footprint?* (IP, Hostname, OS, Kernel/Build, Arch, Domain, DC status)
  2. *What is the attack surface?* (Open ports, services, versions, web paths, shares)
  3. *What access do we have?* (Discovered users, verified credentials, hashes, flags)
  4. *What notes have we recorded?* (Scratchpad timestamped logs)
- **Zero Friction Manual Logging (`capo add`):** When you identify an exploit vector, discover a user in LDAP, or grab an NTLM hash, log it in one short command.
- **Automated Recon Ingestion (`capo scan`):** Automatically runs Nmap, parses ports, service versions, OS signatures, and banner scripts directly into the state database.
- **Persistent State Engine (Schema v5):** Concurrency-safe, file-locked JSON memory per workspace.

---

## Quick Install

```bash
git clone https://github.com/trungdo3224/capo.git
cd capo
pip install -e .
```

---

## Core commands and web workflow

### Web application testing

`capo web` adds an independent, repeating web pentesting workflow: observe, choose a
hypothesis, test, assess evidence, and revisit relevant tests. It includes 34 playbooks,
five tool adapters, per-engagement notes/evidence, Markdown knowledge retrieval and optional
local Gemma assistance. You choose each action; scanner output does not confirm findings.

Use `capo web suggest` to inspect proposed tests and `capo web advanced` to browse the
14 advanced techniques. The original `capo web next` remains a compatibility alias.

Start with `capo web doctor` and follow the [web workflow guide](docs/WEB-WORKFLOW.md).
Existing commands and target workspaces remain available.

The original **4 core CLI commands** remain available:

```text
capo target   ──> Set or inspect the active target workspace
capo scan     ──> Run automated recon (Nmap) and update whiteboard
capo add      ──> Manually log findings to the whiteboard
capo state    ──> Render the Tactical Heads-Up Display (HUD)
```

---

### 1. Target Management (`capo target`)

Set your active target. All commands will automatically operate in the context of this target's workspace.

```bash
# Set active target IP or hostname
capo target 10.10.11.99
# Or explicitly:
capo target set 10.10.11.99 --domain inlanefreight.local

# View current target state HUD
capo target
```

---

### 2. Automated Recon (`capo scan`)

Run network scans with automatic XML parsing and state extraction:

```bash
# Quick TCP SYN scan top 1,000 ports
capo scan quick

# Full TCP port scan (all 65,535 ports) with -sC -sV
capo scan full

# UDP service scan
capo scan udp

# Preview exact Nmap command without running
capo scan quick --dry-run
```

*Results (open ports, protocols, services, versions, OS detection) are automatically parsed and written to the target's state.*

---

### 3. Whiteboard Logger (`capo add`)

Whenever you discover new intelligence during manual testing, log it directly onto your whiteboard:

```bash
# Target Fingerprinting
capo add os "Windows Server 2022"
capo add os-build "20348"
capo add arch "x64"
capo add domain "inlanefreight.local" --dc
capo add hostname "DC01"

# Network & Services
capo add port 80 http "Apache httpd 2.4.52"
capo add port 445 smb "Microsoft Windows Server 2022 smb"
capo add share SYSVOL READ "Logon share"
capo add dir /admin 200
capo add vhost dev.inlanefreight.local

# Identities & Credentials
capo add user svc_backup
capo add cred Administrator "Password123!" --admin
capo add hash "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0" ntlm Administrator

# Progress & Scratchpad
capo add flag user_txt 7a8b9c0d1e2f...
capo add note "Found potential AS-REP roaster user svc_backup without pre-auth"
```

---

### 4. Tactical Heads-Up Display (`capo state`)

Display your real-time tactical whiteboard in rich ANSI formatting:

```bash
capo state
```

```text
============================ TARGET CARD ============================
 Target IP   : 10.10.11.99
 Hostname    : DC01
 OS / Build  : Windows Server 2022 (Build 20348)
 Arch        : x64
 Domain      : INLANEFREIGHT.LOCAL [DC]

=========================== SERVICE MATRIX ==========================
 Port   Proto  Service       Version                   Details
 53     tcp    domain        Simple DNS Plus           -
 88     tcp    kerberos-sec  Microsoft Windows         -
 80     tcp    http          Apache httpd 2.4.52       Dirs: /admin, /api
 445    tcp    microsoft-ds  Windows Server 2022       Shares: SYSVOL (READ)

======================== INTEL & LOOT VAULT =========================
 Users  : Administrator, svc_backup
 Creds  : [ADMIN] Administrator : Password123!
 Hashes : [ntlm] Administrator : aad3b435b51404eeaad3...
 Flags  : [user_txt] 7a8b9c0d1e2f...

========================= SCRATCHPAD NOTES ==========================
 * [2026-09-14 17:00] Found potential AS-REP roaster user svc_backup
```

You can also filter by specific categories:

```bash
capo state ports      # list all open ports & services
capo state users      # list all discovered users
capo state creds      # list credentials & hashes
capo state shares     # list SMB shares
capo state dirs       # list discovered web directories
```

---

## Workspace Layout (`~/.capo/`)

Each target gets an isolated workspace containing raw evidence and the state database:

```text
~/.capo/
├── workspaces/
│   └── 10.10.11.99/
│       ├── state.json       # Concurrency-safe target intelligence (Schema v5)
│       ├── scans/           # Raw Nmap outputs (.nmap, .xml, .gnmap)
│       ├── loot/            # Target wordlists (users.txt, passwords.txt)
│       ├── exploits/        # Downloaded payloads & scripts
│       ├── evidence/        # Screenshots, proof, command logs
│       └── notes.md         # Auto-generated markdown report template
└── .current_target          # Active target pointer
```

---

## Running Unit Tests

```bash
pytest
```

---

## License

MIT License. Designed for ethical security researchers, CTF competitors, and penetration testers.
