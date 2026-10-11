# Web workflow validation

Validated locally on 2026-10-11.

- Windows: Python 3.14.7; 51 tests passed, 2 skipped because ffuf and sqlmap are absent.
- Kali Linux under WSL: Python 3.13.12; all 53 tests passed.
- Ruff checks pass for the new CLI, web modules, tests and live verification script.
- Existing target, state, add and scan tests pass. The shared runner no longer imports
  deleted methodology/session modules. Pre-existing Nmap wrapper edits were preserved.

Real execution checks used temporary local HTTP fixture servers:

- Windows curl 8.21.0 and Linux curl 8.18.0: exact method, cookie and binary-body replay;
  redirects retained as responses; no automatic vulnerability confirmation.
- Kali ffuf 2.1.0-dev: selected query-parameter fuzzing with a two-entry wordlist,
  identity headers, bounded rate and JSON result ingestion.
- Kali sqlmap 1.10.2: saved request and explicit method, stdin target detection disabled,
  selected parameter, controlled detection options and raw evidence preservation.
- Katana and Nuclei are absent on both tested environments. Their argument construction,
  scope/template restrictions and parsers are tested through controlled fixtures;
  actual binary execution remains unverified locally.

The source-independent index at `~/.capo/web/knowledge.sqlite3` contains 372 documents,
2,481 passages and 2,481 embeddings from `embeddinggemma:latest`. Reindexing is incremental.
The live verification script compared the indexed source hashes with their current content:
all indexed source documents remained unchanged.

The actual local `gemma4:e4b-it-q8_0` model answered a temporary invoice-authorization scenario
using six retrieved passages and engagement notes, with valid source/engagement citation IDs.
The final check returned a complete answer without an output-limit warning. Model-generated
advice still needs human review; the model has no execution or finding-confirmation tools.

CI is configured for Windows and Ubuntu with Python 3.10, 3.12 and 3.14. Those hosted matrix
runs have not been executed during this local session. No external target was scanned.

Reproduce with `python -m pytest -q` and, from the repository with `PYTHONPATH=.`,
`python scripts/verify_web_live.py`. The latter requires the independently indexed
knowledge and running local Ollama models; it creates only temporary engagement notes.
# Advanced techniques and command naming: 2026-10-11

Added 14 advanced playbooks and the offline `capo web advanced` command. The primary
recommendation command is now `capo web suggest`, with `next` retained as a hidden alias.
All 34 playbooks remain accessible through `cheatsheet`.

Validation of this extension:

- Windows Python 3.14.7: full suite 83 passed, 2 skipped (missing ffuf/sqlmap).
- Kali WSL Python 3.13.12: full suite 85 passed, including controlled local tool fixtures.
- Added 28 advanced checks covering all 14 rules through capture, inconclusive revision,
  suppression and reopening; offline catalog/search/export; alias compatibility; manual adapter
  rejection; HAR cache signals; identity changes; capability follow-ups and origin isolation.
- Ruff passed for web modules, CLI and advanced/cheatsheet tests.
- Direct Windows CLI listing/detail/help checks caught and fixed legacy console encoding
  of decorative Unicode in reference output. Added a cp1252 reference rendering check.

These checks validate workflow behavior and guidance delivery. They do not claim exploitation
of live advanced-vulnerability labs. Manual-only techniques have no new execution adapters.
External reference URLs were reviewed but are not automatically ingested into the RAG index.
