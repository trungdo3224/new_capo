# Capo web workflow

Capo keeps an evidence-backed application map and proposes relevant tests. You select each action.
It does not run a scan sequence automatically or let an LLM execute commands.

## Start

Use the existing Capo environment, or install the project with `python -m pip install -e .`.
On this Windows checkout you can use `capo_venv\Scripts\python.exe -m capo` in place of `capo`.
On Linux use a separate Linux Python environment, not the Windows virtual environment.

```text
capo web doctor
capo web init practice --url http://lab.test:8080
capo web suggest
capo web show ACTION_ID
capo web run ACTION_ID --tool curl --dry-run
capo web run ACTION_ID --tool curl
```

Replace identifiers such as `ACTION_ID` with the IDs printed by Capo. `init` records exact
origins (scheme, host, port); repeat `--url` for additional allowed origins. Subdomains,
different ports and HTTP-to-HTTPS redirects do not silently expand scope.
Creating an engagement does not send traffic. Only `run` executes a selected tool.

All tools support `--timeout` (1–600 seconds, default 60). Scanners use `--rate`
(1–20 requests/second, default 2), one worker and limited retries. Ctrl+C preserves partial
output. Use `--dry-run` to inspect arguments without writing input files or starting a tool.

## Offline web cheatsheets

Read quick references for all 34 current playbooks without creating an engagement,
running tools or starting Ollama:

```text
capo web cheatsheet
capo web cheatsheet sqli
capo web cheatsheet idor
capo web cheatsheet --search "graphql resolver"
capo web cheatsheet --all
capo web cheatsheet --json
capo web cheatsheet --output "web reference.md"
```

Each reference includes observable triggers, prerequisites, procedure, controlled comparisons,
confirmation criteria, common mistakes, adapter guidance, follow-up topics and knowledge paths.
Content comes directly from the versioned playbooks that drive `capo web suggest`, so their scope
stays aligned. Export writes Markdown and refuses to overwrite an existing file.
`--search` matches all supplied words without case sensitivity. `--json` returns full playbooks;
`--output` takes precedence over display options and exports all selected topics.
Knowledge reference paths are pointers, not proof that a document is in your local index.

## Advanced techniques and suggested tests

```text
capo web advanced
capo web advanced cache-poisoning
capo web advanced cache-deception
capo web advanced smuggling
capo web advanced --search "browser"
capo web advanced --all
capo web advanced --json
capo web advanced --output "advanced reference.md"
capo web suggest --advanced
capo web suggest --advanced --json
```

`advanced` is an offline reference command, with the same search/export options as `cheatsheet`.
It contains 14 versioned rules: cache poisoning, cache deception, request smuggling/desynchronization,
Host-header attacks, deserialization, race conditions, JWT, OAuth/OIDC, NoSQL injection,
prototype pollution, advanced DOM attacks, CORS, WebSockets and postMessage.
Each has observable triggers, a working-request prerequisite, comparisons, confirmation criteria,
pitfalls and linked primary references from PortSwigger's Web Security Academy. The external
references are not automatically downloaded into the local knowledge index.

`suggest` is the primary command for proposing tests from engagement observations, imported
request headers and parameters, HAR response header names, and demonstrated capabilities.
`next` remains a hidden compatibility alias with the same options and behavior.
`--advanced` filters the suggestions; it does not enable scanning or create unrelated tests.
Read a selected action using `capo web show ACTION_ID` for the complete procedure.
Suggestions are hypotheses, not proof of vulnerabilities.

For example, import the working request and record observed cache behavior:

```text
capo web observe "X-Cache changes from MISS to HIT on repeated requests" --url http://lab.test:8080/
capo web suggest --advanced
capo web show ACTION_ID
capo web observe "Controlled cache comparison completed" --action ACTION_ID --file comparison.txt
capo web assess ATTEMPT_ID inconclusive "Marker persisted; security impact still unproven" --evidence EVIDENCE_ID
capo web suggest --advanced
```

The normal evidence cycle handles advanced actions, including inconclusive revisions, suppressed
unchanged repeats and reopening after new evidence or authentication changes. Demonstrated
capabilities can suggest related techniques even without their trigger words, within the same origin.

Smuggling, Host-header, race, OAuth/OIDC, prototype, DOM, CORS, WebSocket and postMessage actions
are marked manual: `run` refuses to execute them through an unsuitable adapter. Their procedures
require framing-preserving clients, browser behavior or synchronized requests that the five
adapters do not implement. Attach proxy/browser/frame transcripts using `observe --action --file`.
The other advanced rules permit ordinary HTTP replay, with manually prepared comparisons;
curl replay alone does not execute a complete advanced technique or confirm a finding.
Cache guidance requires isolated cache keys and a separate verification client; an injected marker
or cache-hit header alone does not establish a security impact.

## Import real requests and label identities

```text
capo web import captured.har --format har --identity alice
capo web import request.txt --format request --url https://lab.test --identity alice
capo web observe "Alice owns invoice 318" --identity alice --role user --object invoice/318
capo web observe "Bob owns invoice 492" --identity bob --role user --object invoice/492
capo web observe "Invoice API accepts an object id" --url https://lab.test/api/invoices/318
capo web note "Expected policy: a user may read only their own invoices."
capo web suggest
```

Raw requests must be complete HTTP/1.x captures. Supply `--url` to identify HTTP versus HTTPS
for origin-form requests. Binary request bodies are stored as bytes; repeated headers and
identity labels are retained. HAR supports HTTP/2 captures but must contain body text (or
base64 content) for requests with bodies. Missing multipart bytes and chunked raw requests
are rejected rather than reconstructed inaccurately. Duplicate imports are deduplicated.

Use `capo web show REQUEST_ID` to inspect an imported request. This intentionally displays
its headers, including authentication information; it is a local inspection command.

## Run a test, assess it, then revisit

```text
capo web run ACTION_ID --tool curl --request REQUEST_ID
capo web show ATTEMPT_ID
capo web assess ATTEMPT_ID inconclusive "Session expired; repeat with a valid cookie" --evidence EVIDENCE_ID
capo web suggest
```

An inconclusive assessment produces a revised action with comparison guidance. An unchanged
completed, blocked or failed test stays suppressed. `suggest --all` displays suppressed actions;
you can explicitly run one again after fixing the problem. Every attempt is retained.
New independent observations, requests, roles, owned objects or relevant demonstrated
capabilities can reopen tests. Output from a test does not immediately schedule that same
test again before you assess it.

For browser, proxy or specialist-tool work performed outside Capo:

```text
capo web observe "Bob received Alice's private invoice contents" --action ACTION_ID --file comparison.txt
capo web assess ATTEMPT_ID supported "Cross-user invoice read bypasses ownership policy" --evidence EVIDENCE_ID --capability "Read another user's private invoice"
capo web suggest
```

Outcomes are `supported`, `contradicted`, `inconclusive`, `blocked` and `failed`.
Assessments require a conclusion and evidence. A failed execution cannot support or
contradict a vulnerability. Mapping completion does not create a vulnerability finding.
Other `supported` assessments are your explicit confirmation; Capo does not independently
verify your claim. Record a new attempt to revise an assessed conclusion.

Use `capo web chain CAPABILITY_ID HYPOTHESIS_ID "Why this capability enables the next test"`
to record a possible chain. A link between two demonstrated capabilities also requires
`--evidence EVIDENCE_ID` to be labelled demonstrated. Unproven links remain hypotheses.

## Tool adapters

Capo does not install or upgrade pentesting tools. `doctor` identifies missing binaries
and unrecognized/old versions. Install separately following upstream documentation:
[curl](https://curl.se/download.html), [ffuf](https://github.com/ffuf/ffuf),
[Katana](https://github.com/projectdiscovery/katana),
[sqlmap](https://github.com/sqlmapproject/sqlmap),
[Nuclei](https://github.com/projectdiscovery/nuclei).

- **curl:** replay the selected request, keep response headers and body separately, and do
  not follow redirects. Uses `curl.exe` on Windows to avoid the PowerShell alias.
- **ffuf:** choose a unique query/form parameter, a scalar top-level JSON property, or
  `path`; supply a wordlist and evidence of a comparison response. The wordlist is snapshotted
  and capped to `rate × timeout` entries. Redirects and recursion are not enabled.
- **Katana:** crawl from a GET URL to depth two with exact-origin scope and redirects disabled.
  A captured request supplies that identity's headers. It does not submit imported POST bodies.
- **sqlmap:** requires a captured request, one known parameter, and comparison evidence.
  Uses level/risk 1, boolean/error techniques, no redirects, one thread, and a request delay.
  The captured HTTP method is explicit, and stdin target-list detection is disabled.
  It performs detection, without database dumping or OS-shell options.
- **Nuclei:** requires one selected local HTTP path template. The adapter snapshots it and
  disables redirects, external callback integration and update checks. Dynamic requests,
  raw requests, executable protocols, workflows and identity/Host overrides are rejected.
  Use manual testing and evidence imports for templates outside this intentionally bounded subset.

```text
capo web run ACTION_ID --tool ffuf --request REQUEST_ID --parameter id --wordlist words.txt --comparison EVIDENCE_ID
capo web run ACTION_ID --tool sqlmap --request REQUEST_ID --parameter id --comparison EVIDENCE_ID
capo web run ACTION_ID --tool katana --request REQUEST_ID
capo web run ACTION_ID --tool nuclei --template selected-check.yaml
capo web import results.json --format ffuf
capo web import results.jsonl --format nuclei
capo web import results.jsonl --format katana
capo web import sqlmap-output.txt --format sqlmap --url https://lab.test/search?id=1
```

Nuclei and ffuf matches remain observations. SQLmap's textual logs are preserved for review,
not treated as a stable machine-readable finding API. Other tools can be used manually and
their raw evidence attached using `observe --file`.

Tool inputs, stdout, stderr, result files, versions, exit status, timing and hashes are saved
locally. These files can contain credentials and application data; they are not uploaded.
Authenticated requests stay separated by request/identity rather than using a global cookie.

## Independent knowledge and local Gemma

```text
capo web knowledge index --source "/path/to/CWES Knowledge Base" --source "/path/to/CWES-OPEN-SOURCE-TOOLS.md"
capo web knowledge search "authorization object ownership"
capo web knowledge index --embed
capo web knowledge search "kiểm tra phân quyền giữa hai tài khoản" --semantic
capo web explain "What should I compare for this suspected IDOR?"
capo web explain "What should I compare for this suspected IDOR?" --ai
```

Sources are read-only Markdown inputs. Indexing excludes images, navigation indexes,
provenance and duplicate documents. Subsequent indexing updates changed/deleted content.
Missing/offline source directories preserve the existing local cache and produce a warning.
`index` remembers its source paths. Removing the chat app does not remove the indexed text.
For future reindexing, move the standalone tool-map Markdown file to a durable knowledge folder
and register its new path if you delete the directory where it originally lived.

Capo's search combines SQLite FTS with optional local embedding similarity. Embeddings are
associated with the model digest; a model change falls back to keyword search until reindexed.
`--ai` explicitly enables local Gemma; retrieval and the testing cycle work without Ollama.
Capo never starts or downloads a model automatically.

The coach prompt lives in `capo/web/knowledge.py` as `PROMPT`. It requires standard wording,
facts/hypotheses separated, comparison requests, confirmation/contradiction criteria,
and source citations. It treats notes, responses and reference passages as untrusted data.
It includes the engagement's recent notes, observations, assessments and capabilities,
with an explicit truncation indicator. Source IDs `[S1]` and engagement IDs `[E1]` are returned
with their content. Invalid model citations produce a warning. The model has no command or
database mutation tools and cannot confirm findings.

Optional configuration: `CAPO_HOME/web/config.json` (default `~/.capo/web/config.json`).

```json
{
  "ollama_url": "http://127.0.0.1:11434",
  "chat_model": "gemma4:e4b-it-q8_0",
  "embedding_model": "embeddinggemma:latest",
  "binaries": {
    "sqlmap": ["python", "/path/to/sqlmap.py"]
  }
}
```

Binary overrides are argument arrays, not shell strings. On Windows, use absolute paths with
JSON-escaped backslashes or forward slashes. Only loopback Ollama endpoints are accepted.
Keep separate native Windows and Linux data directories when running both concurrently;
SQLite state is portable when copied with all connections closed. Do not run both platforms
against the same database over a network filesystem.

## Resume, export and validate

```text
capo web use practice
capo web status
capo web export findings.md
python -m pytest -q
```

Each engagement has a versioned transactional database and evidence directory. Existing
`target`, `scan`, `add` and `state` workspaces retain their original layout. Markdown exports
include notes, hypotheses, attempts, assessments, findings, capabilities, chains and evidence
references. Existing export files are never overwritten.

The test suite covers iteration, identities, malformed/duplicate imports, failed tools,
scope, interrupted output, read-only incremental indexing, unavailable models, prompt-data
separation and existing Nmap execution. Curl is tested against a local fixture server;
Installed ffuf and sqlmap are also tested against local fixtures; unavailable binaries skip
those execution tests. Katana and Nuclei use controlled arguments/output fixtures.
CI is configured for Windows and Linux
with Python 3.10, 3.12 and 3.14.
