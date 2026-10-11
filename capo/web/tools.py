"""Five bounded adapters. A selected action is the only route to execution."""

import base64
import copy
import json
import os
import re
import shutil
import signal
import subprocess
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import yaml

from .playbooks import BY_ID
from .store import home, origin
from .traffic import ingest_results, raw_request

TOOLS = {
    "curl": ("--version", (7, 55, 0)),
    "ffuf": ("-V", (2, 0, 0)),
    "katana": ("-version", (1, 1, 0)),
    "sqlmap": ("--version", (1, 8, 0)),
    "nuclei": ("-version", (3, 0, 0)),
}


def settings():
    path = home() / "config.json"
    result = {
        "ollama_url": "http://127.0.0.1:11434",
        "chat_model": "gemma4:e4b-it-q8_0",
        "embedding_model": "embeddinggemma:latest",
        "binaries": {},
    }
    if path.exists():
        result.update(json.loads(path.read_text(encoding="utf-8")))
    return result


def executable(tool):
    if tool not in TOOLS:
        raise ValueError("Tool must be curl, ffuf, katana, sqlmap or nuclei.")
    configured = settings().get("binaries", {}).get(tool)
    if configured:
        if (
            not isinstance(configured, list)
            or not configured
            or not all(isinstance(p, str) for p in configured)
        ):
            raise ValueError(
                'Binary overrides must be argument arrays, e.g. ["python", "/path/sqlmap.py"].'
            )
        return configured
    return ["curl.exe" if tool == "curl" and os.name == "nt" else tool]


def doctor(tool):
    prefix = executable(tool)
    binary = shutil.which(prefix[0])
    if not binary:
        return {
            "tool": tool,
            "ready": False,
            "reason": (
                f"Missing {prefix[0]}; install separately or configure binaries.{tool} "
                f"in {home() / 'config.json'}."
            ),
        }
    try:
        result = subprocess.run(
            [*prefix, TOOLS[tool][0]],
            capture_output=True,
            timeout=8,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        output = (result.stdout + result.stderr).strip()
        match = re.search(r"(?<!\d)(\d+)\.(\d+)(?:\.(\d+))?", output)
        version = tuple(int(p or 0) for p in match.groups()) if match else None
        ready = result.returncode == 0 and version is not None and version >= TOOLS[tool][1]
        return {
            "tool": tool,
            "ready": ready,
            "version": output[:500],
            "minimum_version": ".".join(str(p) for p in TOOLS[tool][1]),
            "reason": ""
            if ready
            else (
                "Unrecognized or unsupported version; "
                "check the documented minimum and binary override."
            ),
        }
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"tool": tool, "ready": False, "reason": str(exc)}


@dataclass
class Command:
    tool: str
    args: list
    directory: Path
    inputs: dict = field(default_factory=dict)
    result_file: Path | None = None
    metadata: dict = field(default_factory=dict)

    def preview(self):
        # An argv preview is portable and does not invite copying shell-quoted secrets.
        args = list(self.args)
        for i, arg in enumerate(args[:-1]):
            if arg in {"-H", "--header"}:
                name = args[i + 1].split(":", 1)[0]
                if name.lower() in {"authorization", "cookie", "proxy-authorization", "x-api-key"}:
                    args[i + 1] = f"{name}: <redacted>"
        return {
            "tool": self.tool,
            "argv": args,
            "input_files": [str(p) for p in self.inputs],
            **self.metadata,
        }


def fuzz_request(request, parameter):
    request = copy.deepcopy(request)
    if "FUZZ" in json.dumps(request):
        raise ValueError(
            "The original request already contains FUZZ; choose an unambiguous request."
        )
    p = urlsplit(request["url"])
    pairs = parse_qsl(p.query, keep_blank_values=True)
    if parameter == "path":
        request["url"] = urlunsplit((p.scheme, p.netloc, p.path.rstrip("/") + "/FUZZ", p.query, ""))
    elif sum(k == parameter for k, _ in pairs) == 1:
        request["url"] = urlunsplit(
            (
                p.scheme,
                p.netloc,
                p.path,
                urlencode([(k, "FUZZ" if k == parameter else v) for k, v in pairs]),
                "",
            )
        )
    else:
        body = base64.b64decode(request["body_b64"])
        content_type = next((v for k, v in request["headers"] if k.lower() == "content-type"), "")
        if "application/x-www-form-urlencoded" in content_type:
            pairs = parse_qsl(body.decode(), keep_blank_values=True)
            if sum(k == parameter for k, _ in pairs) != 1:
                raise ValueError("Select a unique query/form parameter or 'path'.")
            body = urlencode([(k, "FUZZ" if k == parameter else v) for k, v in pairs]).encode()
        elif "json" in content_type:
            obj = json.loads(body)
            if (
                not isinstance(obj, dict)
                or parameter not in obj
                or isinstance(obj[parameter], (dict, list))
            ):
                raise ValueError("Select a scalar top-level JSON property.")
            obj[parameter] = "FUZZ"
            body = json.dumps(obj).encode()
        else:
            raise ValueError("Select a unique query/form parameter, JSON property or 'path'.")
        request["body_b64"] = base64.b64encode(body).decode()
    return request


def validate_template(path):
    """v1 supports explicit HTTP path templates, not executable/multi-protocol workflows."""
    raw = path.read_bytes()
    try:
        obj = yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        raise ValueError(f"Malformed Nuclei template: {exc}") from exc
    if not isinstance(obj, dict) or not obj.get("http"):
        raise ValueError("Select an HTTP path-based Nuclei template file.")
    if set(obj) - {"id", "info", "http", "variables", "constants"}:
        raise ValueError(
            "This adapter does not run workflows, code, headless or non-HTTP protocols."
        )
    if obj.get("variables") or obj.get("constants"):
        raise ValueError(
            "Template variables/constants need manual review outside this bounded adapter."
        )
    if not isinstance(obj["http"], list):
        raise ValueError("Nuclei http must be a list of request blocks.")
    for block in obj["http"]:
        if (
            not isinstance(block, dict)
            or not isinstance(block.get("path"), list)
            or not block["path"]
        ):
            raise ValueError("Each HTTP template block needs explicit paths.")
        if set(block) - {
            "method",
            "path",
            "headers",
            "body",
            "matchers",
            "matchers-condition",
            "extractors",
            "stop-at-first-match",
            "redirects",
            "max-redirects",
            "host-redirects",
        }:
            raise ValueError("Template uses unsupported raw/dynamic request features.")
        if block.get("redirects") or block.get("host-redirects"):
            raise ValueError("Select a template without redirects.")
        for path_value in block.get("path", []):
            if not isinstance(path_value, str) or not re.match(
                r"^\{\{(?:BaseURL|RootURL)\}\}(?:/|$)", path_value
            ):
                raise ValueError("Template paths must begin with {{BaseURL}}/ or {{RootURL}}/.")
            if "{{" in re.sub(r"\{\{(?:BaseURL|RootURL)\}\}", "", path_value) or "\\" in path_value:
                raise ValueError("Dynamic template destinations are not supported.")
        for name in block.get("headers", {}):
            if name.lower() in {"host", "authorization", "cookie"}:
                raise ValueError("Template cannot override the selected identity or Host header.")
    if b"interactsh" in raw.lower():
        raise ValueError("External callbacks require a separately configured manual test.")
    expressions = re.findall(r"\{\{(.*?)\}\}", raw.decode("utf-8"), re.S)
    if any(expr.strip() not in {"BaseURL", "RootURL"} for expr in expressions):
        raise ValueError("Dynamic template expressions need a manual test outside this adapter.")
    return raw


def build(
    engagement,
    action,
    tool,
    request_id=None,
    parameter=None,
    comparison=None,
    wordlist=None,
    template=None,
    rate=2,
    timeout=60,
):
    if BY_ID[action["playbook"]].get("manual_only"):
        raise ValueError(
            "This technique needs manual browser, connection or concurrency testing. "
            "Use capo web show ACTION_ID, then attach evidence with "
            'capo web observe "Observation" --action ACTION_ID --file FILE.'
        )
    if not 1 <= rate <= 20 or not 1 <= timeout <= 600:
        raise ValueError("Use rate 1–20 requests/sec and timeout 1–600 seconds.")
    url = engagement.check_url(action["url"])
    directory = engagement.path / "evidence" / f"run-{uuid.uuid4().hex}"
    inputs = {}
    request_id = request_id or action.get("request")
    request = engagement.get(request_id, "request") if request_id else None
    if request and request["url"] != url:
        raise ValueError("Select a request for this action's exact URL.")
    if request:
        engagement.check_url(request["url"])
    else:
        request = {
            "url": url,
            "method": "GET",
            "headers": [],
            "body_b64": "",
            "identity": "anonymous",
        }
    prefix = executable(tool)
    result_file = directory / "result.json"
    header_file = directory / "headers.txt"
    headers = [
        (k, v)
        for k, v in request["headers"]
        if k.lower() not in {"host", "content-length", "connection"}
    ]
    args = []
    if tool == "curl":
        # -q disables .curlrc; no -L, so redirects remain evidence rather than new requests.
        inputs[header_file] = "\n".join(f"{k}: {v}" for k, v in headers).encode()
        args = [
            "-q",
            "--silent",
            "--show-error",
            "--globoff",
            "--path-as-is",
            "--proto",
            "=http,https",
            "--max-time",
            str(timeout),
            "--request",
            request["method"],
            "--header",
            "@" + str(header_file),
            "--dump-header",
            str(directory / "response-headers.txt"),
            "--output",
            str(directory / "response-body.bin"),
            "--write-out",
            "%{http_code}",
            "--url",
            url,
        ]
        body = base64.b64decode(request["body_b64"])
        if body:
            body_file = directory / "request-body.bin"
            inputs[body_file] = body
            args.extend(["--data-binary", "@" + str(body_file)])
        result_file = None
    elif tool == "ffuf":
        if not parameter or not comparison or not wordlist:
            raise ValueError("ffuf requires --parameter, --comparison EVIDENCE_ID and --wordlist.")
        engagement.evidence_path(comparison)
        wordlist = Path(wordlist).resolve()
        if not wordlist.is_file():
            raise ValueError("Wordlist file does not exist.")
        # Snapshot only the bounded prefix so a huge list cannot silently become an unbounded run.
        lines = wordlist.read_bytes().splitlines()[: rate * timeout]
        if not lines or any(b"\r" in line or b"\n" in line or b"\x00" in line for line in lines):
            raise ValueError("Empty or malformed wordlist.")
        words = directory / "words.txt"
        inputs[words] = b"\n".join(lines) + b"\n"
        req_file = directory / "request.http"
        inputs[req_file] = raw_request(fuzz_request(request, parameter))
        config_file = directory / "ffuf.conf"
        inputs[config_file] = b"[http]\nfollowredirects = false\n"
        args = [
            "-config",
            str(config_file),
            "-request",
            str(req_file),
            "-request-proto",
            urlsplit(url).scheme,
            "-w",
            str(words),
            "-rate",
            str(rate),
            "-t",
            "1",
            "-timeout",
            "10",
            "-maxtime",
            str(timeout),
            "-noninteractive",
            "-mc",
            "all",
            "-of",
            "json",
            "-o",
            str(result_file),
        ]
    elif tool == "sqlmap":
        if not request_id or not parameter or not comparison:
            raise ValueError(
                "sqlmap requires a captured --request, --parameter and --comparison evidence."
            )
        if parameter not in request.get("parameters", []) or any(c in parameter for c in ",*\r\n"):
            raise ValueError("Select one captured parameter for SQL injection testing.")
        engagement.evidence_path(comparison)
        req_file = directory / "request.http"
        inputs[req_file] = raw_request(request)
        args = [
            "-r",
            str(req_file),
            "-p",
            parameter,
            "--batch",
            "--ignore-stdin",
            "--method",
            request["method"],
            "--level=1",
            "--risk=1",
            "--threads=1",
            "--technique=BE",
            "--ignore-redirects",
            "--disable-coloring",
            "--delay",
            str(1 / rate),
            "--timeout=10",
            "--retries=0",
            "--output-dir",
            str(directory / "sqlmap"),
        ]
        if urlsplit(url).scheme == "https":
            args.append("--force-ssl")
        result_file = None
    elif tool == "katana":
        if request["method"] != "GET" or request["body_b64"]:
            raise ValueError("Katana starts from a GET URL; use curl to replay this request first.")
        scope = "^" + re.escape(origin(url)) + r"(?:/|$)"
        inputs[header_file] = "\n".join(f"{k}: {v}" for k, v in headers).encode()
        args = [
            "-u",
            url,
            "-cs",
            scope,
            "-fs",
            "fqdn",
            "-dr",
            "-d",
            "2",
            "-rl",
            str(rate),
            "-c",
            "1",
            "-p",
            "1",
            "-ct",
            f"{timeout}s",
            "-timeout",
            "10",
            "-retry",
            "0",
            "-H",
            str(header_file),
            "-jsonl",
            "-o",
            str(result_file),
            "-silent",
        ]
    elif tool == "nuclei":
        if not template or not Path(template).is_file():
            raise ValueError("Nuclei requires one explicit --template FILE.")
        snapshot = directory / "template.yaml"
        inputs[snapshot] = validate_template(Path(template))
        inputs[header_file] = "\n".join(f"{k}: {v}" for k, v in headers).encode()
        args = [
            "-u",
            url,
            "-t",
            str(snapshot),
            "-dr",
            "-ni",
            "-duc",
            "-rl",
            str(rate),
            "-c",
            "1",
            "-bs",
            "1",
            "-timeout",
            "10",
            "-retries",
            "0",
            "-H",
            str(header_file),
            "-jsonl",
            "-o",
            str(result_file),
            "-silent",
        ]
    return Command(
        tool,
        [*prefix, *args],
        directory,
        inputs,
        result_file,
        {
            "identity": request["identity"],
            "request": request_id,
            "comparison": comparison,
            "rate": rate,
            "timeout": timeout,
            "scope": origin(url),
        },
    )


def stop_process(process):
    if process.poll() is not None:
        return
    if os.name == "nt":
        # Kill descendants too (e.g. a configured Python launcher); no shell interpolation.
        job = getattr(process, "_capo_job", None)
        if job:
            job.terminate()
        else:
            subprocess.run(
                ["taskkill", "/PID", str(process.pid), "/T", "/F"], capture_output=True, timeout=5
            )
        if process.poll() is None:
            process.kill()
    else:
        os.killpg(process.pid, signal.SIGKILL)
    process.wait(timeout=5)


class WindowsJob:
    """Keep child processes in a job so cancellation includes Python launchers."""

    def __init__(self, process):
        import ctypes
        from ctypes import wintypes

        self.api = ctypes.WinDLL("kernel32", use_last_error=True)
        self.api.CreateJobObjectW.argtypes = [wintypes.LPVOID, wintypes.LPCWSTR]
        self.api.CreateJobObjectW.restype = wintypes.HANDLE
        self.api.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
        self.api.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
        self.api.CloseHandle.argtypes = [wintypes.HANDLE]
        self.handle = self.api.CreateJobObjectW(None, None)
        if not self.handle or not self.api.AssignProcessToJobObject(
            self.handle, int(process._handle)
        ):
            if self.handle:
                self.api.CloseHandle(self.handle)
            raise OSError(
                ctypes.get_last_error(), "Could not contain the tool in a Windows process job"
            )

    def terminate(self):
        self.api.TerminateJobObject(self.handle, 1)

    def close(self):
        self.api.CloseHandle(self.handle)


def execute(engagement, action, command):
    command.directory.mkdir(parents=True)
    for path, data in command.inputs.items():
        path.write_bytes(data)
    attempt_id = engagement.put(
        "attempt",
        {"action": action["id"], "tool": command.tool, "execution": "running", **command.metadata},
    )
    version = doctor(command.tool)
    stdout = command.directory / "stdout.txt"
    stderr = command.directory / "stderr.txt"
    started = time.monotonic()
    status, code, error = "failed", None, ""
    if version["ready"]:
        process = None
        try:
            with stdout.open("wb") as out, stderr.open("wb") as err:
                kwargs = (
                    {"start_new_session": True}
                    if os.name != "nt"
                    else {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP}
                )
                process = subprocess.Popen(
                    command.args,
                    stdout=out,
                    stderr=err,
                    stdin=subprocess.DEVNULL,
                    shell=False,
                    **kwargs,
                )
                if os.name == "nt" and hasattr(process, "_handle"):
                    try:
                        process._capo_job = WindowsJob(process)
                    except OSError:
                        process.kill()
                        process.wait()
                        raise
                code = process.wait(timeout=command.metadata["timeout"])
                status = "completed" if code == 0 else "failed"
        except subprocess.TimeoutExpired:
            status, error = (
                "timeout",
                "Execution exceeded the selected timeout. Partial output preserved.",
            )
            stop_process(process)
        except KeyboardInterrupt:
            status, error = "cancelled", "Interrupted by user. Partial output preserved."
            if process:
                stop_process(process)
        except OSError as exc:
            error = str(exc)
        finally:
            if process and getattr(process, "_capo_job", None):
                process._capo_job.terminate()
                process._capo_job.close()
    else:
        error = version.get("reason", "Tool unavailable.")
    evidence = []
    for path in sorted(command.directory.rglob("*")):
        if path.is_file():
            evidence.append(
                engagement.evidence(
                    path.read_bytes(),
                    f"{attempt_id}: {path.relative_to(command.directory)}",
                    path.suffix or ".bin",
                )
            )
    manifest = {
        "attempt": attempt_id,
        "command": command.preview(),
        "version": version,
        "execution": status,
        "exit_code": code,
        "duration": round(time.monotonic() - started, 3),
        "error": error,
        "evidence": evidence.copy(),
    }
    evidence.append(
        engagement.evidence(json.dumps(manifest, indent=2), "Execution manifest", ".json")
    )
    parse_error = ""
    if status == "completed":
        try:
            if command.result_file:
                if not command.result_file.exists():
                    raise ValueError("Tool exited successfully but its result file is missing.")
                content = command.result_file.read_text(encoding="utf-8")
            else:
                content = stdout.read_text(encoding="utf-8", errors="replace")
            result_evidence = engagement.evidence(content, f"{command.tool} parsed output")
            evidence.append(result_evidence)
            ingest_results(
                engagement, command.tool, content, result_evidence, action["url"], action["id"]
            )
        except (ValueError, OSError, KeyError, TypeError, AttributeError) as exc:
            parse_error = str(exc)
    engagement.update(
        attempt_id,
        execution=status,
        exit_code=code,
        duration=manifest["duration"],
        evidence=evidence,
        error=error,
        parse_error=parse_error,
        version=version,
    )
    return engagement.get(attempt_id, "attempt")
