"""Traffic import preserves request bodies as bytes and keeps identity labels explicit."""

import base64
import json
from urllib.parse import parse_qsl, urlsplit, urlunsplit

from .store import digest, origin


def validate_headers(headers):
    for name, value in headers:
        if not name or any(c in name for c in "\r\n:") or any(c in value for c in "\r\n"):
            raise ValueError("Invalid HTTP header.")


def add_request(engagement, method, url, headers, body, identity="anonymous", source=None):
    url = engagement.check_url(url)
    if not method.isalpha():
        raise ValueError("Invalid HTTP method.")
    validate_headers(headers)
    # Host overrides are a different application, not an implicit scope expansion.
    for name, value in headers:
        if name.lower() == "host" and origin(urlsplit(url).scheme + "://" + value) != origin(url):
            raise ValueError(
                "Host header differs from the scoped URL; "
                "import with the intended virtual host URL."
            )
    parameters = [k for k, _ in parse_qsl(urlsplit(url).query, keep_blank_values=True)]
    content_type = next((v for k, v in headers if k.lower() == "content-type"), "")
    if "application/x-www-form-urlencoded" in content_type:
        parameters += [
            k for k, _ in parse_qsl(body.decode("utf-8", errors="replace"), keep_blank_values=True)
        ]
    elif "json" in content_type:
        try:
            obj = json.loads(body)
            if isinstance(obj, dict):
                parameters += list(obj)
        except (ValueError, UnicodeError):
            pass
    record = {
        "method": method.upper(),
        "url": url,
        "headers": headers,
        "body_b64": base64.b64encode(body).decode(),
        "identity": identity,
        "parameters": sorted(set(parameters)),
        "source": source,
    }
    identity_data = dict(record)
    identity_data.pop("source")
    request_id = engagement.put("request", record, key=digest(identity_data))
    engagement.put("endpoint", {"url": url, "method": method.upper(), "tags": parameters}, key=url)
    return request_id


def import_raw(engagement, data, url=None, identity="anonymous", source=None):
    if b"\r\n\r\n" in data:
        header, body = data.split(b"\r\n\r\n", 1)
    elif b"\n\n" in data:
        header, body = data.split(b"\n\n", 1)
    else:
        header, body = data, b""
    lines = header.decode("iso-8859-1").splitlines()
    if not lines:
        raise ValueError("Empty request.")
    parts = lines[0].split()
    if len(parts) != 3 or not parts[2].startswith("HTTP/1."):
        raise ValueError("Expected a raw HTTP/1.x request; use HAR for HTTP/2 traffic.")
    method, target, _ = parts
    headers = []
    for line in lines[1:]:
        if ":" not in line:
            raise ValueError("Malformed request header.")
        name, value = line.split(":", 1)
        headers.append([name, value.strip()])
    if any(k.lower() in {"transfer-encoding", "upgrade"} for k, _ in headers):
        raise ValueError("Chunked/upgraded requests need a decoded HAR export before replay.")
    lengths = [v for k, v in headers if k.lower() == "content-length"]
    if lengths and (
        len(set(lengths)) != 1 or not lengths[0].isdigit() or int(lengths[0]) != len(body)
    ):
        raise ValueError("Request body does not match Content-Length; import a complete request.")
    if url:
        base = urlsplit(engagement.check_url(url))
        resolved = (
            target
            if target.startswith(("http://", "https://"))
            else urlunsplit(
                (base.scheme, base.netloc, urlsplit(target).path, urlsplit(target).query, "")
            )
        )
    elif target.startswith(("http://", "https://")):
        resolved = target
    else:
        raise ValueError("Raw origin-form requests require --url to specify HTTP vs HTTPS.")
    return add_request(engagement, method, resolved, headers, body, identity, source)


def import_har(engagement, data, identity="anonymous", source=None):
    document = json.loads(data)
    if not isinstance(document, dict) or not isinstance(document.get("log"), dict):
        raise ValueError("Expected a HAR object with log.entries.")
    entries = document.get("log", {}).get("entries")
    if not isinstance(entries, list):
        raise ValueError("Expected HAR log.entries.")
    imported, skipped = [], []
    for entry in entries:
        request = entry["request"]
        try:
            engagement.check_url(request["url"])
        except ValueError:
            skipped.append(request["url"])
            continue
        post = request.get("postData", {})
        if post.get("params") and "text" not in post:
            raise ValueError("HAR omits original request body bytes; export with request content.")
        text = post.get("text", "")
        body = (
            base64.b64decode(text, validate=True)
            if post.get("encoding") == "base64"
            else text.encode("utf-8")
        )
        headers = [
            [h["name"], h["value"]]
            for h in request.get("headers", [])
            if not h["name"].startswith(":")
        ]
        if request.get("cookies") and not any(k.lower() == "cookie" for k, _ in headers):
            headers.append(
                ["Cookie", "; ".join(f"{c['name']}={c['value']}" for c in request["cookies"])]
            )
        identifier = add_request(
            engagement, request["method"], request["url"], headers, body, identity, source
        )
        imported.append(identifier)
        response = entry.get("response", {})
        if response:
            response_headers = [h["name"] for h in response.get("headers", [])]
            engagement.put(
                "observation",
                {
                    "url": request["url"],
                    "text": (
                        f"Captured response status {response.get('status')}; "
                        f"request identity {identity}."
                        f" Response header names: {', '.join(response_headers)}."
                    ),
                    "evidence": [source] if source else [],
                    "request": identifier,
                },
                key=digest([identifier, response]),
            )
    return {"requests": imported, "skipped_out_of_scope": skipped}


def raw_request(request):
    p = urlsplit(request["url"])
    target = urlunsplit(("", "", p.path or "/", p.query, ""))
    body = base64.b64decode(request["body_b64"])
    headers = [
        (k, v)
        for k, v in request["headers"]
        if k.lower() not in {"host", "content-length", "connection"}
    ]
    lines = [
        f"{request['method']} {target} HTTP/1.1",
        f"Host: {p.netloc}",
        *[f"{k}: {v}" for k, v in headers],
        f"Content-Length: {len(body)}",
    ]
    return ("\r\n".join(lines) + "\r\n\r\n").encode("iso-8859-1") + body


def parse_results(tool, text):
    """Yield normalized observations; malformed output raises, never means a clean scan."""
    if tool == "ffuf":
        obj = json.loads(text)
        if not isinstance(obj, dict) or not isinstance(obj.get("results"), list):
            raise ValueError("ffuf output is missing results.")
        for row in obj["results"]:
            if not isinstance(row, dict) or not isinstance(row.get("url"), str):
                raise ValueError("ffuf result is missing a URL.")
            yield {
                "url": row["url"],
                "text": (
                    f"ffuf candidate: status={row.get('status')} length={row.get('length')}; "
                    "requires comparison."
                ),
            }
    elif tool in {"katana", "nuclei"}:
        for line in text.splitlines():
            if not line.strip():
                continue
            row = json.loads(line)
            if not isinstance(row, dict):
                raise ValueError(f"Expected a {tool} JSON object per line.")
            if tool == "katana":
                url = row.get("request", {}).get("endpoint")
                if not url:
                    raise ValueError("Katana row has no request.endpoint.")
                yield {
                    "url": url,
                    "text": (
                        "Katana discovered endpoint; purpose and authorization remain untested."
                    ),
                }
            else:
                url = row.get("matched-at") or row.get("host")
                if not url:
                    raise ValueError("Nuclei row has no matched-at/host.")
                yield {
                    "url": url,
                    "text": (
                        f"Nuclei signal {row.get('template-id', 'unknown')}: "
                        f"{row.get('info', {}).get('name', '')}; manual confirmation required."
                    ),
                }
    elif tool in {"curl", "sqlmap"}:
        # Retain raw evidence; SQLmap's human-readable logs are not a stable finding API.
        return
    else:
        raise ValueError(f"Unsupported result format: {tool}")


def ingest_results(engagement, tool, text, evidence, url=None, action=None):
    rows = list(parse_results(tool, text))  # validate completely before writing observations
    accepted, skipped = [], []
    for row in rows:
        try:
            row["url"] = engagement.check_url(row["url"])
        except ValueError:
            skipped.append(row["url"])
            continue
        row["evidence"] = [evidence]
        row["action"] = action
        accepted.append(engagement.put("observation", row, key=digest(row)))
        engagement.put("endpoint", {"url": row["url"], "method": "GET"}, key=row["url"])
    if tool in {"curl", "sqlmap"}:
        if not url:
            raise ValueError("Text result imports require --url.")
        url = engagement.check_url(url)
        row = {
            "url": url,
            "text": f"{tool} output recorded for review; no vulnerability conclusion was inferred.",
            "evidence": [evidence],
            "action": action,
        }
        accepted.append(engagement.put("observation", row, key=digest(row)))
    return {"observations": accepted, "skipped_out_of_scope": skipped}
