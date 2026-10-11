"""Advanced web rules; guidance is data, never executable payloads."""


def playbooks(book):
    def advanced(key, title, triggers, procedure, comparison, confirmation, pitfalls,
                 followups, source, manual=False, identities=False, cost=20):
        rule = book(
            key, title, triggers, procedure, comparison, confirmation, pitfalls,
            followups, prerequisites=("request",), tool="manual" if manual else "curl",
        )
        rule.update(
            category="advanced", references=["https://portswigger.net/web-security/" + source],
            manual_only=manual, identity_sensitive=identities, cost=cost,
        )
        return rule

    return [
        advanced(
            "cache-poisoning", "Web Cache Poisoning",
            "cache cached caching cdn age x-cache cache-control vary unkeyed",
            "Establish cache hits/misses and which inputs affect the cache key. Verify a unique "
            "test key isolates the entry. Vary one candidate unkeyed input using an inert marker, "
            "then request the same key without that input from a separate clean client. Record TTL "
            "and expire or remove the test entry afterward.",
            "Compare clean miss, modified request, clean hit and a fresh isolated key. Keep the "
            "verification key unchanged; use different keys between experiments.",
            "An independently fetched cached response retains the injected change; demonstrate "
            "its security consequence separately before confirming a vulnerability.",
            "Reflection, Age or X-Cache alone is not proof. A cache buster may be ignored; "
            "browser caching and origin personalization can mimic shared-cache behavior.",
            ["xss", "host-header", "dom"], "web-cache-poisoning",
        ),
        advanced(
            "cache-deception", "Web Cache Deception",
            "cache cached caching cdn age x-cache cache-control vary "
            "account profile private static extension normalization",
            "Use a test account's private page and isolated URLs. Check whether path suffixes, "
            "delimiters or normalization make the origin serve private content under a cacheable "
            "route. Fetch the exact same route from a separate unauthenticated client; remove or "
            "expire the entry after the experiment.",
            "Compare original private route, modified route as its owner, then identical modified "
            "route without cookies. Verify fresh-key controls deny access.",
            "The shared cache serves identifiable private test-account content to a client that "
            "cannot obtain it directly from the origin.",
            "Static extensions and cache headers do not establish leakage. Avoid using another "
            "person's data; distinguish direct authorization failure from cache disclosure.",
            ["idor", "auth"], "web-cache-deception", identities=True,
        ),
        advanced(
            "smuggling", "HTTP Request Smuggling and Desynchronization",
            "smuggling desync desynchronization proxy intermediary front-end backend http2 "
            "transfer-encoding content-length",
            "Map protocol conversions and intermediaries. In an isolated lab connection, use "
            "a request editor that preserves framing bytes and a paired follow-up request you "
            "control. Record connection reuse and exact wire bytes. Cover framing disagreements "
            "and HTTP/2 downgrade behavior only when that protocol is observed.",
            "Compare unambiguous framing with the candidate discrepancy and repeated paired "
            "follow-up behavior; separate ordinary timeout and connection-close behavior.",
            "Repeatable boundary disagreement changes interpretation of your controlled subsequent "
            "request. Demonstrate a concrete security consequence separately.",
            "One timeout is insufficient. Ordinary HTTP clients normalize framing; Capo's raw "
            "import and curl replay cannot preserve smuggling probes. "
            "Do not target other users' traffic.",
            ["cache-poisoning", "host-header", "idor"], "request-smuggling", manual=True, cost=40,
        ),
        advanced(
            "host-header", "HTTP Host Header Attacks",
            "host x-forwarded-host forwarded reset absolute routing virtual-host",
            "Identify use of Host or forwarded authority in links, reset messages and routing. "
            "Keep the network destination pinned to the scoped application; vary one authority "
            "input using a controlled hostname. Inspect the test account's generated reset link "
            "without navigating to unscoped destinations.",
            "Compare normal authority, changed authority and a control; inspect generated links "
            "and actual routing rather than only redirects.",
            "Attacker-controlled authority causes a demonstrated reset-token exposure, routing "
            "policy bypass or independently verified cache impact.",
            "Reflected Host or redirect alone is not account takeover. Capo strips Host on normal "
            "replay, so attach manual wire evidence for these comparisons.",
            ["cache-poisoning", "ssrf", "auth"], "host-header", manual=True, identities=True,
        ),
        advanced(
            "deserialization", "Insecure Deserialization",
            "deserialize deserialization serialized serialization object pickle java php viewstate",
            "Identify encoding and serialization format before modifying one controlled field. "
            "Establish integrity checks and runtime behavior. Use benign type/property changes "
            "and corroborate reconstruction or gadget execution with a controlled effect.",
            "Compare original object, benign modification and invalid-format control under the "
            "same session. Separate parsing errors from application state changes.",
            "Untrusted serialized input causes an unintended object behavior or security-relevant "
            "state change; claim code execution only with independent execution evidence.",
            "Base64, a serialized cookie or stack trace alone is insufficient. Gadget suitability "
            "depends on installed classes, runtime and reachability.",
            ["auth", "command", "ssrf"], "deserialization",
        ),
        advanced(
            "race", "Race Conditions",
            "race concurrency concurrent coupon redeem transfer balance limit checkout",
            "State the invariant and reset test-account state. Compare sequential execution with "
            "a fixed small synchronized batch. Record request count, timing, identifiers and "
            "persistent before/after state. Repeat only within the selected attempt budget.",
            "Use the same operations and starting state for sequential and concurrent runs; "
            "read back final state after all requests finish.",
            "Concurrency reproducibly violates the stated invariant while equivalent sequential "
            "operations do not.",
            "Multiple success messages can represent one committed operation. Rate-limit behavior "
            "and network timing alone are not proof; serial adapters do not synchronize batches.",
            ["logic", "auth", "api"], "race-conditions", manual=True, identities=True, cost=35,
        ),
        advanced(
            "jwt", "JWT Validation Attacks",
            "jwt bearer jws jwk jwks kid token claims algorithm",
            "Decode the test token and record issuer, audience, expiry and intended authorization. "
            "Change one claim, algorithm or key-selection input at a time. Test signature "
            "enforcement before investigating applicable key-confusion or key-trust behavior.",
            "Compare valid token, tampered token, invalid signature and expired token against "
            "the same protected operation; verify the resulting identity and permissions.",
            "A token that violates the validation policy gains demonstrably unauthorized access "
            "or changes the accepted identity.",
            "Decoding is not verification. A 200 login page is not accepted authentication; "
            "client-side claim changes and unused fields do not prove server trust.",
            ["auth", "idor", "api"], "jwt", identities=True,
        ),
        advanced(
            "oauth", "OAuth and OpenID Connect",
            "oauth oidc openid authorize authorization-code redirect_uri pkce nonce state callback",
            "Map browser, client and provider exchanges using test accounts. Check redirect URI "
            "binding, state/session binding, code reuse and PKCE where applicable. For OIDC also "
            "check nonce and ID-token issuer/audience. Keep each account's flow separate.",
            "Compare a valid flow with one changed binding; inspect the final logged-in identity "
            "and account-linking state, not just callback status.",
            "A binding failure produces an unauthorized login, account link or controlled token "
            "disclosure with a reproducible flow.",
            "Missing state alone is not proof where other binding exists. OAuth authorization "
            "and OIDC authentication are distinct; redirects must not silently expand scope.",
            ["auth", "jwt", "idor"], "oauth", manual=True, identities=True, cost=30,
        ),
        advanced(
            "nosql", "NoSQL Injection",
            "nosql mongo mongodb operator bson document-database mongoose",
            "Identify the query format and input type. Distinguish syntax injection from "
            "operator injection; vary one scalar or structured property in the captured request.",
            "Repeat equivalent true/false query controls and invalid-type controls while "
            "preserving method, content type and session.",
            "Repeatable query-dependent behavior shows control of query semantics beyond the "
            "intended input, with the demonstrated access consequence recorded.",
            "JSON acceptance, database errors and one changed result are insufficient. SQLmap "
            "does not substitute for NoSQL-specific comparisons.",
            ["auth", "idor", "api"], "nosql-injection",
        ),
        advanced(
            "prototype", "Prototype Pollution",
            "prototype __proto__ constructor merge javascript node pollution",
            "Trace user-controlled keys into recursive merges or property assignments. Use a "
            "unique benign property and check whether a separately created object inherits it. "
            "Then trace a reachable consumer; reset the isolated browser or server test state.",
            "Compare ordinary own-property input with inherited-property behavior and a fresh "
            "unmodified execution context.",
            "Untrusted input changes a prototype and a reachable consumer causes a demonstrated "
            "security effect; record these as separate evidence steps.",
            "An echoed __proto__ key is not pollution. Server-wide properties can affect later "
            "requests; a gadget name does not establish reachability or code execution.",
            ["dom", "xss", "command"], "prototype-pollution", manual=True,
        ),
        advanced(
            "dom", "Advanced DOM-Based Attacks",
            "dom sink source hash fragment location document javascript innerhtml",
            "Trace URL, storage or message input through decoding and sanitization to a browser "
            "sink. Use a benign marker, then a context-appropriate execution or navigation test. "
            "Record browser version, source, sink and rendered behavior.",
            "Compare inert and encoded input in raw HTTP, live DOM and a fresh browser context.",
            "A controllable source reaches an unsafe sink and causes the demonstrated execution, "
            "navigation or data exposure in the affected origin.",
            "Server reflection does not prove a DOM flow. HTML insertion alone may not execute; "
            "CSP, Trusted Types and decoding order affect exploitability.",
            ["xss", "postmessage", "prototype"], "dom-based", manual=True,
        ),
        advanced(
            "cors", "CORS Misconfiguration",
            "cors access-control-allow-origin access-control-allow-credentials origin preflight",
            "Identify sensitive endpoints and their authentication mechanism. Compare origins, "
            "then use a controlled separate-origin browser page to check whether credentials "
            "are sent and response data is readable. Record preflight and cookie behavior.",
            "Compare trusted, controlled untrusted and rejected origins with the same account "
            "and protected resource; preserve browser-enforced conditions.",
            "An untrusted origin can read sensitive authenticated response data through the "
            "browser despite the intended origin policy.",
            "Reflected ACAO alone is not proof. Wildcard origin with credential mode is rejected "
            "by browsers; SameSite and third-party cookie settings affect the actual request.",
            ["auth", "api"], "cors", manual=True, identities=True,
        ),
        advanced(
            "websocket", "WebSocket Security",
            "websocket websockets ws wss upgrade socket handshake",
            "Record handshake authentication and Origin handling, then map message actions. "
            "Compare object/role authorization per message, session revocation and reconnects. "
            "Test browser cross-site initiation separately from message injection.",
            "Replay the same message with owner and nonowner test accounts; compare allowed "
            "and disallowed browser origins plus revoked sessions.",
            "An unauthorized message action, protected data disclosure or browser cross-site "
            "session hijack is demonstrated under the tested authentication policy.",
            "A 101 handshake is not an authorization bypass. HTTP adapters do not capture "
            "WebSocket frames; attach frame transcripts and resulting state.",
            ["idor", "auth", "xss"], "websockets", manual=True, identities=True,
        ),
        advanced(
            "postmessage", "Cross-Window Messaging (postMessage)",
            "postmessage message event.origin event.source targetorigin iframe window",
            "Map sending windows and receivers. Check exact origin and source-window validation "
            "and how message data reaches sinks. Send benign messages from a controlled untrusted "
            "window and inspect sensitive outbound messages and their targetOrigin.",
            "Compare legitimate sender with untrusted sender and lookalike origins; keep the "
            "message shape identical when testing sender validation.",
            "An unauthorized sender causes a protected action or unsafe sink, or a controlled "
            "recipient receives sensitive messages contrary to policy.",
            "A message listener or wildcard targetOrigin alone is not sufficient. Confirm "
            "window relationships, accepted data and actual execution or disclosure.",
            ["dom", "xss", "auth"], "dom-based/controlling-the-web-message-source", manual=True,
        ),
    ]
