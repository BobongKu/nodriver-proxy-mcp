"""Proxy MCP tools — 18 tools for traffic inspection, replay, fuzzing, rule management, and session variables.

All tools are registered via register_proxy_tools(mcp) in main.py.
"""

import json
import re
import time
import uuid
import logging
from typing import Optional

from ..proxy.recorder import traffic_db
from ..proxy.scope import scope_manager
from ..proxy.controller import proxy_manager

logger = logging.getLogger(__name__)


def _proxy_url() -> str | None:
    """Return the proxy URL if proxy is running, else None."""
    if proxy_manager.running:
        return f"http://127.0.0.1:{proxy_manager.port}"
    return None


def register_proxy_tools(mcp):
    """Register all 18 proxy tools with the FastMCP server."""

    # ── Lifecycle ──

    @mcp.tool()
    async def manage_proxy(action: str, port: int = 8082, ui: bool = False, upstream: str = "") -> str:
        """Start or stop the mitmproxy background process. This is the FIRST tool you should call before any proxy/traffic operation.

        WORKFLOW:
        1. Call manage_proxy(action="start") to start the proxy
        2. Then call browser_open(proxy_port=8082) to route browser traffic through it
        3. Now all browser traffic is captured — use get_traffic_summary, search_traffic, etc.

        To chain through Burp Suite: manage_proxy(action="start", upstream="localhost:8080")
        To get a web GUI: manage_proxy(action="start", ui=true) — opens mitmweb on port 8081

        Args:
            action: "start" to launch mitmproxy, "stop" to kill it. No other values accepted.
            port: Proxy listen port (default 8082). Browser must connect to the same port.
            ui: If true, launches mitmweb (web GUI on port 8081) instead of headless mitmdump.
            upstream: Forward all traffic to an upstream proxy (e.g. "localhost:8080" for Burp Suite). Leave empty for direct connections.
        """
        if action == "start":
            result = proxy_manager.start(port=port, ui=ui, upstream=upstream)
        elif action == "stop":
            result = proxy_manager.stop()
        else:
            result = {"error": f"Unknown action: {action}. Use 'start' or 'stop'."}
        return json.dumps(result, indent=2)

    @mcp.tool()
    async def set_scope(allowed_domains: list[str]) -> str:
        """Limit which domains the proxy records. Call AFTER manage_proxy(action="start").

        By default, ALL traffic is recorded. Use this to focus on specific target domains and reduce noise.
        Static assets (.jpg, .css, .woff, etc.) and OPTIONS requests are always ignored regardless of scope.

        Examples:
        - set_scope(allowed_domains=["target.com", "api.target.com"]) — only record these domains
        - set_scope(allowed_domains=[]) — reset to record everything

        Args:
            allowed_domains: List of domains to record. Subdomains must be listed explicitly. Empty list = record all traffic.
        """
        scope_manager.set_domains(allowed_domains)
        return json.dumps(scope_manager.to_dict(), indent=2)

    @mcp.tool()
    async def proxy_status() -> str:
        """Check if the mitmproxy process is currently running. Returns status, port, and PID.

        Call this BEFORE any proxy operation if you're unsure whether the proxy is already running.
        If status is "not_running", call manage_proxy(action="start") first.
        """
        if proxy_manager.running:
            return json.dumps({
                "status": "running",
                "port": proxy_manager.port,
                "pid": proxy_manager._proc.pid if proxy_manager._proc else None,
            }, indent=2)
        return json.dumps({"status": "not_running"})

    # ── Traffic Read ──

    @mcp.tool()
    async def get_traffic_summary(limit: int = 20, offset: int = 0) -> str:
        """Get a paginated list of all captured HTTP flows. REQUIRES: proxy must be running and traffic must exist.

        Returns flow IDs, URLs, methods, status codes, and latency for each flow.
        Use the returned flow_id values with inspect_flow, replay_flow, extract_from_flow, etc.

        WORKFLOW: manage_proxy(start) → browser_open → browser_go → get_traffic_summary → inspect_flow(flow_id)

        Args:
            limit: Maximum number of flows to return (default 20). Use smaller values to save tokens.
            offset: Number of flows to skip from the start (default 0). Use for pagination: offset=20 gets the next page.
        """
        result = traffic_db.get_summary(limit=limit, offset=offset)
        return json.dumps(result, indent=2)

    @mcp.tool()
    async def inspect_flow(flow_id: str, include: list[str] = None) -> str:
        """Get full details of a single HTTP flow (request headers, body, response headers, body).

        PREREQUISITE: Get flow_id from get_traffic_summary or search_traffic first.

        By default returns only metadata (URL, method, status) to save tokens.
        Add fields to the include list to get headers and bodies.

        Args:
            flow_id: The flow ID from get_traffic_summary or search_traffic results.
            include: List of fields to include. Options:
                - "metadata" (default) — URL, method, status code, latency
                - "requestHeaders" — all request headers
                - "requestBody" — request body content
                - "responseHeaders" — all response headers
                - "responseBody" — response body content
                Example: ["metadata", "requestHeaders", "responseBody"]
        """
        if include is None:
            include = ["metadata"]
        result = traffic_db.get_detail(flow_id, include=include)
        if not result:
            return json.dumps({"error": f"Flow {flow_id} not found"})
        return json.dumps(result, indent=2)

    @mcp.tool()
    async def search_traffic(
        query: str = None,
        domain: str = None,
        method: str = None,
        status_code: int = None,
        limit: int = 50,
    ) -> str:
        """Search captured traffic by keyword, domain, HTTP method, or status code.

        PREREQUISITE: Proxy must be running and have captured traffic.

        Use this instead of get_traffic_summary when you need to find specific requests.
        All filters are optional and can be combined (AND logic).

        Examples:
        - search_traffic(query="password") — find flows containing "password" in URL or body
        - search_traffic(domain="api.target.com", method="POST") — find all POSTs to the API
        - search_traffic(status_code=401) — find unauthorized responses

        Args:
            query: Keyword to search in URL, request body, and response body
            domain: Filter by exact domain (e.g. "api.target.com")
            method: Filter by HTTP method: "GET", "POST", "PUT", "DELETE", etc.
            status_code: Filter by exact response status code (e.g. 200, 401, 500)
            limit: Maximum results to return (default 50)
        """
        results = traffic_db.search(
            query=query, domain=domain, method=method,
            status_code=status_code, limit=limit,
        )
        return json.dumps({"total": len(results), "flows": results}, indent=2)

    @mcp.tool()
    async def extract_from_flow(
        flow_id: str,
        json_path: str = None,
        css_selector: str = None,
        regex: str = None,
    ) -> str:
        """Extract specific data from a flow's response body using JSONPath, CSS selector, or regex.

        PREREQUISITE: Get flow_id from get_traffic_summary or search_traffic.

        Choose exactly ONE extractor per call:
        - json_path: For JSON API responses. Example: "$.data.users[0].id"
        - css_selector: For HTML pages. Example: "input[name=csrf]" to find CSRF tokens
        - regex: For any text. Example: 'token":"([^"]+)' to capture a token value

        To save the extracted value for reuse in replay_flow, use extract_session_variable instead.

        Args:
            flow_id: The flow ID to extract from
            json_path: JSONPath expression (e.g. "$.data.users[0].id", "$.token")
            css_selector: CSS selector for HTML (e.g. "input[name=csrf]", "a.secret-link")
            regex: Regex pattern — use capture groups to extract specific parts (e.g. 'token":"([^"]+)')
        """
        detail = traffic_db.get_detail(flow_id, include=["metadata"])
        if not detail:
            return json.dumps({"error": f"Flow {flow_id} not found"})

        # Use untruncated body for accurate extraction
        body = traffic_db.get_raw_body(flow_id, "response_body") or ""
        matches = []

        if json_path:
            try:
                from jsonpath_ng import parse as jp_parse
                expr = jp_parse(json_path)
                data = json.loads(body)
                matches = [str(m.value) for m in expr.find(data)]
            except Exception as e:
                return json.dumps({"error": f"JSONPath error: {e}"})

        elif css_selector:
            try:
                from bs4 import BeautifulSoup
                soup = BeautifulSoup(body, "lxml")
                elements = soup.select(css_selector)
                for el in elements:
                    if el.get("value"):
                        matches.append(el["value"])
                    elif el.string:
                        matches.append(el.string.strip())
                    else:
                        matches.append(el.get_text(strip=True)[:200])
            except Exception as e:
                return json.dumps({"error": f"CSS selector error: {e}"})

        elif regex:
            try:
                found = re.findall(regex, body)
                matches = [str(m) for m in found]
            except Exception as e:
                return json.dumps({"error": f"Regex error: {e}"})

        return json.dumps({
            "flow_id": flow_id,
            "extractor": "json_path" if json_path else "css_selector" if css_selector else "regex",
            "expression": json_path or css_selector or regex,
            "matches": matches[:20],
        }, indent=2)

    @mcp.tool()
    async def clear_traffic() -> str:
        """Delete all captured traffic from the database. Use when you want a clean slate before a new test.

        WARNING: This permanently deletes all recorded flows. Session variables are NOT cleared.
        """
        count = traffic_db.clear()
        return json.dumps({"cleared": count, "status": "ok"})

    @mcp.tool()
    async def generate_curl(flow_id: str) -> str:
        """Generate a copy-paste curl command that reproduces a captured HTTP flow.

        PREREQUISITE: Get flow_id from get_traffic_summary or search_traffic.

        Useful for:
        - Exporting requests to share with teammates
        - Testing in terminal outside the MCP environment
        - Importing into Burp Suite or Postman

        Args:
            flow_id: The flow ID to generate a curl command for
        """
        cmd = traffic_db.generate_curl(flow_id)
        if not cmd:
            return json.dumps({"error": f"Flow {flow_id} not found"})
        return json.dumps({"flow_id": flow_id, "curl": cmd}, indent=2)

    # ── Replay & Raw Send ──

    @mcp.tool()
    async def replay_flow(
        flow_id: str,
        replacements: list[dict] = None,
        follow_redirects: bool = True,
    ) -> str:
        """Resend a captured HTTP request with optional modifications (like Burp Repeater).

        PREREQUISITE: Get flow_id from get_traffic_summary or search_traffic.

        Session variable substitution: Any {{varname}} in URL, headers, or body is automatically replaced
        with the value saved by extract_session_variable. Use this for token rotation.

        Regex replacements: Modify parts of the request using regex find-and-replace.
        Example: replacements=[{"regex": "user_id=1", "replacement": "user_id=2"}]

        TYPICAL IDOR WORKFLOW:
        1. search_traffic(query="/api/users/") → get flow_id
        2. extract_session_variable(flow_id, regex="Bearer ([\\w.-]+)", name="jwt")
        3. replay_flow(flow_id, replacements=[{"regex": "/users/1", "replacement": "/users/2"}])

        Args:
            flow_id: The captured flow to replay
            replacements: List of {"regex": "pattern", "replacement": "value"} objects for partial modification
            follow_redirects: Follow HTTP 3xx redirects (default true). Set false to inspect redirect targets.
        """
        import httpx

        flow = traffic_db.get_flow_for_replay(flow_id)
        if not flow:
            return json.dumps({"error": f"Flow {flow_id} not found"})

        # Apply regex replacements to the raw request
        url = flow["url"]
        headers = flow["headers"].copy()
        body = flow["body"]

        # Substitute session variables: {{varname}} → saved value
        session_vars = traffic_db.get_all_session_vars()
        if session_vars:
            for var_name, var_value in session_vars.items():
                placeholder = "{{" + var_name + "}}"
                url = url.replace(placeholder, var_value)
                if body:
                    body = body.replace(placeholder, var_value)
                headers = {k: v.replace(placeholder, var_value) for k, v in headers.items()}

        if replacements:
            for r in replacements:
                pattern = r.get("regex", "")
                repl = r.get("replacement", "")
                url = re.sub(pattern, repl, url)
                body = re.sub(pattern, repl, body) if body else body
                headers = {
                    k: re.sub(pattern, repl, v)
                    for k, v in headers.items()
                }

        # Remove hop-by-hop headers (case-insensitive)
        hop_by_hop = {"host", "content-length", "transfer-encoding"}
        headers = {k: v for k, v in headers.items() if k.lower() not in hop_by_hop}

        start = time.monotonic()
        try:
            async with httpx.AsyncClient(verify=False, follow_redirects=follow_redirects, proxy=_proxy_url()) as client:
                resp = await client.request(
                    method=flow["method"],
                    url=url,
                    headers=headers,
                    content=body.encode() if body else None,
                    timeout=30,
                )
            latency = int((time.monotonic() - start) * 1000)

            resp_body = resp.text
            return json.dumps({
                "status_code": resp.status_code,
                "latency_ms": latency,
                "headers": dict(resp.headers),
                "body": resp_body[:10000],
                "body_truncated": len(resp_body) > 10000,
                "applied_replacements": len(replacements or []),
            }, indent=2)
        except Exception as e:
            return json.dumps({"error": str(e)})

    @mcp.tool()
    async def send_raw_request(
        raw: str,
        host: str = None,
        port: int = None,
        tls: bool = True,
        follow_redirects: bool = True,
        approved: bool = False,
    ) -> str:
        """Send a hand-crafted raw HTTP request (like Burp Repeater's raw editor). No proxy required.

        REQUIRES: approved=true (human must approve sending potentially destructive requests).

        Use this when you need full control over request formatting — multipart uploads,
        unusual headers, HTTP smuggling payloads, etc. For replaying captured traffic, use replay_flow instead.

        Example raw request:
            POST /api/login HTTP/1.1
            Host: target.com
            Content-Type: application/json

            {"username":"admin","password":"test"}

        SECURITY: SSRF protection blocks requests to localhost/private IPs.

        Args:
            raw: Complete raw HTTP request text (request line + headers + blank line + body)
            host: Override the Host header for routing (optional — extracted from Host header if omitted)
            port: Target port (default: 443 for HTTPS, 80 for HTTP)
            tls: Use HTTPS (default true). Set false for plain HTTP targets.
            follow_redirects: Follow HTTP 3xx redirects (default true)
            approved: MUST be true. Set this ONLY after the human user has explicitly approved this action.
        """
        if not approved:
            return json.dumps({"error": "HITL Gateway: Sending raw HTTP requests may include destructive payloads. Obtain explicit user approval, then call again with approved=true."})

        import httpx

        lines = raw.strip().split("\n")
        if not lines:
            return json.dumps({"error": "Empty request"})

        # Parse request line
        first_line = lines[0].strip()
        parts = first_line.split(" ", 2)
        if len(parts) < 2:
            return json.dumps({"error": f"Invalid request line: {first_line}"})

        method = parts[0]
        path = parts[1]

        # Parse headers and body
        headers = {}
        body_start = None
        for i, line in enumerate(lines[1:], 1):
            stripped = line.strip()
            if stripped == "":
                body_start = i + 1
                break
            if ": " in stripped:
                key, value = stripped.split(": ", 1)
                headers[key] = value

        body = "\n".join(lines[body_start:]) if body_start and body_start < len(lines) else None

        # Determine host
        if not host:
            host = headers.get("Host", headers.get("host", ""))
        if not host:
            return json.dumps({"error": "Host is required"})

        # SSRF Protection
        import ipaddress
        clean_host = host.split(":")[0]  # strip port if present
        try:
            ip = ipaddress.ip_address(clean_host)
            if ip.is_loopback or ip.is_private or ip.is_reserved:
                return json.dumps({"error": f"HITL SSRF Blocked: Cannot target private/loopback IP ({clean_host}). Action denied."})
        except ValueError:
            if clean_host.lower() in ("localhost", "127.0.0.1", "::1", "0.0.0.0"):
                return json.dumps({"error": "HITL SSRF Blocked: Cannot target local network host. Action denied."})

        # Build URL
        scheme = "https" if tls else "http"
        actual_port = port or (443 if tls else 80)
        if (tls and actual_port == 443) or (not tls and actual_port == 80):
            url = f"{scheme}://{host}{path}"
        else:
            url = f"{scheme}://{host}:{actual_port}{path}"

        # Remove hop-by-hop (case-insensitive)
        hop_by_hop = {"host", "content-length", "transfer-encoding"}
        headers = {k: v for k, v in headers.items() if k.lower() not in hop_by_hop}

        start = time.monotonic()
        try:
            async with httpx.AsyncClient(verify=False, follow_redirects=follow_redirects, proxy=_proxy_url()) as client:
                resp = await client.request(
                    method=method,
                    url=url,
                    headers=headers,
                    content=body.encode() if body else None,
                    timeout=30,
                )
            latency = int((time.monotonic() - start) * 1000)

            resp_body = resp.text
            return json.dumps({
                "status_code": resp.status_code,
                "latency_ms": latency,
                "headers": dict(resp.headers),
                "body": resp_body[:10000],
                "body_truncated": len(resp_body) > 10000,
            }, indent=2)
        except Exception as e:
            return json.dumps({"error": str(e)})

    # ── Interception Rules ──

    @mcp.tool()
    async def add_interception_rule(
        url_pattern: str,
        action: str,
        resource_type: str = "request",
        key: str = None,
        value: str = None,
        search_pattern: str = None,
        method: str = None,
    ) -> str:
        """Add a rule that modifies HTTP traffic in real-time as it passes through the mitmproxy.

        PREREQUISITE: Proxy must be running (call manage_proxy(action="start") first).

        NOTE: These rules apply to ALL traffic through the proxy (browser + code-mode + replay).
        Rules are cached for ~5 seconds, so changes are not instant.
        For instant browser-only interception, use browser_intercept_request/response instead.

        Available actions:
        - "inject_header": Add/override a header. Requires key and value.
          Example: add_interception_rule(url_pattern=".*api.*", action="inject_header", key="X-Admin", value="true")
        - "replace_body": Find and replace text in the body. Requires search_pattern and value.
          Example: add_interception_rule(url_pattern=".*", action="replace_body", search_pattern="false", value="true", resource_type="response")
        - "block": Block matching requests entirely.
          Example: add_interception_rule(url_pattern=".*analytics.*", action="block")

        Args:
            url_pattern: Regex pattern to match URLs (e.g. ".*api.target.com.*", ".*\\.js$")
            action: "inject_header", "replace_body", or "block"
            resource_type: "request" or "response" (default: "request")
            key: Header name (required for inject_header only)
            value: Header value (for inject_header) or replacement text (for replace_body)
            search_pattern: Regex to find in body (required for replace_body only)
            method: Only match this HTTP method, e.g. "POST" (optional, matches all methods if omitted)
        """
        rule_id = f"r-{uuid.uuid4().hex[:8]}"
        traffic_db.add_rule(
            rule_id,
            url_pattern=url_pattern,
            action_type=action,
            resource_type=resource_type,
            key=key,
            value=value,
            search_pattern=search_pattern,
            method=method,
        )
        return json.dumps({"rule_id": rule_id, "active": True})

    @mcp.tool()
    async def remove_interception_rule(rule_id: str) -> str:
        """Remove a proxy interception rule by its ID.

        PREREQUISITE: Get rule_id from list_interception_rules or the add_interception_rule response.

        Args:
            rule_id: The rule ID to remove (e.g. "r-abc12345")
        """
        removed = traffic_db.remove_rule(rule_id)
        if removed:
            return json.dumps({"status": "removed", "rule_id": rule_id})
        return json.dumps({"error": f"Rule {rule_id} not found"})

    @mcp.tool()
    async def list_interception_rules() -> str:
        """List all active proxy interception rules (added via add_interception_rule).

        NOTE: These are proxy-level rules only. For browser-level CDP Fetch rules,
        use browser_list_intercept_rules instead.
        """
        rules = traffic_db.get_active_rules()
        return json.dumps({"total": len(rules), "rules": rules}, indent=2)

    # ── Session Variables ──

    @mcp.tool()
    async def extract_session_variable(
        flow_id: str,
        regex: str,
        name: str,
        source: str = "response_body",
    ) -> str:
        """Extract a value from a captured flow and save it as a named session variable.

        PREREQUISITE: Get flow_id from get_traffic_summary or search_traffic.

        Saved variables are automatically substituted in replay_flow:
        Any {{varname}} in the URL, headers, or body of a replayed request is replaced with the saved value.

        TYPICAL AUTH WORKFLOW:
        1. search_traffic(query="/login") → find the login response flow_id
        2. extract_session_variable(flow_id, regex='token":"([^"]+)', name="jwt", source="response_body")
        3. replay_flow(another_flow_id) → {{jwt}} in Authorization header is auto-replaced

        Args:
            flow_id: The flow to extract from
            regex: Regex with exactly ONE capture group — the captured group becomes the saved value.
                   Example: 'Bearer ([\\w.-]+)' captures the token part only.
            name: Variable name to save as. Used as {{name}} in replay_flow.
            source: Where to extract from (default: "response_body"):
                - "response_body" — response body text
                - "response_header" — response headers (raw text)
                - "request_header" — request headers (raw text)
                - "request_body" — request body text
        """
        detail = traffic_db.get_detail(flow_id, include=["metadata"])
        if not detail:
            return json.dumps({"error": f"Flow {flow_id} not found"})

        # Use untruncated data for accurate extraction
        raw = traffic_db.get_raw_body(flow_id, source) or ""
        if source in ("response_header", "request_header"):
            # Headers are stored as JSON, already a string
            text = raw
        else:
            text = raw

        match = re.search(regex, text)
        if not match:
            return json.dumps({"error": f"Pattern not found: {regex}"})

        value = match.group(1) if match.lastindex else match.group(0)
        traffic_db.set_session_var(name, value, flow_id)
        return json.dumps({"name": name, "value": value, "source": source})

    @mcp.tool()
    async def list_session_variables() -> str:
        """List all saved session variables. These are used as {{name}} placeholders in replay_flow.

        Variables are created by extract_session_variable. They persist until the proxy is restarted.
        """
        variables = traffic_db.get_all_session_vars()
        return json.dumps({"total": len(variables), "variables": variables}, indent=2)

    # ── Auth Detection ──

    @mcp.tool()
    async def detect_auth_pattern(flow_ids: str = None) -> str:
        """Automatically scan captured traffic to detect authentication mechanisms.

        PREREQUISITE: Proxy must be running and have captured traffic (especially login/API flows).

        Detects: JWT, Bearer tokens, API keys, session cookies, CSRF tokens, Basic auth, OAuth2 endpoints.
        Returns which auth types were found and the flow IDs where they appear.

        Use this early in a pentest to understand the target's auth model before planning attacks.

        Args:
            flow_ids: Optional comma-separated flow IDs to analyze (e.g. "abc123,def456").
                      If omitted, scans the 100 most recent flows automatically.
        """
        if flow_ids:
            ids = [fid.strip() for fid in flow_ids.split(",")]
            flows = []
            for fid in ids:
                detail = traffic_db.get_detail(fid, include=["requestHeaders"])
                if detail:
                    flows.append({
                        "id": detail["id"],
                        "url": detail["url"],
                        "headers": detail.get("request", {}).get("headers", {}),
                    })
        else:
            # Single query instead of N+1
            flows = traffic_db.get_headers_batch(limit=100)

        auth_signals = {
            "jwt": {"detected": False, "signals": [], "flows": []},
            "bearer_token": {"detected": False, "signals": [], "flows": []},
            "api_key": {"detected": False, "signals": [], "flows": []},
            "session_cookie": {"detected": False, "signals": [], "flows": []},
            "csrf": {"detected": False, "signals": [], "flows": []},
            "basic_auth": {"detected": False, "signals": [], "flows": []},
            "oauth2": {"detected": False, "signals": [], "flows": []},
        }

        for f in flows:
            headers = f.get("headers", {})
            fid = f["id"]

            auth_header = headers.get("Authorization", headers.get("authorization", ""))

            if auth_header.startswith("Bearer "):
                token = auth_header[7:]
                auth_signals["bearer_token"]["detected"] = True
                auth_signals["bearer_token"]["flows"].append(fid)
                if token.count(".") == 2:
                    auth_signals["jwt"]["detected"] = True
                    auth_signals["jwt"]["signals"].append("Bearer token is JWT format (3-part dot)")
                    auth_signals["jwt"]["flows"].append(fid)

            if auth_header.startswith("Basic "):
                auth_signals["basic_auth"]["detected"] = True
                auth_signals["basic_auth"]["flows"].append(fid)

            for h, v in headers.items():
                h_lower = h.lower()
                if any(k in h_lower for k in ["x-api-key", "api-key", "apikey", "x-auth-token"]):
                    auth_signals["api_key"]["detected"] = True
                    auth_signals["api_key"]["signals"].append(f"Header: {h}")
                    auth_signals["api_key"]["flows"].append(fid)
                if any(c in h_lower for c in ["csrf", "xsrf", "x-csrf", "x-xsrf"]):
                    auth_signals["csrf"]["detected"] = True
                    auth_signals["csrf"]["signals"].append(f"CSRF header: {h}")
                    auth_signals["csrf"]["flows"].append(fid)

            cookie_header = headers.get("Cookie", headers.get("cookie", ""))
            if cookie_header:
                for cookie in cookie_header.split(";"):
                    c_name = cookie.strip().split("=")[0].lower() if "=" in cookie else ""
                    if any(s in c_name for s in ["session", "sid", "sess", "auth", "phpsessid"]):
                        auth_signals["session_cookie"]["detected"] = True
                        auth_signals["session_cookie"]["signals"].append(f"Cookie: {c_name}")
                        auth_signals["session_cookie"]["flows"].append(fid)

            url_lower = f.get("url", "").lower()
            if any(p in url_lower for p in ["/oauth", "/token", "/authorize", "/auth/callback"]):
                auth_signals["oauth2"]["detected"] = True
                auth_signals["oauth2"]["signals"].append(f"OAuth endpoint: {url_lower}")
                auth_signals["oauth2"]["flows"].append(fid)

        # Deduplicate
        for key in auth_signals:
            auth_signals[key]["flows"] = list(set(auth_signals[key]["flows"]))[:5]
            auth_signals[key]["signals"] = list(set(auth_signals[key]["signals"]))

        detected = [k for k, v in auth_signals.items() if v["detected"]]
        return json.dumps({"detected_auth_types": detected, "details": auth_signals}, indent=2)

    # ── Fuzzing ──

    @mcp.tool()
    async def fuzz_endpoint(
        flow_id: str,
        payloads: list[str],
        target_pattern: str = "FUZZ",
        concurrency: int = 5,
        approved: bool = False,
    ) -> str:
        """Fuzz a captured HTTP request by injecting payloads and detecting anomalies.

        REQUIRES: approved=true (human must approve high-volume fuzzing).
        PREREQUISITE: Get flow_id from a captured request that contains the target_pattern string.

        HOW IT WORKS:
        1. Takes the captured request and replaces target_pattern with each payload
        2. Sends all modified requests (concurrently for speed)
        3. Measures a baseline from the original request
        4. Flags anomalies: unexpected status codes, unusual response lengths, latency spikes, error keywords

        SETUP: Insert "FUZZ" into the target field before capturing:
        - For URL parameter fuzzing: browser_go("https://target.com/api?id=FUZZ")
        - For body fuzzing: use replay_flow with replacements first to insert FUZZ, then fuzz

        Args:
            flow_id: The base flow to fuzz. Its URL/headers/body MUST contain the target_pattern string.
            payloads: List of strings to inject. Example: ["' OR 1=1--", "<script>alert(1)</script>", "../../../etc/passwd"]
            target_pattern: The placeholder string to replace with each payload (default: "FUZZ")
            concurrency: Number of simultaneous requests (default 5). Higher = faster but more aggressive.
            approved: MUST be true. Set this ONLY after the human user has explicitly approved this action.
        """
        if not approved:
            return json.dumps({"error": "HITL Gateway: Fuzzing sends high-volume traffic with potentially destructive payloads to the target server. Obtain explicit user approval, then call again with approved=true."})

        from .fuzzer import run_fuzz

        result = await run_fuzz(
            flow_id=flow_id,
            payloads=payloads,
            target_pattern=target_pattern,
            concurrency=concurrency
        )
        return json.dumps(result, indent=2)
