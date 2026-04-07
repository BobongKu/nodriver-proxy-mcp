"""Mitmproxy addon script — loaded by mitmdump via -s flag.

Records all in-scope traffic to the SQLite TrafficDB.
Applies active interception rules (header injection, body replace, block).
"""

import json
import time
import sys
import os

# Add parent package to path so we can import recorder/scope
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from nodriver_proxy_mcp.proxy.recorder import traffic_db
from nodriver_proxy_mcp.proxy.scope import scope_manager


def _safe_decode(content: bytes | None, max_len: int = 0) -> str | None:
    if content is None:
        return None
    try:
        text = content.decode("utf-8", errors="replace")
    except Exception:
        return "<binary data>"
    if max_len and len(text) > max_len:
        return text[:max_len]
    return text


class TrafficRecorderAddon:
    """Mitmproxy addon that records flows to SQLite and applies rules."""

    def __init__(self):
        self._request_times: dict[str, float] = {}
        self._rules_cache: list[dict] = []
        self._rules_ts: float = 0
        self._rules_ttl: float = 5.0  # refresh rules every 5s

    def request(self, flow):
        """Called when a request is received."""
        url = flow.request.url
        method = flow.request.method

        if not scope_manager.is_allowed(url, method):
            return

        # Record request start time for latency calculation
        self._request_times[flow.id] = time.time()

        # Apply interception rules
        self._apply_rules(flow, "request")

        # Save request (response not available yet)
        headers = dict(flow.request.headers)
        body = _safe_decode(flow.request.content)

        traffic_db.save_flow(
            flow_id=flow.id,
            url=url,
            method=method,
            status_code=None,
            request_headers=headers,
            request_body=body,
            response_headers=None,
            response_body=None,
            latency_ms=None,
            size=0,
            timestamp=time.time(),
        )

    def response(self, flow):
        """Called when a response is received."""
        url = flow.request.url
        method = flow.request.method

        if not scope_manager.is_allowed(url, method):
            return

        # Apply interception rules
        self._apply_rules(flow, "response")

        # Calculate latency
        start = self._request_times.pop(flow.id, None)
        latency_ms = int((time.time() - start) * 1000) if start else None

        # Save complete flow
        req_headers = dict(flow.request.headers)
        req_body = _safe_decode(flow.request.content, max_len=100000)
        resp_headers = dict(flow.response.headers) if flow.response else None
        size = len(flow.response.content) if flow.response and flow.response.content else 0

        # Skip binary response bodies to prevent DB bloat
        resp_body = None
        if flow.response and flow.response.content:
            ct = flow.response.headers.get("content-type", "").lower()
            is_binary = any(t in ct for t in [
                "image/", "audio/", "video/", "font/",
                "application/octet-stream", "application/zip",
                "application/gzip", "application/pdf",
                "application/wasm",
            ])
            if not is_binary:
                resp_body = _safe_decode(flow.response.content, max_len=100000)

        traffic_db.save_flow(
            flow_id=flow.id,
            url=url,
            method=method,
            status_code=flow.response.status_code if flow.response else None,
            request_headers=req_headers,
            request_body=req_body,
            response_headers=resp_headers,
            response_body=resp_body,
            latency_ms=latency_ms,
            size=size,
        )

    def _apply_rules(self, flow, resource_type: str):
        """Apply active interception rules to the flow (cached)."""
        import re

        now = time.time()
        if now - self._rules_ts > self._rules_ttl:
            self._rules_cache = traffic_db.get_active_rules()
            self._rules_ts = now

        for rule in self._rules_cache:
            if rule["resource_type"] != resource_type:
                continue
            if rule["url_pattern"] and not re.search(rule["url_pattern"], flow.request.url):
                continue
            if rule["method"] and flow.request.method.upper() != rule["method"].upper():
                continue

            action = rule["action_type"]

            if action == "inject_header":
                if resource_type == "request":
                    flow.request.headers[rule["key"]] = rule["value"]
                elif resource_type == "response" and flow.response:
                    flow.response.headers[rule["key"]] = rule["value"]

            elif action == "replace_body":
                if resource_type == "request" and flow.request.content:
                    text = flow.request.content.decode("utf-8", errors="replace")
                    text = re.sub(rule["search_pattern"], rule["value"], text)
                    flow.request.content = text.encode("utf-8")
                elif resource_type == "response" and flow.response and flow.response.content:
                    text = flow.response.content.decode("utf-8", errors="replace")
                    text = re.sub(rule["search_pattern"], rule["value"], text)
                    flow.response.content = text.encode("utf-8")

            elif action == "block":
                from mitmproxy import http
                flow.response = http.Response.make(
                    403,
                    b"Blocked by interception rule",
                    {"Content-Type": "text/plain"},
                )


addons = [TrafficRecorderAddon()]
