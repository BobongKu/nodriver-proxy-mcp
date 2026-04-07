"""Browser Daemon — runs nodriver in a separate process with IPC.

Launched as a subprocess by browser_open(). Communicates via TCP JSON-RPC.
Each session gets its own daemon process with independent Chrome instance.
This avoids asyncio event loop conflicts between nodriver and the MCP server.
"""

import asyncio
import json
import sys
import time
import logging
import argparse
from typing import Any

logger = logging.getLogger(__name__)


class BrowserDaemon:
    """Manages a single nodriver browser instance with IPC server."""

    def __init__(self, ipc_port: int, cdp_port: int, headless: bool = True, browser_args: list[str] = None, parent_pid: int = None):
        self.ipc_port = ipc_port
        self.cdp_port = cdp_port
        self.headless = headless
        self.browser_args = browser_args or []
        self.parent_pid = parent_pid
        self.browser = None
        self.tab = None
        self._dialogs: list[dict] = []
        self._console: list[dict] = []
        self._server = None
        self._intercept_rules: list[dict] = []
        self._fetch_enabled: bool = False
        self._extra_headers: dict[str, str] = {}  # For inject_header via Network.setExtraHTTPHeaders

    async def _run_cdp_proxy(self, internal_port: int):
        async def forward(reader, writer):
            try:
                c_reader, c_writer = await asyncio.open_connection("127.0.0.1", internal_port)
                async def pipe(r, w):
                    try:
                        while True:
                            data = await r.read(4096)
                            if not data: break
                            w.write(data)
                            await w.drain()
                    except Exception: pass
                    w.close()
                asyncio.create_task(pipe(reader, c_writer))
                asyncio.create_task(pipe(c_reader, writer))
            except Exception:
                writer.close()

        server = await asyncio.start_server(forward, "127.0.0.1", self.cdp_port)
        logger.info(f"CDP local mapper listening on 127.0.0.1:{self.cdp_port} -> 127.0.0.1:{internal_port}")
        async with server:
            await server.serve_forever()

    async def start(self):
        """Start browser and IPC server."""
        import nodriver

        config = nodriver.Config(headless=self.headless)
        for arg in self.browser_args:
            config.add_argument(arg)

        self.browser = await nodriver.start(config)
        self.tab = self.browser.main_tab
        
        # Map dynamic Chrome port to known CDP port natively
        internal_port = self.browser.config.port
        asyncio.create_task(self._run_cdp_proxy(internal_port))

        # Set up dialog handler
        from nodriver import cdp
        self.tab.add_handler(cdp.page.JavascriptDialogOpening, self._on_dialog)
        # Console handler
        await self.tab.send(cdp.runtime.enable())
        self.tab.add_handler(cdp.runtime.ConsoleAPICalled, self._on_console)

        # Start IPC server
        self._server = await asyncio.start_server(
            self._handle_client, "127.0.0.1", self.ipc_port
        )
        logger.info(f"BrowserDaemon IPC listening on port {self.ipc_port}")

        if self.parent_pid:
            asyncio.create_task(self._health_check())

        async with self._server:
            await self._server.serve_forever()

    async def _health_check(self):
        """Monitor parent process and self-terminate if parent dies.
        Uses platform-specific checks: OpenProcess on Windows, kill(0) on Unix."""
        import os
        while True:
            await asyncio.sleep(2)
            if not self._is_parent_alive():
                logger.warning("Parent process died. Terminating browser daemon.")
                if self.browser:
                    try:
                        self.browser.stop()
                    except Exception:
                        pass
                sys.exit(0)

    def _is_parent_alive(self) -> bool:
        """Check if parent process is still running (cross-platform)."""
        import os
        if sys.platform == "win32":
            import ctypes
            kernel32 = ctypes.windll.kernel32
            SYNCHRONIZE = 0x00100000
            handle = kernel32.OpenProcess(SYNCHRONIZE, False, self.parent_pid)
            if handle:
                kernel32.CloseHandle(handle)
                return True
            return False
        else:
            try:
                os.kill(self.parent_pid, 0)
                return True
            except PermissionError:
                return True  # alive but no permission to signal
            except OSError:
                return False

    # ── CDP Fetch Interception ──

    async def _enable_fetch(self):
        """Enable CDP Fetch domain for real-time request interception.
        Uses Request-stage patterns only; response interception is handled
        per-request via continueRequest(interceptResponse=True)."""
        from nodriver import cdp

        request_patterns = [
            cdp.fetch.RequestPattern(
                url_pattern="*",
                request_stage=cdp.fetch.RequestStage("Request"),
            ),
        ]

        await self.tab.send(cdp.fetch.enable(patterns=request_patterns))
        if not self._fetch_enabled:
            self.tab.add_handler(cdp.fetch.RequestPaused, self._on_request_paused)
        self._fetch_enabled = True
        logger.info("Fetch interception enabled")

    async def _disable_fetch(self):
        """Disable CDP Fetch domain."""
        from nodriver import cdp
        if self._fetch_enabled:
            await self.tab.send(cdp.fetch.disable())
            self._fetch_enabled = False
            self._intercept_rules.clear()
            logger.info("Fetch interception disabled")

    async def _on_request_paused(self, event):
        """Handle paused requests — apply intercept rules or continue.

        Architecture:
          - inject_header: handled via Network.setExtraHTTPHeaders (not here)
          - block: fail_request at request stage
          - modify_url: continue_request(url=...) at request stage
          - replace_body: request stage -> continueRequest(interceptResponse=True),
                          response stage -> modify body with fulfillRequest
        """
        import re
        import base64
        from nodriver import cdp

        request_url = event.request.url
        is_response_stage = event.response_status_code is not None

        # Find matching rule (skip inject_header — handled separately)
        matched_rule = None
        for rule in self._intercept_rules:
            if rule.get("action") == "inject_header":
                continue
            if rule.get("stage") == "response" and not is_response_stage:
                continue
            if rule.get("stage") == "request" and is_response_stage:
                continue
            try:
                if re.search(rule["url_pattern"], request_url):
                    matched_rule = rule
                    break
            except re.error:
                continue

        try:
            if not matched_rule:
                # No match — check if any response rules need interceptResponse
                if not is_response_stage:
                    needs_response = False
                    for r in self._intercept_rules:
                        if r.get("action") == "inject_header" or r.get("stage") != "response":
                            continue
                        try:
                            if re.search(r["url_pattern"], request_url):
                                needs_response = True
                                break
                        except re.error:
                            continue
                    await self.tab.send(cdp.fetch.continue_request(
                        request_id=event.request_id,
                        intercept_response=needs_response or None,
                    ))
                else:
                    await self.tab.send(cdp.fetch.continue_response(
                        request_id=event.request_id,
                    ))
                return

            action = matched_rule["action"]

            if action == "block":
                await self.tab.send(cdp.fetch.fail_request(
                    request_id=event.request_id,
                    error_reason=cdp.network.ErrorReason("BlockedByClient"),
                ))

            elif action == "modify_url" and not is_response_stage:
                new_url = matched_rule.get("value", request_url)
                await self.tab.send(cdp.fetch.continue_request(
                    request_id=event.request_id,
                    url=new_url,
                ))

            elif action == "replace_body":
                if not is_response_stage:
                    # Request stage: continue and request response interception
                    await self.tab.send(cdp.fetch.continue_request(
                        request_id=event.request_id,
                        intercept_response=True,
                    ))
                else:
                    # Response stage: get body, modify, fulfill
                    resp = await self.tab.send(cdp.fetch.get_response_body(
                        request_id=event.request_id,
                    ))
                    body_text = resp[0] if resp else ""
                    if resp and resp[1]:  # base64 encoded
                        body_text = base64.b64decode(body_text).decode("utf-8", errors="replace")

                    search = matched_rule.get("search_pattern", "")
                    replacement = matched_rule.get("value", "")
                    if search:
                        body_text = re.sub(search, replacement, body_text)

                    encoded_body = base64.b64encode(body_text.encode("utf-8")).decode("ascii")
                    await self.tab.send(cdp.fetch.fulfill_request(
                        request_id=event.request_id,
                        response_code=event.response_status_code or 200,
                        body=encoded_body,
                    ))

            else:
                if is_response_stage:
                    await self.tab.send(cdp.fetch.continue_response(request_id=event.request_id))
                else:
                    await self.tab.send(cdp.fetch.continue_request(request_id=event.request_id))

        except Exception as e:
            logger.error(f"Fetch intercept error: {e}")
            try:
                if is_response_stage:
                    await self.tab.send(cdp.fetch.continue_response(request_id=event.request_id))
                else:
                    await self.tab.send(cdp.fetch.continue_request(request_id=event.request_id))
            except Exception:
                pass

    async def _on_dialog(self, event):
        """Capture JavaScript dialogs (alert/confirm/prompt)."""
        self._dialogs.append({
            "type": event.type_.value if hasattr(event.type_, 'value') else str(event.type_),
            "message": event.message,
            "url": event.url if hasattr(event, 'url') else "",
            "timestamp": time.time(),
        })
        # Auto-dismiss to prevent blocking
        from nodriver import cdp
        await self.tab.send(cdp.page.handle_javascript_dialog(accept=True))

    async def _on_console(self, event):
        """Capture console messages."""
        try:
            args_text = " ".join(
                str(a.value) if hasattr(a, 'value') and a.value is not None
                else str(a.description) if hasattr(a, 'description') and a.description
                else ""
                for a in (event.args or [])
            )
            self._console.append({
                "level": event.type_.value if hasattr(event.type_, 'value') else str(event.type_),
                "text": args_text[:500],
                "timestamp": event.timestamp,
            })
        except Exception:
            pass

    def _drain_events(self) -> dict:
        """Get and clear accumulated dialog events. Console is NOT cleared here
        so that get_console can read the full buffer independently."""
        dialogs = self._dialogs.copy()
        console_errors = [e for e in self._console if e.get("level") in ("error", "warning")]
        self._dialogs.clear()
        # NOTE: Do NOT clear self._console here. get_console manages its own clearing.
        return {
            "current_url": self.tab.url if self.tab else "",
            "dialogs": dialogs,
            "console_errors": console_errors[-10:],  # Last 10
        }

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Handle one IPC request."""
        try:
            data = await asyncio.wait_for(reader.readline(), timeout=120)
            if not data:
                return

            request = json.loads(data.decode())
            method = request.get("method", "")
            params = request.get("params", {})
            req_id = request.get("id", 0)

            result = await self._dispatch(method, params)
            response = {"result": result, "id": req_id}
        except Exception as e:
            req_id = request.get("id", 0) if 'request' in locals() else 0
            response = {"error": str(e), "id": req_id}

        writer.write((json.dumps(response) + "\n").encode())
        await writer.drain()
        writer.close()

    def _get_tab(self, tab_id: str = None):
        if not tab_id:
            return self.browser.main_tab
            
        target_tab = None
        for t in self.browser.tabs:
            if getattr(t.target, 'target_id', getattr(t.target, 'id', '')) == tab_id:
                target_tab = t
                break
                
        if not target_tab:
            raise ValueError(f"Tab ID {tab_id} not found")
            
        if not getattr(target_tab, "_handlers_attached", False):
            from nodriver import cdp
            try:
                target_tab.add_handler(cdp.page.JavascriptDialogOpening, self._on_dialog)
                import asyncio
                asyncio.create_task(target_tab.send(cdp.runtime.enable()))
                target_tab.add_handler(cdp.runtime.ConsoleAPICalled, self._on_console)
            except Exception:
                pass
            target_tab._handlers_attached = True
            
        return target_tab

    async def _dispatch(self, method: str, params: dict) -> dict:
        """Dispatch IPC method to handler."""
        if method == "list_tabs":
            tabs = []
            for t in self.browser.tabs:
                tabs.append({
                    "tab_id": getattr(t.target, 'target_id', getattr(t.target, 'id', '')),
                    "url": t.target.url if hasattr(t.target, 'url') else "",
                    "title": t.target.title if hasattr(t.target, 'title') else ""
                })
            return {"result": {"tabs": tabs}}

        self.tab = self._get_tab(params.get("tab_id"))
        events = self._drain_events()

        if method == "go":
            url = params["url"]
            await self.tab.get(url)
            if params.get("wait_for"):
                try:
                    await self.tab.select(params["wait_for"], timeout=params.get("timeout", 10))
                except Exception:
                    pass
            await self.tab
            events = self._drain_events()
            return {
                "result": {
                    "status": "loaded",
                    "final_url": self.tab.url,
                    "title": await self._get_title(),
                },
                **events,
            }

        elif method == "back":
            await self.tab.back()
            await self.tab
            events = self._drain_events()
            return {"result": {"status": "ok"}, **events}

        elif method == "click":
            selector = params.get("selector")
            text = params.get("text")
            if selector:
                elem = await self.tab.select(selector, timeout=5)
            elif text:
                elem = await self.tab.find(text, best_match=True, timeout=5)
            else:
                return {"result": {"error": "selector or text required"}, **events}

            if not elem:
                return {"result": {"error": f"Element not found: {selector or text}"}, **events}

            await elem.click()
            await self.tab.sleep(0.5)
            events = self._drain_events()
            return {"result": {"clicked": True, "element": str(elem.tag_name or "")}, **events}

        elif method == "type":
            elem = await self.tab.select(params["selector"], timeout=5)
            if not elem:
                return {"result": {"error": f"Element not found: {params['selector']}"}, **events}
            if params.get("clear", True):
                await elem.clear_input()
            await elem.send_keys(params["text"])
            if params.get("press_enter"):
                await elem.send_keys("\n")
            return {"result": {"typed": True}, **events}

        elif method == "js":
            from nodriver import cdp
            result, exc = await self.tab.send(
                cdp.runtime.evaluate(expression=params["expression"], return_by_value=True)
            )
            value = None
            if result:
                value = result.value if hasattr(result, 'value') else str(result)
            return {"result": {"value": value, "type": str(result.type_) if result else None}, **events}

        elif method == "get_dom":
            dom_info = await self._extract_dom(
                params.get("selector", "body"),
                params.get("max_depth", 4),
            )
            return {"result": dom_info, **events}

        elif method == "get_text":
            elem = await self.tab.select(params["selector"], timeout=5)
            text = elem.text_all if elem else ""
            return {"result": {"selector": params["selector"], "text": text[:2000]}, **events}

        elif method == "get_storage":
            from nodriver import cdp
            st = params.get("storage_type", "both")
            result = {}
            if st in ("local", "both"):
                r, _ = await self.tab.send(cdp.runtime.evaluate(
                    expression="JSON.stringify(Object.fromEntries(Object.entries(localStorage)))",
                    return_by_value=True,
                ))
                result["localStorage"] = json.loads(r.value) if r and r.value else {}
            if st in ("session", "both"):
                r, _ = await self.tab.send(cdp.runtime.evaluate(
                    expression="JSON.stringify(Object.fromEntries(Object.entries(sessionStorage)))",
                    return_by_value=True,
                ))
                result["sessionStorage"] = json.loads(r.value) if r and r.value else {}
            return {"result": result, **events}

        elif method == "get_console":
            level = params.get("level", "all")
            entries = self._console.copy()
            if level != "all":
                entries = [e for e in entries if e.get("level") == level]
            if params.get("clear", False):
                self._console.clear()
            return {"result": {"entries": entries[-50:], "total": len(entries)}, **events}

        elif method == "screenshot":
            from nodriver import cdp
            data = await self.tab.send(cdp.page.capture_screenshot(format_="png"))
            import base64
            # Save to file
            import tempfile, os
            path = os.path.join(tempfile.gettempdir(), f"screenshot_{int(time.time())}.png")
            with open(path, "wb") as f:
                f.write(base64.b64decode(data))
            return {"result": {"path": path}, **events}

        elif method == "set_cookie":
            from nodriver import cdp
            from urllib.parse import urlparse
            domain = params.get("domain")
            if not domain and self.tab.url:
                parsed = urlparse(self.tab.url)
                domain = parsed.hostname or ""
            await self.tab.send(cdp.network.set_cookie(
                name=params["name"],
                value=params["value"],
                domain=domain,
                path=params.get("path", "/"),
                http_only=params.get("http_only", False),
                secure=params.get("secure", False),
            ))
            return {"result": {"set": True, "name": params["name"]}, **events}

        elif method == "wait":
            selector = params.get("selector")
            text = params.get("text")
            timeout = params.get("timeout", 10)
            start = time.time()
            found = False
            try:
                if selector:
                    elem = await self.tab.select(selector, timeout=timeout)
                    found = elem is not None
                elif text:
                    elem = await self.tab.find(text, best_match=True, timeout=timeout)
                    found = elem is not None
            except Exception:
                pass
            waited_ms = int((time.time() - start) * 1000)
            return {"result": {"found": found, "waited_ms": waited_ms}, **events}

        elif method == "ping":
            return {"result": {"status": "alive", "url": self.tab.url if self.tab else ""}, **events}

        elif method == "close":
            if self.browser:
                self.browser.stop()
            return {"result": {"status": "closed"}, **events}

        # ── Fetch Interception IPC Methods ──

        elif method == "enable_intercept":
            await self._enable_fetch()
            return {"result": {"status": "enabled"}, **events}

        elif method == "disable_intercept":
            await self._disable_fetch()
            # Also clear extra headers
            if self._extra_headers:
                self._extra_headers.clear()
                from nodriver import cdp
                await self.tab.send(cdp.network.set_extra_http_headers(
                    headers=cdp.network.Headers({}),
                ))
            return {"result": {"status": "disabled", "rules_cleared": True}, **events}

        elif method == "add_intercept_rule":
            from nodriver import cdp
            rule = {
                "id": params.get("rule_id", f"cdp-{int(time.time()*1000)}"),
                "url_pattern": params["url_pattern"],
                "action": params["action"],
                "stage": params.get("stage", "request"),
                "key": params.get("key"),
                "value": params.get("value"),
                "search_pattern": params.get("search_pattern"),
            }
            self._intercept_rules.append(rule)

            if rule["action"] == "inject_header":
                # Use Network.setExtraHTTPHeaders — works with proxies
                # Network domain must be enabled first
                if not self._extra_headers:
                    await self.tab.send(cdp.network.enable())
                self._extra_headers[rule["key"]] = rule["value"]
                await self.tab.send(cdp.network.set_extra_http_headers(
                    headers=cdp.network.Headers(self._extra_headers),
                ))
            else:
                # Enable Fetch for block/modify_url/replace_body
                if not self._fetch_enabled:
                    await self._enable_fetch()
            return {"result": {"status": "added", "rule": rule}, **events}

        elif method == "remove_intercept_rule":
            from nodriver import cdp
            rule_id = params.get("rule_id")
            removed_rules = [r for r in self._intercept_rules if r["id"] == rule_id]
            self._intercept_rules = [r for r in self._intercept_rules if r["id"] != rule_id]
            removed = len(removed_rules)
            # Update extra headers if an inject_header rule was removed
            if removed and removed_rules[0].get("action") == "inject_header":
                self._extra_headers = {
                    r["key"]: r["value"]
                    for r in self._intercept_rules
                    if r.get("action") == "inject_header"
                }
                await self.tab.send(cdp.network.set_extra_http_headers(
                    headers=cdp.network.Headers(self._extra_headers),
                ))
            return {"result": {"status": "removed" if removed else "not_found", "rule_id": rule_id}, **events}

        elif method == "list_intercept_rules":
            return {"result": {
                "enabled": self._fetch_enabled,
                "total": len(self._intercept_rules),
                "rules": self._intercept_rules,
            }, **events}

        else:
            return {"result": {"error": f"Unknown method: {method}"}, **events}

    async def _get_title(self) -> str:
        try:
            from nodriver import cdp
            result, _ = await self.tab.send(cdp.runtime.evaluate(
                expression="document.title", return_by_value=True
            ))
            return result.value if result else ""
        except Exception:
            return ""

    async def _extract_dom(self, selector: str, max_depth: int) -> dict:
        """Extract security-relevant DOM information."""
        from nodriver import cdp

        result = {
            "url": self.tab.url,
            "title": await self._get_title(),
            "forms": [],
            "links": [],
            "scripts": [],
            "iframes": [],
            "meta_tags": [],
            "comments": [],
            "noscript": [],
            "inputs_outside_forms": [],
            "event_handlers": [],
            "data_attributes": [],
            "dom_tree": "",
        }

        # Extract forms (with CSRF detection, file upload detection)
        forms_js = """
        Array.from(document.forms).map(f => ({
            action: f.action, method: f.method, id: f.id,
            inputs: Array.from(f.elements).filter(e => e.tagName !== 'FIELDSET').map(e => ({
                name: e.name, type: e.type, id: e.id,
                value: e.type === 'hidden' ? e.value : undefined
            })),
            has_csrf: Array.from(f.elements).some(e =>
                e.type === 'hidden' && /csrf|xsrf|token|nonce/i.test(e.name)),
            has_file_upload: Array.from(f.elements).some(e => e.type === 'file')
        }))
        """
        r, _ = await self.tab.send(cdp.runtime.evaluate(
            expression=f"JSON.stringify({forms_js})", return_by_value=True
        ))
        if r and r.value:
            result["forms"] = json.loads(r.value)

        # Extract links (increased limit: 200)
        links_js = """
        Array.from(document.querySelectorAll('a[href]')).slice(0, 200).map(a => ({
            href: a.getAttribute('href'), text: a.textContent.trim().substring(0, 80),
            target: a.target || null
        }))
        """
        r, _ = await self.tab.send(cdp.runtime.evaluate(
            expression=f"JSON.stringify({links_js})", return_by_value=True
        ))
        if r and r.value:
            result["links"] = json.loads(r.value)

        # Extract scripts (inline preview: 500 chars)
        scripts_js = """
        Array.from(document.querySelectorAll('script')).map(s => ({
            src: s.src || null,
            inline: !s.src,
            preview: !s.src ? s.textContent.substring(0, 500) : undefined
        }))
        """
        r, _ = await self.tab.send(cdp.runtime.evaluate(
            expression=f"JSON.stringify({scripts_js})", return_by_value=True
        ))
        if r and r.value:
            result["scripts"] = json.loads(r.value)

        # Extract iframes
        iframes_js = "Array.from(document.querySelectorAll('iframe')).map(f => ({src: f.src, sandbox: f.sandbox?.value || null}))"
        r, _ = await self.tab.send(cdp.runtime.evaluate(
            expression=f"JSON.stringify({iframes_js})", return_by_value=True
        ))
        if r and r.value:
            result["iframes"] = json.loads(r.value)

        # Extract meta tags (CSP, CSRF, API keys, etc.)
        meta_js = """
        Array.from(document.querySelectorAll('meta')).map(m => ({
            name: m.name || null,
            property: m.getAttribute('property') || null,
            httpEquiv: m.httpEquiv || null,
            content: m.content || null
        })).filter(m => m.name || m.property || m.httpEquiv)
        """
        r, _ = await self.tab.send(cdp.runtime.evaluate(
            expression=f"JSON.stringify({meta_js})", return_by_value=True
        ))
        if r and r.value:
            result["meta_tags"] = json.loads(r.value)

        # Extract HTML comments (developer leaks, TODOs, debug info)
        comments_js = """
        (() => {
            const comments = [];
            const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_COMMENT);
            while (walker.nextNode()) {
                const text = walker.currentNode.textContent.trim();
                if (text.length > 0) comments.push(text.substring(0, 300));
            }
            return comments.slice(0, 30);
        })()
        """
        r, _ = await self.tab.send(cdp.runtime.evaluate(
            expression=f"JSON.stringify({comments_js})", return_by_value=True
        ))
        if r and r.value:
            result["comments"] = json.loads(r.value)

        # Extract <noscript> content
        noscript_js = """
        Array.from(document.querySelectorAll('noscript')).map(n => n.innerHTML.substring(0, 300))
        """
        r, _ = await self.tab.send(cdp.runtime.evaluate(
            expression=f"JSON.stringify({noscript_js})", return_by_value=True
        ))
        if r and r.value:
            result["noscript"] = json.loads(r.value)

        # Extract inline event handlers (onclick, onsubmit, onerror, etc.)
        handlers_js = """
        (() => {
            const attrs = ['onclick','onsubmit','onerror','onload','onfocus','onblur',
                           'onmouseover','onchange','oninput','onkeyup','onkeydown'];
            const found = [];
            document.querySelectorAll('*').forEach(el => {
                attrs.forEach(a => {
                    const val = el.getAttribute(a);
                    if (val) found.push({
                        tag: el.tagName.toLowerCase(),
                        id: el.id || null,
                        event: a,
                        handler: val.substring(0, 200)
                    });
                });
            });
            return found.slice(0, 50);
        })()
        """
        r, _ = await self.tab.send(cdp.runtime.evaluate(
            expression=f"JSON.stringify({handlers_js})", return_by_value=True
        ))
        if r and r.value:
            result["event_handlers"] = json.loads(r.value)

        # Extract data-* attributes (often contain user IDs, API URLs, config)
        data_attrs_js = """
        (() => {
            const found = [];
            document.querySelectorAll('[data-api-url],[data-user-id],[data-token],[data-endpoint],[data-config],[data-id],[data-role],[data-url]').forEach(el => {
                const attrs = {};
                for (const attr of el.attributes) {
                    if (attr.name.startsWith('data-'))
                        attrs[attr.name] = attr.value.substring(0, 200);
                }
                if (Object.keys(attrs).length > 0) {
                    found.push({tag: el.tagName.toLowerCase(), id: el.id || null, ...attrs});
                }
            });
            // Also grab ALL data-* from elements with many data attributes
            document.querySelectorAll('*').forEach(el => {
                const dataAttrs = {};
                for (const attr of el.attributes) {
                    if (attr.name.startsWith('data-') && /api|url|token|key|id|user|role|config|secret|auth/i.test(attr.name))
                        dataAttrs[attr.name] = attr.value.substring(0, 200);
                }
                if (Object.keys(dataAttrs).length > 0) {
                    found.push({tag: el.tagName.toLowerCase(), id: el.id || null, ...dataAttrs});
                }
            });
            // Deduplicate
            const seen = new Set();
            return found.filter(f => {
                const key = JSON.stringify(f);
                if (seen.has(key)) return false;
                seen.add(key); return true;
            }).slice(0, 50);
        })()
        """
        r, _ = await self.tab.send(cdp.runtime.evaluate(
            expression=f"JSON.stringify({data_attrs_js})", return_by_value=True
        ))
        if r and r.value:
            result["data_attributes"] = json.loads(r.value)

        # Inputs outside forms
        inputs_js = """
        Array.from(document.querySelectorAll('input:not(form input), textarea:not(form textarea), select:not(form select)'))
            .slice(0, 30).map(e => ({
                tag: e.tagName.toLowerCase(), name: e.name, type: e.type, id: e.id,
                value: e.type === 'hidden' ? e.value : undefined
            }))
        """
        r, _ = await self.tab.send(cdp.runtime.evaluate(
            expression=f"JSON.stringify({inputs_js})", return_by_value=True
        ))
        if r and r.value:
            result["inputs_outside_forms"] = json.loads(r.value)

        # Simplified DOM tree (increased limit: 8000 chars)
        tree_js = f"""
        (function simplify(el, depth) {{
            if (depth > {max_depth}) return '...';
            let tag = el.tagName.toLowerCase();
            let id = el.id ? '#' + el.id : '';
            let cls = el.className && typeof el.className === 'string' ?
                '.' + el.className.split(' ').filter(Boolean).join('.') : '';
            let attrs = '';
            if (el.type) attrs += ' type="' + el.type + '"';
            if (el.name) attrs += ' name="' + el.name + '"';
            if (el.href) attrs += ' href="' + el.getAttribute('href') + '"';
            if (el.action) attrs += ' action="' + el.action + '"';
            if (el.method) attrs += ' method="' + el.method + '"';
            let line = '<' + tag + id + cls + attrs + '>';
            let children = Array.from(el.children);
            if (children.length === 0) {{
                let text = el.textContent.trim().substring(0, 60);
                if (text) line += ' "' + text + '"';
            }}
            return line + '\\n' + children.map(c => '  '.repeat(depth+1) + simplify(c, depth+1)).join('');
        }})(document.querySelector('{selector}') || document.body, 0)
        """
        r, _ = await self.tab.send(cdp.runtime.evaluate(
            expression=tree_js, return_by_value=True
        ))
        if r and r.value:
            result["dom_tree"] = r.value[:8000]

        return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--ipc-port", type=int, required=True)
    parser.add_argument("--cdp-port", type=int, required=True)
    parser.add_argument("--headless", type=str, default="true")
    parser.add_argument("--browser-args", type=str, default="[]")
    parser.add_argument("--parent-pid", type=int, default=None)
    args = parser.parse_args()

    headless = args.headless.lower() == "true"
    browser_args = json.loads(args.browser_args)

    daemon = BrowserDaemon(
        ipc_port=args.ipc_port,
        cdp_port=args.cdp_port,
        headless=headless,
        browser_args=browser_args,
        parent_pid=args.parent_pid,
    )

    # Register shutdown handler to ensure Chrome is killed on daemon terminate
    import signal as _signal
    import atexit

    def _shutdown_browser(*_args):
        if daemon.browser:
            try:
                daemon.browser.stop()
            except Exception:
                pass
        sys.exit(0)

    atexit.register(_shutdown_browser)
    if sys.platform != "win32":
        _signal.signal(_signal.SIGTERM, _shutdown_browser)

    asyncio.run(daemon.start())


if __name__ == "__main__":
    main()
