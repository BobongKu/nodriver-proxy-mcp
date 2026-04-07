"""Browser MCP tools — 20 tools for browser automation and security testing.

All tools use the SessionManager to communicate with BrowserDaemon processes.
"""

import json
import logging

from ..browser.session_manager import session_manager

logger = logging.getLogger(__name__)


def register_browser_tools(mcp):
    """Register all 20 browser tools with the FastMCP server."""

    # ── Session Management ──

    @mcp.tool()
    async def browser_open(
        session_name: str = "default",
        proxy_port: int = 8082,
        headless: bool = True,
    ) -> str:
        """Launch a new Chrome browser session with anti-bot bypass (nodriver CDP). Call this BEFORE any other browser_* tool.

        TYPICAL STARTUP SEQUENCE:
        1. manage_proxy(action="start") — start the proxy first
        2. browser_open(proxy_port=8082) — launch Chrome routed through proxy
        3. browser_go(url="https://target.com") — navigate

        Each session is an independent Chrome instance. You can run multiple sessions simultaneously
        for multi-user testing (e.g. "victim" and "attacker" sessions for IDOR/privilege escalation).

        The browser uses nodriver which bypasses Cloudflare, DataDome, and other bot detection automatically.

        Args:
            session_name: Unique name for this session (default: "default"). Use different names for multiple sessions.
            proxy_port: Route all browser traffic through mitmproxy on this port (default 8082).
                        Must match the port used in manage_proxy. Set to 0 to disable proxy routing.
            headless: Run Chrome without a visible window (default true). Set false for visual debugging.
        """
        result = session_manager.open(
            session_name=session_name,
            proxy_port=proxy_port,
            headless=headless,
        )
        return json.dumps(result, indent=2)

    @mcp.tool()
    async def browser_close(session_name: str = "default") -> str:
        """Close a browser session and terminate the Chrome process.

        Call this when you're done with a browser session to free resources.
        If session_name is omitted, closes the "default" session.

        Args:
            session_name: Session to close (default: "default")
        """
        result = session_manager.close(session_name)
        return json.dumps(result, indent=2)

    @mcp.tool()
    async def browser_list_sessions() -> str:
        """List all active browser sessions with their status, PID, ports, and uptime.

        Use this to check which sessions are running before sending commands.
        Dead sessions are automatically cleaned up.
        """
        sessions = session_manager.list_sessions()
        return json.dumps({"sessions": sessions}, indent=2)


    @mcp.tool()
    async def browser_list_tabs(session_name: str = "default") -> str:
        """List all open tabs in a browser session with their tab IDs and URLs.

        PREREQUISITE: browser_open must have been called first.

        Use tab_id from the results to target specific tabs in other browser_* tools.

        Args:
            session_name: Browser session to query (default: "default")
        """
        result = await session_manager.send(session_name, "list_tabs")
        return json.dumps(result, indent=2)

    # ── Navigation ──

    @mcp.tool()
    async def browser_go(
        url: str,
        session_name: str = "default",
        tab_id: str = None,
        wait_for: str = None,
    ) -> str:
        """Navigate to a URL and wait for the page to load. Returns the page title and any JS dialog messages.

        PREREQUISITE: browser_open must have been called first.

        For Single Page Applications (SPAs) that load content dynamically after initial page load,
        use wait_for to specify a CSS selector that indicates the content is ready.

        Args:
            url: Full URL to navigate to (e.g. "https://target.com/login")
            session_name: Browser session to use (default: "default")
            tab_id: Target a specific tab (optional — uses active tab if omitted)
            wait_for: CSS selector to wait for after navigation (e.g. "#main-content", ".login-form"). Use for SPAs.
        """
        result = await session_manager.send(session_name, "go", {
            "tab_id": tab_id,
            "url": url,
            "wait_for": wait_for,
        })
        return json.dumps(result, indent=2)

    @mcp.tool()
    async def browser_back(session_name: str = "default", tab_id: str = None) -> str:
        """Navigate back in browser history (like clicking the Back button).

        PREREQUISITE: browser_open and browser_go must have been called first.

        Args:
            session_name: Browser session to use (default: "default")
        """
        result = await session_manager.send(session_name, "back", {"tab_id": tab_id})
        return json.dumps(result, indent=2)

    # ── Page State (client-side only — things proxy can't see) ──

    @mcp.tool()
    async def browser_get_dom(
        selector: str = "body",
        max_depth: int = 4,
        session_name: str = "default",
        tab_id: str = None,
    ) -> str:
        """Extract security-relevant DOM structure from the current page. Returns data the PROXY CANNOT SEE.

        PREREQUISITE: browser_open and browser_go must have been called first.

        Automatically extracts:
        - Forms: action URLs, methods, input fields, hidden inputs, CSRF tokens
        - Links: all <a> href values
        - Scripts: <script> src attributes (for finding JS endpoints)
        - Iframes: embedded frame sources
        - HTML comments: developers often leave sensitive info in comments
        - Event handlers: onclick, onsubmit, etc. (for client-side logic)
        - data-* attributes: often contain API endpoints or config values
        - Simplified DOM tree (depth-limited)

        Use this for initial recon after navigating to a page.

        Args:
            selector: Root element CSS selector to analyze (default: "body" = entire page)
            max_depth: How deep to traverse the DOM tree (default: 4). Higher = more detail but more tokens.
            session_name: Browser session to use (default: "default")
        """
        result = await session_manager.send(session_name, "get_dom", {
            "tab_id": tab_id,
            "selector": selector,
            "max_depth": max_depth,
        })
        return json.dumps(result, indent=2)

    @mcp.tool()
    async def browser_get_text(
        selector: str,
        session_name: str = "default",
        tab_id: str = None,
    ) -> str:
        """Get the visible text content of a specific DOM element.

        PREREQUISITE: browser_open and browser_go must have been called first.

        Use this to read specific parts of a page (error messages, user info, API responses rendered in HTML).
        For full DOM analysis, use browser_get_dom instead.

        Args:
            selector: CSS selector for the element (e.g. "#error-message", ".user-name", "h1")
            session_name: Browser session to use (default: "default")
        """
        result = await session_manager.send(session_name, "get_text", {
            "tab_id": tab_id,
            "selector": selector,
        })
        return json.dumps(result, indent=2)

    @mcp.tool()
    async def browser_get_storage(
        storage_type: str = "both",
        session_name: str = "default",
        tab_id: str = None,
    ) -> str:
        """Dump browser localStorage and/or sessionStorage contents. Returns data the PROXY CANNOT SEE.

        PREREQUISITE: browser_open and browser_go must have been called first.

        Web apps often store JWT tokens, API keys, user preferences, or feature flags in browser storage.
        This data never appears in HTTP traffic — it's only accessible client-side.

        Args:
            storage_type: What to read — "local" (localStorage only), "session" (sessionStorage only), or "both" (default)
            session_name: Browser session to use (default: "default")
        """
        result = await session_manager.send(session_name, "get_storage", {
            "tab_id": tab_id,
            "storage_type": storage_type,
        })
        return json.dumps(result, indent=2)

    @mcp.tool()
    async def browser_get_console(
        level: str = "all",
        clear: bool = False,
        session_name: str = "default",
        tab_id: str = None,
    ) -> str:
        """Read JavaScript console output from the browser. Returns data the PROXY CANNOT SEE.

        PREREQUISITE: browser_open and browser_go must have been called first.

        Console messages often contain:
        - Stack traces that reveal internal file paths and function names
        - Debug messages with internal API URLs or configuration
        - Error messages that indicate vulnerability surfaces
        - Content Security Policy (CSP) violation reports

        Args:
            level: Filter by message level — "all" (default), "error", or "warning"
            clear: Clear the console buffer after reading (default false). Set true to avoid re-reading old messages.
            session_name: Browser session to use (default: "default")
        """
        result = await session_manager.send(session_name, "get_console", {
            "tab_id": tab_id,
            "level": level,
            "clear": clear,
        })
        return json.dumps(result, indent=2)

    @mcp.tool()
    async def browser_screenshot(
        selector: str = None,
        session_name: str = "default",
        tab_id: str = None,
    ) -> str:
        """Take a screenshot of the current page (returns base64-encoded PNG).

        PREREQUISITE: browser_open and browser_go must have been called first.

        Useful for:
        - Verifying the page state after navigation (did login succeed?)
        - Checking for bot detection challenges (Cloudflare, CAPTCHA)
        - Documenting vulnerability evidence
        - Visual confirmation before destructive actions

        Args:
            selector: CSS selector to capture a specific element (optional — captures full page if omitted)
            session_name: Browser session to use (default: "default")
        """
        result = await session_manager.send(session_name, "screenshot", {
            "tab_id": tab_id,
            "selector": selector,
        })
        return json.dumps(result, indent=2)

    # ── Interaction ──

    @mcp.tool()
    async def browser_click(
        selector: str = None,
        text: str = None,
        session_name: str = "default",
        tab_id: str = None,
    ) -> str:
        """Click an element on the page. Returns any JavaScript alert/confirm/prompt dialog messages triggered.

        PREREQUISITE: browser_open and browser_go must have been called first.

        Provide EITHER selector OR text (not both):
        - selector: CSS selector for the element (e.g. "#login-btn", "button[type=submit]")
        - text: Visible text to find and click (uses best match, e.g. "Login", "Submit")

        XSS DETECTION: If clicking triggers a JavaScript alert() dialog, the dialog message is returned.
        This is how you verify reflected/stored XSS — inject a payload, navigate to the page, and check for alerts.

        Args:
            selector: CSS selector to click (e.g. "#submit", "button.login")
            text: Visible text to find and click (e.g. "Login", "Submit Order")
            session_name: Browser session to use (default: "default")
        """
        result = await session_manager.send(session_name, "click", {
            "tab_id": tab_id,
            "selector": selector,
            "text": text,
        })
        return json.dumps(result, indent=2)

    @mcp.tool()
    async def browser_type(
        selector: str,
        text: str,
        clear: bool = True,
        press_enter: bool = False,
        session_name: str = "default",
        tab_id: str = None,
    ) -> str:
        """Type text into an input field (login forms, search boxes, payload injection).

        PREREQUISITE: browser_open and browser_go must have been called first.

        TYPICAL LOGIN FLOW:
        1. browser_go(url="https://target.com/login")
        2. browser_type(selector="#email", text="admin@target.com")
        3. browser_type(selector="#password", text="password123")
        4. browser_click(selector="#login-btn")

        For XSS testing, type payloads directly: browser_type(selector="#search", text='<script>alert(1)</script>')

        Args:
            selector: CSS selector for the input element (e.g. "#email", "input[name=username]", "#search")
            text: Text to type. Can be any string including XSS/SQLi payloads.
            clear: Clear existing text before typing (default true). Set false to append.
            press_enter: Press Enter key after typing (default false). Useful for search forms without a submit button.
            session_name: Browser session to use (default: "default")
        """
        result = await session_manager.send(session_name, "type", {
            "tab_id": tab_id,
            "selector": selector,
            "text": text,
            "clear": clear,
            "press_enter": press_enter,
        })
        return json.dumps(result, indent=2)

    @mcp.tool()
    async def browser_set_cookie(
        name: str,
        value: str,
        domain: str = None,
        path: str = "/",
        http_only: bool = False,
        secure: bool = False,
        session_name: str = "default",
        tab_id: str = None,
    ) -> str:
        """Set a cookie in the browser via CDP. Can set httpOnly cookies (unlike document.cookie in JS).

        PREREQUISITE: browser_open and browser_go must have been called first (need a page loaded for domain).

        USE CASES:
        - IDOR testing: Set another user's session cookie to test access controls
        - Session fixation: Pre-set a known session ID
        - Testing httpOnly bypass: Inject cookies that JavaScript can't normally set

        Args:
            name: Cookie name (e.g. "session_id", "auth_token")
            value: Cookie value
            domain: Cookie domain (default: current page's domain). Must match or be a parent of the page domain.
            path: Cookie path (default: "/")
            http_only: Set the HttpOnly flag — makes cookie invisible to document.cookie (default false)
            secure: Set the Secure flag — cookie only sent over HTTPS (default false)
            session_name: Browser session to use (default: "default")
        """
        result = await session_manager.send(session_name, "set_cookie", {
            "tab_id": tab_id,
            "name": name,
            "value": value,
            "domain": domain,
            "path": path,
            "http_only": http_only,
            "secure": secure,
        })
        return json.dumps(result, indent=2)

    @mcp.tool()
    async def browser_js(
        expression: str,
        session_name: str = "default",
        tab_id: str = None,
    ) -> str:
        """Execute arbitrary JavaScript in the browser page context. Returns the expression's result.

        PREREQUISITE: browser_open and browser_go must have been called first.

        USE CASES:
        - Extract CSRF tokens: 'document.querySelector("meta[name=csrf-token]").content'
        - Read cookies: 'document.cookie'
        - Hook fetch API to monitor requests
        - Inspect JavaScript objects and prototypes
        - Test DOM-based XSS payloads
        - Call internal JavaScript functions

        The expression is evaluated in the page's JS context — it has full access to the page's DOM,
        variables, functions, and APIs.

        Args:
            expression: JavaScript code to evaluate. Can be a single expression or multi-line code.
                        Example: 'document.title' or 'fetch("/api/me").then(r=>r.json())'
            session_name: Browser session to use (default: "default")
        """
        result = await session_manager.send(session_name, "js", {
            "tab_id": tab_id,
            "expression": expression,
        })
        return json.dumps(result, indent=2)

    @mcp.tool()
    async def browser_wait(
        selector: str = None,
        text: str = None,
        timeout: int = 10,
        session_name: str = "default",
        tab_id: str = None,
    ) -> str:
        """Wait for a DOM element or text to appear on the page. Use for SPAs, AJAX, and dynamic content.

        PREREQUISITE: browser_open and browser_go must have been called first.

        Use this AFTER browser_go or browser_click when the page loads content asynchronously.
        Provide EITHER selector OR text (not both).

        Args:
            selector: CSS selector to wait for (e.g. "#dashboard", ".search-results", "table.data")
            text: Text content to wait for (e.g. "Welcome back", "Results found")
            timeout: Maximum wait time in seconds (default: 10). Returns error if element doesn't appear.
            session_name: Browser session to use (default: "default")
        """
        result = await session_manager.send(session_name, "wait", {
            "tab_id": tab_id,
            "selector": selector,
            "text": text,
            "timeout": timeout,
        })
        return json.dumps(result, indent=2)

    # ── CDP Fetch Interception ──

    @mcp.tool()
    async def browser_intercept_request(
        url_pattern: str,
        action: str,
        key: str = None,
        value: str = None,
        session_name: str = "default",
    ) -> str:
        """Intercept and modify OUTGOING browser requests in real-time via Chrome CDP Fetch API.

        PREREQUISITE: browser_open must have been called first.

        IMPORTANT — This is DIFFERENT from add_interception_rule (proxy-level):
        - browser_intercept_* = instant, browser-only, via Chrome CDP. Changes take effect immediately.
        - add_interception_rule = proxy-level, ~5s cache delay, applies to ALL traffic (browser + code-mode).

        Available actions:
        - "inject_header": Add a custom header to matching requests.
          Example: browser_intercept_request(url_pattern=".*api.*", action="inject_header", key="X-Admin", value="true")
        - "block": Block matching requests entirely (returns network error to the page).
          Example: browser_intercept_request(url_pattern=".*analytics.*", action="block")

        Args:
            url_pattern: Regex pattern to match request URLs (e.g. ".*api.target.com.*")
            action: "inject_header" or "block"
            key: Header name (required for inject_header)
            value: Header value (required for inject_header)
            session_name: Browser session to use (default: "default")
        """
        result = await session_manager.send(session_name, "add_intercept_rule", {
            "url_pattern": url_pattern,
            "action": action,
            "stage": "request",
            "key": key,
            "value": value,
        })
        return json.dumps(result, indent=2)

    @mcp.tool()
    async def browser_intercept_response(
        url_pattern: str,
        action: str,
        search_pattern: str = None,
        value: str = None,
        session_name: str = "default",
    ) -> str:
        """Intercept and modify INCOMING browser responses in real-time via Chrome CDP Fetch API.

        PREREQUISITE: browser_open must have been called first.

        USE CASES:
        - CSP bypass testing: Replace Content-Security-Policy headers in responses
        - Response tampering: Modify API responses to test client-side validation
        - Inject XSS payloads into response bodies
        - Remove security headers to test fallback behavior

        Available actions:
        - "replace_body": Find and replace text in the response body.
          Example: browser_intercept_response(url_pattern=".*api.*", action="replace_body", search_pattern='"admin":false', value='"admin":true')
        - "block": Block the response entirely.

        Args:
            url_pattern: Regex pattern to match request URLs (e.g. ".*api.target.com/me.*")
            action: "replace_body" or "block"
            search_pattern: Regex to find in the response body (required for replace_body)
            value: Replacement text (required for replace_body)
            session_name: Browser session to use (default: "default")
        """
        result = await session_manager.send(session_name, "add_intercept_rule", {
            "url_pattern": url_pattern,
            "action": action,
            "stage": "response",
            "search_pattern": search_pattern,
            "value": value,
        })
        return json.dumps(result, indent=2)

    @mcp.tool()
    async def browser_intercept_disable(session_name: str = "default") -> str:
        """Disable ALL CDP Fetch interception and remove all rules for this browser session.

        Call this when you want to stop intercepting and return to normal browsing.
        This clears both request and response intercept rules.

        Args:
            session_name: Browser session to use (default: "default")
        """
        result = await session_manager.send(session_name, "disable_intercept")
        return json.dumps(result, indent=2)

    @mcp.tool()
    async def browser_list_intercept_rules(session_name: str = "default") -> str:
        """List all active CDP Fetch interception rules for a browser session.

        NOTE: These are browser-level rules only (set via browser_intercept_request/response).
        For proxy-level rules, use list_interception_rules instead.

        Args:
            session_name: Browser session to use (default: "default")
        """
        result = await session_manager.send(session_name, "list_intercept_rules")
        return json.dumps(result, indent=2)
