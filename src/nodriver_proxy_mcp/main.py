"""Nodriver Proxy MCP Server — 39 tools for autonomous pentesting.

Architecture:
  - Code-Mode (1): AI writes Python scripts executed in isolated subprocess
  - Proxy (18): Traffic capture, inspection, replay, fuzzing, rules, session vars via mitmproxy
  - Browser (20): CDP-based Chrome automation via nodriver (anti-bot bypass) + Fetch interception
"""

import logging
from mcp.server.fastmcp import FastMCP

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("nodriver_proxy_mcp")

# Create FastMCP server
mcp = FastMCP(
    "nodriver-proxy-mcp",
    instructions=(
        "39-tool MCP server for autonomous web security testing. "
        "Combines headless proxy (mitmproxy, 18 tools), browser automation (nodriver CDP, 20 tools), "
        "Code-mode (AI-driven Python sandbox, 1 tool).\n\n"
        "## Startup Sequence\n"
        "Always follow this order:\n"
        "1. manage_proxy(action='start') — start the proxy first\n"
        "2. browser_open(proxy_port=8082) — launch Chrome routed through proxy\n"
        "3. browser_go(url='https://target.com') — navigate to target\n"
        "4. Now use traffic tools (get_traffic_summary, search_traffic, etc.)\n\n"
        "## Tool Usage Strategy\n"
        "1. **Autonomous Tool Selection**: You have access to granular tool commands AND a full `execute_security_code` sandbox. "
        "For simple interactions, use individual tools. "
        "For race conditions, heavy looping (Blind SQLi), complex encoding, or PoC generation, use Code-Mode.\n"
        "2. **Code-Mode for Encoding**: When URL encoding/decoding chains are involved "
        "(double encoding, path traversal, etc.), ALWAYS use code-mode to calculate and verify "
        "with assert statements. Never do multi-layer encoding math in your head.\n"
        "3. **Browser for Recon**: Use browser tools for initial reconnaissance, DOM inspection, "
        "and screenshot capture. Use browser_intercept_request/response for real-time CDP Fetch interception. "
        "Switch to code-mode once the attack vector is identified.\n"
        "4. **Proxy for Traffic Analysis**: Start proxy early to passively capture traffic. "
        "Use search_traffic/inspect_flow to understand API patterns before scripting the exploit. "
        "Use proxy_status to check if the proxy is running. Use list_session_variables to review extracted tokens.\n"
        "5. **Two Interception Layers**: "
        "browser_intercept_request/response = instant, browser-only (CDP Fetch). "
        "add_interception_rule = proxy-level, ~5s cache, applies to ALL traffic. "
        "Choose based on scope and latency needs.\n"
        "6. **Session Variables**: Extract tokens with extract_session_variable, "
        "then use {{varname}} in replay_flow for automatic substitution.\n"
        "7. **Individual Tools for Precision**: Use send_raw_request or replay_flow only when "
        "you need byte-level control over a single request. "
        "replay_flow supports {{varname}} session variable placeholders."
    ),
)

# ── Register all tool modules ──

from nodriver_proxy_mcp.proxy.tools import register_proxy_tools
from nodriver_proxy_mcp.browser.tools import register_browser_tools
from nodriver_proxy_mcp.codemode.tools import register_codemode_tools

register_proxy_tools(mcp)       # 18 tools
register_browser_tools(mcp)     # 20 tools
register_codemode_tools(mcp)     #  1 tool

logger.info("Registered tools: Proxy(18) + Browser(20) + Code-mode(1) = 39")


def main():
    """Entry point for the MCP server."""
    import atexit
    from nodriver_proxy_mcp.proxy.controller import proxy_manager
    from nodriver_proxy_mcp.browser.session_manager import session_manager

    def cleanup():
        """Ensure all child processes are killed on exit."""
        logger.info("Cleaning up zombie processes...")
        try:
            proxy_manager.stop()
        except Exception as e:
            logger.warning(f"Proxy cleanup error: {e}")
        try:
            session_manager.close()
        except Exception as e:
            logger.warning(f"Session cleanup error: {e}")

    atexit.register(cleanup)

    logger.info("Starting Nodriver Proxy MCP Server v4.0.0")
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
