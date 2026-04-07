"""nodriver-proxy-mcp SDK — 코드모드 스크립트에서 29개 도구를 직접 호출.

사용법:
    from nodriver_proxy_mcp.sdk import NdpSDK

    async def main():
        sdk = NdpSDK()  # 기존 세션 자동 감지 (MCP_BROWSER_SESSIONS 환경변수)

        # Proxy 도구
        await sdk.manage_proxy("start", port=8082)
        flows = await sdk.get_traffic_summary(limit=20)

        # Browser 도구
        await sdk.browser_open(session_name="default", proxy_port=8082)
        await sdk.browser_go("https://target.com")
        dom = await sdk.browser_get_dom()

    import asyncio
    asyncio.run(main())

반환값: MCP 도구와 달리 JSON 문자열이 아닌 파싱된 Python dict/list 반환.
"""

import asyncio
import json
import logging
import os
import re
import socket
import subprocess
import sys
import time
import uuid
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────
# 내부: 경량 Browser IPC 클라이언트
# ─────────────────────────────────────────────

class _BrowserIPCClient:
    """BrowserDaemon과 TCP JSON-RPC 통신하는 경량 클라이언트.
    browser/session_manager.py의 BrowserSession과 동일한 프로토콜."""

    def __init__(self, ipc_port: int):
        self.ipc_port = ipc_port

    async def send(self, method: str, params: dict = None, timeout: float = 120) -> dict:
        request = json.dumps({
            "method": method,
            "params": params or {},
            "id": int(time.time() * 1000),
        }) + "\n"
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection("127.0.0.1", self.ipc_port),
                timeout=5,
            )
            writer.write(request.encode())
            await writer.drain()
            data = await asyncio.wait_for(reader.readline(), timeout=timeout)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            if data:
                response = json.loads(data.decode())
                if "error" in response:
                    return {"error": response["error"]}
                return response.get("result", {})
            return {"error": "Empty response from daemon"}
        except asyncio.TimeoutError:
            return {"error": f"IPC timeout after {timeout}s"}
        except ConnectionRefusedError:
            return {"error": f"Cannot connect to browser daemon on port {self.ipc_port}"}
        except Exception as e:
            return {"error": f"IPC error: {e}"}


def _find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_for_port(port: int, timeout: float = 10.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return True
        except (ConnectionRefusedError, OSError):
            time.sleep(0.3)
    return False


# ─────────────────────────────────────────────
# NdpSDK 메인 클래스
# ─────────────────────────────────────────────

class NdpSDK:
    """nodriver-proxy-mcp 29개 도구의 Python SDK.

    코드모드 스크립트(execute_security_code subprocess)에서 직접 import하여 사용.

    Args:
        default_session: 브라우저 세션 기본 이름 (default: "default")
    """

    def __init__(self, default_session: str = "default"):
        self.default_session = default_session

        # 환경변수에서 기존 세션 IPC 포트 정보 로드
        # (codemode/tools.py가 MCP_BROWSER_SESSIONS JSON을 주입)
        self._sessions: dict[str, dict] = {}
        raw = os.environ.get("MCP_BROWSER_SESSIONS", "")
        if raw:
            try:
                self._sessions = json.loads(raw)
            except Exception:
                pass

        # 코드모드 subprocess가 직접 시작한 세션 관리
        self._local_procs: dict[str, subprocess.Popen] = {}

        # Proxy 싱글턴 lazy-import (subprocess 내에서도 동일 DB 공유)
        self._traffic_db = None
        self._scope_manager = None
        self._proxy_manager = None

    # ─── Lazy imports (패키지 내부 싱글턴) ───

    def _get_traffic_db(self):
        if self._traffic_db is None:
            from nodriver_proxy_mcp.proxy.recorder import traffic_db
            self._traffic_db = traffic_db
        return self._traffic_db

    def _get_scope_manager(self):
        if self._scope_manager is None:
            from nodriver_proxy_mcp.proxy.scope import scope_manager
            self._scope_manager = scope_manager
        return self._scope_manager

    def _get_proxy_manager(self):
        if self._proxy_manager is None:
            from nodriver_proxy_mcp.proxy.controller import proxy_manager
            self._proxy_manager = proxy_manager
        return self._proxy_manager

    def _proxy_url(self) -> str | None:
        """Return the proxy URL if proxy is running, else None."""
        pm = self._get_proxy_manager()
        if pm.running:
            return f"http://127.0.0.1:{pm.port}"
        return None

    def _get_ipc_client(self, session_name: str) -> Optional[_BrowserIPCClient]:
        info = self._sessions.get(session_name)
        if info:
            return _BrowserIPCClient(info["ipc_port"])
        return None

    # ═══════════════════════════════════════════════════
    # PROXY 도구 (13개)
    # ═══════════════════════════════════════════════════

    async def manage_proxy(
        self,
        action: str,
        port: int = 8082,
        ui: bool = False,
        upstream: str = "localhost:8080",
    ) -> dict:
        """프록시 시작/중지.
        Args:
            action: "start" 또는 "stop"
            port: 리스닝 포트 (기본 8082)
            ui: True면 mitmweb GUI 모드 (포트 8081)
            upstream: 업스트림 프록시 주소 (기본 localhost:8080 = Burp)
        """
        pm = self._get_proxy_manager()
        if action == "start":
            return pm.start(port=port, ui=ui, upstream=upstream)
        elif action == "stop":
            return pm.stop()
        else:
            return {"error": f"Unknown action: {action}. Use 'start' or 'stop'."}

    async def set_scope(self, allowed_domains: list[str]) -> dict:
        """프록시 스코프 설정. 빈 리스트 = 모든 트래픽 기록.
        Args:
            allowed_domains: 기록할 도메인 목록 (예: ["target.com", "api.target.com"])
        """
        sm = self._get_scope_manager()
        sm.set_domains(allowed_domains)
        return sm.to_dict()

    async def get_traffic_summary(self, limit: int = 20, offset: int = 0) -> dict:
        """캡처된 HTTP 트래픽 요약 (페이징 지원).
        Returns: { total, flows: [{id, method, url, status_code, latency_ms, ...}] }
        """
        return self._get_traffic_db().get_summary(limit=limit, offset=offset)

    async def inspect_flow(
        self,
        flow_id: str,
        include: list[str] = None,
    ) -> dict:
        """특정 플로우 상세 정보.
        Args:
            flow_id: get_traffic_summary에서 반환된 플로우 ID
            include: 포함할 필드 목록
                     옵션: metadata, requestHeaders, requestBody, responseHeaders, responseBody
        Returns: 플로우 상세 dict 또는 {"error": ...}
        """
        if include is None:
            include = ["metadata"]
        result = self._get_traffic_db().get_detail(flow_id, include=include)
        if not result:
            return {"error": f"Flow {flow_id} not found"}
        return result

    async def search_traffic(
        self,
        query: str = None,
        domain: str = None,
        method: str = None,
        status_code: int = None,
        limit: int = 50,
    ) -> dict:
        """트래픽 검색.
        Args:
            query: URL/요청본문/응답본문에서 검색할 키워드
            domain: 도메인 필터
            method: HTTP 메서드 필터 (GET, POST, ...)
            status_code: 응답 상태코드 필터
            limit: 최대 반환 건수 (기본 50)
        Returns: { total, flows: [...] }
        """
        results = self._get_traffic_db().search(
            query=query, domain=domain, method=method,
            status_code=status_code, limit=limit,
        )
        return {"total": len(results), "flows": results}

    async def extract_from_flow(
        self,
        flow_id: str,
        json_path: str = None,
        css_selector: str = None,
        regex: str = None,
    ) -> dict:
        """플로우 응답 본문에서 데이터 추출.
        추출기는 하나만 사용: json_path, css_selector, regex 중 택1.
        Args:
            flow_id: 대상 플로우 ID
            json_path: JSONPath 표현식 (예: $.data.users[0].id)
            css_selector: HTML CSS 셀렉터 (예: input[name=csrf])
            regex: 캡처그룹 포함 정규식 (예: token: "([^"]+)")
        Returns: { flow_id, extractor, expression, matches: [...] }
        """
        db = self._get_traffic_db()
        detail = db.get_detail(flow_id, include=["metadata"])
        if not detail:
            return {"error": f"Flow {flow_id} not found"}

        body = db.get_raw_body(flow_id, "response_body") or ""
        matches = []

        if json_path:
            try:
                from jsonpath_ng import parse as jp_parse
                expr = jp_parse(json_path)
                data = json.loads(body)
                matches = [str(m.value) for m in expr.find(data)]
            except Exception as e:
                return {"error": f"JSONPath error: {e}"}
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
                return {"error": f"CSS selector error: {e}"}
        elif regex:
            try:
                found = re.findall(regex, body)
                matches = [str(m) for m in found]
            except Exception as e:
                return {"error": f"Regex error: {e}"}

        return {
            "flow_id": flow_id,
            "extractor": "json_path" if json_path else "css_selector" if css_selector else "regex",
            "expression": json_path or css_selector or regex,
            "matches": matches[:20],
        }

    async def clear_traffic(self) -> dict:
        """DB의 모든 캡처 트래픽 삭제.
        Returns: { cleared: N, status: "ok" }
        """
        count = self._get_traffic_db().clear()
        return {"cleared": count, "status": "ok"}

    async def replay_flow(
        self,
        flow_id: str,
        replacements: list[dict] = None,
        follow_redirects: bool = True,
    ) -> dict:
        """캡처된 플로우를 재전송 (Burp Repeater와 동일).
        Args:
            flow_id: 재전송할 플로우 ID
            replacements: [{"regex": "...", "replacement": "..."}] 목록
            follow_redirects: 리다이렉트 따라가기 (기본 True)
        Returns: { status_code, latency_ms, headers, body, ... }
        """
        import httpx

        db = self._get_traffic_db()
        flow = db.get_flow_for_replay(flow_id)
        if not flow:
            return {"error": f"Flow {flow_id} not found"}

        url = flow["url"]
        headers = flow["headers"].copy()
        body = flow["body"]

        if replacements:
            for r in replacements:
                pattern = r.get("regex", "")
                repl = r.get("replacement", "")
                url = re.sub(pattern, repl, url)
                body = re.sub(pattern, repl, body) if body else body
                headers = {k: re.sub(pattern, repl, v) for k, v in headers.items()}

        for h in ["Host", "Content-Length", "Transfer-Encoding"]:
            headers.pop(h, None)

        start = time.monotonic()
        try:
            async with httpx.AsyncClient(verify=False, follow_redirects=follow_redirects, proxy=self._proxy_url()) as client:
                resp = await client.request(
                    method=flow["method"],
                    url=url,
                    headers=headers,
                    content=body.encode() if body else None,
                    timeout=30,
                )
            latency = int((time.monotonic() - start) * 1000)
            resp_body = resp.text
            return {
                "status_code": resp.status_code,
                "latency_ms": latency,
                "headers": dict(resp.headers),
                "body": resp_body[:10000],
                "body_truncated": len(resp_body) > 10000,
                "applied_replacements": len(replacements or []),
            }
        except Exception as e:
            return {"error": str(e)}

    async def send_raw_request(
        self,
        raw: str,
        host: str = None,
        port: int = None,
        tls: bool = True,
        follow_redirects: bool = True,
    ) -> dict:
        """Raw HTTP 요청 전송.
        Args:
            raw: 완전한 HTTP 요청 문자열 (메서드 라인 + 헤더 + 본문)
            host: 대상 호스트 (Host 헤더보다 우선)
            port: 대상 포트 (기본: TLS=443, 평문=80)
            tls: HTTPS 사용 여부 (기본 True)
            follow_redirects: 리다이렉트 따라가기 (기본 True)
        Returns: { status_code, latency_ms, headers, body, ... }
        """
        import httpx

        lines = raw.strip().split("\n")
        if not lines:
            return {"error": "Empty request"}

        first_line = lines[0].strip()
        parts = first_line.split(" ", 2)
        if len(parts) < 2:
            return {"error": f"Invalid request line: {first_line}"}

        method = parts[0]
        path = parts[1]

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

        if not host:
            host = headers.get("Host", headers.get("host", ""))
        if not host:
            return {"error": "Host is required"}

        scheme = "https" if tls else "http"
        actual_port = port or (443 if tls else 80)
        if (tls and actual_port == 443) or (not tls and actual_port == 80):
            url = f"{scheme}://{host}{path}"
        else:
            url = f"{scheme}://{host}:{actual_port}{path}"

        for h in ["Host", "Content-Length", "Transfer-Encoding"]:
            headers.pop(h, None)

        start = time.monotonic()
        try:
            async with httpx.AsyncClient(verify=False, follow_redirects=follow_redirects, proxy=self._proxy_url()) as client:
                resp = await client.request(
                    method=method,
                    url=url,
                    headers=headers,
                    content=body.encode() if body else None,
                    timeout=30,
                )
            latency = int((time.monotonic() - start) * 1000)
            resp_body = resp.text
            return {
                "status_code": resp.status_code,
                "latency_ms": latency,
                "headers": dict(resp.headers),
                "body": resp_body[:10000],
                "body_truncated": len(resp_body) > 10000,
            }
        except Exception as e:
            return {"error": str(e)}

    async def add_interception_rule(
        self,
        url_pattern: str,
        action: str,
        resource_type: str = "request",
        key: str = None,
        value: str = None,
        search_pattern: str = None,
        method: str = None,
    ) -> dict:
        """실시간 트래픽 인터셉션 규칙 추가.
        Args:
            url_pattern: URL 매칭 정규식
            action: inject_header, replace_body, block 중 하나
            resource_type: request 또는 response (기본 request)
            key: 헤더 이름 (inject_header용)
            value: 헤더 값 (inject_header용) 또는 치환 텍스트 (replace_body용)
            search_pattern: 본문에서 찾을 정규식 (replace_body용)
            method: 특정 HTTP 메서드만 매칭 (선택)
        Returns: { rule_id, active: True }
        """
        rule_id = f"r-{uuid.uuid4().hex[:8]}"
        self._get_traffic_db().add_rule(
            rule_id,
            url_pattern=url_pattern,
            action_type=action,
            resource_type=resource_type,
            key=key,
            value=value,
            search_pattern=search_pattern,
            method=method,
        )
        return {"rule_id": rule_id, "active": True}

    async def extract_session_variable(
        self,
        flow_id: str,
        regex: str,
        name: str,
        source: str = "response_body",
    ) -> dict:
        """플로우에서 값을 추출하여 세션 변수로 저장.
        저장된 변수는 replay_flow의 replacements에서 {{name}} 형식으로 참조 가능.
        Args:
            flow_id: 대상 플로우 ID
            regex: 캡처그룹 1개 포함 정규식
            name: 저장할 변수 이름
            source: 추출 위치 (response_body, response_header, request_header, request_body)
        Returns: { name, value, source }
        """
        db = self._get_traffic_db()
        detail = db.get_detail(flow_id, include=["metadata"])
        if not detail:
            return {"error": f"Flow {flow_id} not found"}

        text = db.get_raw_body(flow_id, source) or ""
        match = re.search(regex, text)
        if not match:
            return {"error": f"Pattern not found: {regex}"}

        value = match.group(1) if match.lastindex else match.group(0)
        db.set_session_var(name, value, flow_id)
        return {"name": name, "value": value, "source": source}

    async def detect_auth_pattern(self, flow_ids: str = None) -> dict:
        """트래픽에서 인증 패턴 자동 감지.
        감지 대상: JWT, Bearer 토큰, API 키, 세션 쿠키, CSRF 토큰, Basic 인증, OAuth2.
        Args:
            flow_ids: 쉼표로 구분된 플로우 ID 목록 (없으면 최근 100개 분석)
        Returns: { detected_auth_types: [...], details: {...} }
        """
        db = self._get_traffic_db()

        if flow_ids:
            ids = [fid.strip() for fid in flow_ids.split(",")]
            flows = []
            for fid in ids:
                detail = db.get_detail(fid, include=["requestHeaders"])
                if detail:
                    flows.append({
                        "id": detail["id"],
                        "url": detail["url"],
                        "headers": detail.get("request", {}).get("headers", {}),
                    })
        else:
            flows = db.get_headers_batch(limit=100)

        auth_signals = {
            k: {"detected": False, "signals": [], "flows": []}
            for k in ["jwt", "bearer_token", "api_key", "session_cookie", "csrf", "basic_auth", "oauth2"]
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

        for key in auth_signals:
            auth_signals[key]["flows"] = list(set(auth_signals[key]["flows"]))[:5]
            auth_signals[key]["signals"] = list(set(auth_signals[key]["signals"]))

        detected = [k for k, v in auth_signals.items() if v["detected"]]
        return {"detected_auth_types": detected, "details": auth_signals}

    async def fuzz_endpoint(
        self,
        flow_id: str,
        payloads: list[str],
        target_pattern: str = "FUZZ",
        concurrency: int = 5,
    ) -> dict:
        """엔드포인트 퍼징 (FUZZ 패턴을 페이로드로 치환하여 이상 감지).
        Args:
            flow_id: 기반 플로우 ID (target_pattern 포함되어야 함)
            payloads: 주입할 페이로드 문자열 목록
            target_pattern: 치환 대상 문자열 (기본 "FUZZ")
            concurrency: 동시 요청 수 (기본 5)
        Returns: { baseline, total_requests, anomalies_found, anomalies: [...] }
        """
        from nodriver_proxy_mcp.proxy.fuzzer import run_fuzz
        return await run_fuzz(
            flow_id=flow_id,
            payloads=payloads,
            target_pattern=target_pattern,
            concurrency=concurrency,
        )

    # ═══════════════════════════════════════════════════
    # BROWSER 도구 (16개)
    # ═══════════════════════════════════════════════════

    async def browser_open(
        self,
        session_name: str = "default",
        proxy_port: int = 8082,
        headless: bool = True,
    ) -> dict:
        """Chrome 브라우저 세션 시작 (CDP + anti-bot bypass).
        이미 열려있으면 기존 세션 정보를 반환.
        Args:
            session_name: 세션 이름 (기본 "default")
            proxy_port: mitmproxy 포트 (기본 8082, 0이면 프록시 미사용)
            headless: 헤드리스 모드 (기본 True)
        Returns: { status, session, ipc_port, cdp_port, pid }
        """
        # 이미 열린 세션이 있으면 재사용
        if session_name in self._sessions:
            info = self._sessions[session_name]
            client = _BrowserIPCClient(info["ipc_port"])
            result = await client.send("ping")
            if "error" not in result:
                return {
                    "status": "already_open",
                    "session": session_name,
                    "ipc_port": info["ipc_port"],
                    "cdp_port": info["cdp_port"],
                }

        ipc_port = _find_free_port()
        cdp_port = _find_free_port()

        browser_args = []
        if proxy_port:
            browser_args.extend([
                f"--proxy-server=127.0.0.1:{proxy_port}",
                "--ignore-certificate-errors",
            ])

        daemon_module = "nodriver_proxy_mcp.browser.daemon"
        cmd = [
            sys.executable, "-m", daemon_module,
            "--ipc-port", str(ipc_port),
            "--cdp-port", str(cdp_port),
            "--headless", str(headless).lower(),
            "--browser-args", json.dumps(browser_args),
            "--parent-pid", str(os.getpid()),
        ]

        popen_kwargs = dict(
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if sys.platform == "win32":
            popen_kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
        else:
            popen_kwargs["start_new_session"] = True

        proc = subprocess.Popen(cmd, **popen_kwargs)

        if not _wait_for_port(ipc_port, timeout=15.0):
            if proc.poll() is not None:
                stderr = proc.stderr.read().decode(errors="replace") if proc.stderr else ""
                return {"error": f"Browser daemon exited: {stderr[:500]}"}
            else:
                logger.warning(f"IPC port {ipc_port} not ready after 15s, but process alive")

        # 세션 정보 등록
        self._sessions[session_name] = {"ipc_port": ipc_port, "cdp_port": cdp_port}
        self._local_procs[session_name] = proc

        result = {
            "status": "ready",
            "session": session_name,
            "ipc_port": ipc_port,
            "cdp_port": cdp_port,
            "pid": proc.pid,
        }
        if proxy_port:
            result["proxy"] = f"127.0.0.1:{proxy_port}"
        return result

    async def browser_close(self, session_name: str = "default") -> dict:
        """브라우저 세션 종료.
        Args:
            session_name: 종료할 세션 이름 (기본 "default")
        Returns: { status, session }
        """
        # IPC로 닫기 시그널 먼저
        client = self._get_ipc_client(session_name)
        if client:
            await client.send("close")

        # 로컬 프로세스 종료
        proc = self._local_procs.pop(session_name, None)
        if proc and proc.poll() is None:
            try:
                proc.terminate()
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=3)

        self._sessions.pop(session_name, None)
        return {"status": "closed", "session": session_name}

    async def browser_list_sessions(self) -> dict:
        """활성 브라우저 세션 목록.
        Returns: { sessions: [{name, ipc_port, cdp_port, status}] }
        """
        sessions = []
        for name, info in self._sessions.items():
            client = _BrowserIPCClient(info["ipc_port"])
            ping = await client.send("ping", timeout=3)
            status = "active" if "error" not in ping else "dead"
            sessions.append({
                "name": name,
                "ipc_port": info["ipc_port"],
                "cdp_port": info["cdp_port"],
                "status": status,
                "current_url": ping.get("current_url", ""),
            })
        return {"sessions": sessions}

    async def browser_list_tabs(self, session_name: str = None) -> dict:
        """브라우저의 열린 탭 목록.
        Returns: { tabs: [{tab_id, url, title}] }
        """
        session_name = session_name or self.default_session
        client = self._get_ipc_client(session_name)
        if not client:
            return {"error": f"Session '{session_name}' not found. Use browser_open first."}
        return await client.send("list_tabs")

    async def browser_go(
        self,
        url: str,
        session_name: str = None,
        tab_id: str = None,
        wait_for: str = None,
    ) -> dict:
        """URL로 이동. 페이지 로드 완료까지 대기.
        Args:
            url: 이동할 URL
            session_name: 브라우저 세션 이름
            tab_id: 특정 탭 ID (없으면 현재 탭)
            wait_for: 로드 후 대기할 CSS 셀렉터 (SPA용)
        Returns: { status, final_url, title, dialogs, ... }
        """
        session_name = session_name or self.default_session
        client = self._get_ipc_client(session_name)
        if not client:
            return {"error": f"Session '{session_name}' not found. Use browser_open first."}
        return await client.send("go", {"tab_id": tab_id, "url": url, "wait_for": wait_for})

    async def browser_back(self, session_name: str = None, tab_id: str = None) -> dict:
        """브라우저 뒤로가기.
        Returns: { status: "ok" }
        """
        session_name = session_name or self.default_session
        client = self._get_ipc_client(session_name)
        if not client:
            return {"error": f"Session '{session_name}' not found. Use browser_open first."}
        return await client.send("back", {"tab_id": tab_id})

    async def browser_get_dom(
        self,
        selector: str = "body",
        max_depth: int = 4,
        session_name: str = None,
        tab_id: str = None,
    ) -> dict:
        """보안 관련 DOM 구조 추출.
        폼, 링크, 스크립트, iframe, 메타태그, HTML 주석, 이벤트 핸들러,
        data-* 속성, 간소화된 DOM 트리를 자동 추출.
        프록시가 볼 수 없는 클라이언트 사이드 정보.
        Returns: { url, title, forms, links, scripts, iframes, ... }
        """
        session_name = session_name or self.default_session
        client = self._get_ipc_client(session_name)
        if not client:
            return {"error": f"Session '{session_name}' not found. Use browser_open first."}
        return await client.send("get_dom", {
            "tab_id": tab_id, "selector": selector, "max_depth": max_depth,
        })

    async def browser_get_text(
        self,
        selector: str,
        session_name: str = None,
        tab_id: str = None,
    ) -> dict:
        """특정 엘리먼트의 텍스트 내용 반환.
        Args:
            selector: CSS 셀렉터 (예: "h1", "#user-info", ".alert")
        Returns: { selector, text }
        """
        session_name = session_name or self.default_session
        client = self._get_ipc_client(session_name)
        if not client:
            return {"error": f"Session '{session_name}' not found. Use browser_open first."}
        return await client.send("get_text", {"tab_id": tab_id, "selector": selector})

    async def browser_get_storage(
        self,
        storage_type: str = "both",
        session_name: str = None,
        tab_id: str = None,
    ) -> dict:
        """브라우저 localStorage/sessionStorage 읽기.
        JWT, API 키 등 클라이언트 사이드 민감 데이터 확인용.
        Args:
            storage_type: "local", "session", "both" (기본 "both")
        Returns: { localStorage: {...}, sessionStorage: {...} }
        """
        session_name = session_name or self.default_session
        client = self._get_ipc_client(session_name)
        if not client:
            return {"error": f"Session '{session_name}' not found. Use browser_open first."}
        return await client.send("get_storage", {"tab_id": tab_id, "storage_type": storage_type})

    async def browser_get_console(
        self,
        level: str = "all",
        clear: bool = False,
        session_name: str = None,
        tab_id: str = None,
    ) -> dict:
        """JS 콘솔 출력 가져오기.
        스택 트레이스, 내부 API URL, 디버그 정보 등 프록시에서 볼 수 없는 정보.
        Args:
            level: "all", "error", "warning" 필터 (기본 "all")
            clear: 읽은 후 버퍼 초기화 여부 (기본 False)
        Returns: { entries: [{level, text, timestamp}], total }
        """
        session_name = session_name or self.default_session
        client = self._get_ipc_client(session_name)
        if not client:
            return {"error": f"Session '{session_name}' not found. Use browser_open first."}
        return await client.send("get_console", {"tab_id": tab_id, "level": level, "clear": clear})

    async def browser_screenshot(
        self,
        selector: str = None,
        session_name: str = None,
        tab_id: str = None,
    ) -> dict:
        """현재 페이지 스크린샷 캡처.
        Args:
            selector: 특정 엘리먼트만 캡처할 CSS 셀렉터 (없으면 전체 페이지)
        Returns: { path: "/tmp/screenshot_xxx.png" }
        """
        session_name = session_name or self.default_session
        client = self._get_ipc_client(session_name)
        if not client:
            return {"error": f"Session '{session_name}' not found. Use browser_open first."}
        return await client.send("screenshot", {"tab_id": tab_id, "selector": selector})

    async def browser_click(
        self,
        selector: str = None,
        text: str = None,
        session_name: str = None,
        tab_id: str = None,
    ) -> dict:
        """엘리먼트 클릭. 트리거된 JS 다이얼로그 반환 (XSS alert 감지).
        selector 또는 text 중 하나를 지정.
        Args:
            selector: CSS 셀렉터 (예: "#submit-btn", "button.login")
            text: 텍스트로 엘리먼트 찾기 (best_match 알고리즘)
        Returns: { clicked, element, dialogs: [...] }
        """
        session_name = session_name or self.default_session
        client = self._get_ipc_client(session_name)
        if not client:
            return {"error": f"Session '{session_name}' not found. Use browser_open first."}
        return await client.send("click", {
            "tab_id": tab_id, "selector": selector, "text": text,
        })

    async def browser_type(
        self,
        selector: str,
        text: str,
        clear: bool = True,
        press_enter: bool = False,
        session_name: str = None,
        tab_id: str = None,
    ) -> dict:
        """입력 필드에 텍스트 입력. XSS/SQLi 페이로드 주입 가능.
        Args:
            selector: CSS 셀렉터 (예: "input[name=username]", "#password")
            text: 입력할 텍스트 (페이로드 포함 가능)
            clear: 기존 내용 먼저 지우기 (기본 True)
            press_enter: 입력 후 Enter 키 입력 여부 (기본 False)
        Returns: { typed: True }
        """
        session_name = session_name or self.default_session
        client = self._get_ipc_client(session_name)
        if not client:
            return {"error": f"Session '{session_name}' not found. Use browser_open first."}
        return await client.send("type", {
            "tab_id": tab_id, "selector": selector, "text": text,
            "clear": clear, "press_enter": press_enter,
        })

    async def browser_set_cookie(
        self,
        name: str,
        value: str,
        domain: str = None,
        path: str = "/",
        http_only: bool = False,
        secure: bool = False,
        session_name: str = None,
        tab_id: str = None,
    ) -> dict:
        """CDP로 쿠키 설정 (document.cookie보다 강력 — httpOnly 설정 가능).
        IDOR 테스트: 다른 사용자의 세션 쿠키를 주입해서 접근 제어 우회 확인.
        Args:
            name: 쿠키 이름
            value: 쿠키 값
            domain: 쿠키 도메인 (없으면 현재 페이지 도메인)
            path: 쿠키 경로 (기본 "/")
            http_only: HttpOnly 플래그 설정
            secure: Secure 플래그 설정
        Returns: { set: True, name }
        """
        session_name = session_name or self.default_session
        client = self._get_ipc_client(session_name)
        if not client:
            return {"error": f"Session '{session_name}' not found. Use browser_open first."}
        return await client.send("set_cookie", {
            "tab_id": tab_id, "name": name, "value": value,
            "domain": domain, "path": path,
            "http_only": http_only, "secure": secure,
        })

    async def browser_js(
        self,
        expression: str,
        session_name: str = None,
        tab_id: str = None,
    ) -> dict:
        """브라우저에서 JavaScript 실행.
        CSRF 토큰 추출, DOM 기반 XSS 테스트, fetch API 후킹, 이벤트 리스너 검사 등.
        Args:
            expression: 실행할 JavaScript 표현식 (예: "document.cookie", "localStorage.getItem('token')")
        Returns: { value, type }
        """
        session_name = session_name or self.default_session
        client = self._get_ipc_client(session_name)
        if not client:
            return {"error": f"Session '{session_name}' not found. Use browser_open first."}
        return await client.send("js", {"tab_id": tab_id, "expression": expression})

    async def browser_wait(
        self,
        selector: str = None,
        text: str = None,
        timeout: int = 10,
        session_name: str = None,
        tab_id: str = None,
    ) -> dict:
        """엘리먼트가 나타날 때까지 대기. SPA 로딩, AJAX 완료 대기에 사용.
        Args:
            selector: 대기할 CSS 셀렉터
            text: 대기할 텍스트 내용
            timeout: 최대 대기 시간 (초, 기본 10)
        Returns: { found: True/False, waited_ms }
        """
        session_name = session_name or self.default_session
        client = self._get_ipc_client(session_name)
        if not client:
            return {"error": f"Session '{session_name}' not found. Use browser_open first."}
        return await client.send("wait", {
            "tab_id": tab_id, "selector": selector, "text": text, "timeout": timeout,
        })

    # ─── 편의 메서드 ───

    def get_session_var(self, name: str) -> Optional[str]:
        """저장된 세션 변수 값 조회."""
        return self._get_traffic_db().get_session_var(name)

    def get_all_session_vars(self) -> dict:
        """모든 세션 변수 조회."""
        return self._get_traffic_db().get_all_session_vars()

    def generate_curl(self, flow_id: str) -> Optional[str]:
        """플로우를 curl 명령어로 변환."""
        return self._get_traffic_db().generate_curl(flow_id)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        """컨텍스트 매니저 종료 시 로컬로 시작한 브라우저 세션 정리."""
        for name in list(self._local_procs.keys()):
            await self.browser_close(name)
