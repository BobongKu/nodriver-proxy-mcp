"""SQLite-backed traffic recorder for captured HTTP flows.

Stores all proxied requests/responses with latency tracking.
Provides summary, detail, search, and analysis queries.
"""

import json
import shlex
import sqlite3
import time
from pathlib import Path
from typing import Any, Optional


DB_PATH = Path.home() / ".nodriver-proxy-mcp" / "traffic.db"


class TrafficDB:
    """SQLite persistence for HTTP traffic flows."""

    def __init__(self, db_path: str | Path = DB_PATH):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        with self._conn() as conn:
            conn.executescript("""
                PRAGMA journal_mode=WAL;
                PRAGMA synchronous=NORMAL;
                CREATE TABLE IF NOT EXISTS flows (
                    id TEXT PRIMARY KEY,
                    url TEXT NOT NULL,
                    method TEXT NOT NULL,
                    status_code INTEGER,
                    request_headers TEXT,
                    request_body TEXT,
                    response_headers TEXT,
                    response_body TEXT,
                    latency_ms INTEGER,
                    size INTEGER DEFAULT 0,
                    timestamp REAL NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_flows_timestamp ON flows(timestamp);
                CREATE INDEX IF NOT EXISTS idx_flows_url ON flows(url);
                CREATE INDEX IF NOT EXISTS idx_flows_method ON flows(method);
                CREATE INDEX IF NOT EXISTS idx_flows_status ON flows(status_code);

                CREATE TABLE IF NOT EXISTS session_vars (
                    name TEXT PRIMARY KEY,
                    value TEXT,
                    source_flow_id TEXT,
                    created_at REAL
                );

                CREATE TABLE IF NOT EXISTS interception_rules (
                    id TEXT PRIMARY KEY,
                    active INTEGER DEFAULT 1,
                    url_pattern TEXT,
                    method TEXT,
                    resource_type TEXT DEFAULT 'request',
                    action_type TEXT,
                    key TEXT,
                    value TEXT,
                    search_pattern TEXT,
                    created_at REAL
                );
            """)

    # ── Write ──

    def save_flow(
        self,
        flow_id: str,
        url: str,
        method: str,
        status_code: int | None,
        request_headers: dict,
        request_body: str | None,
        response_headers: dict | None,
        response_body: str | None,
        latency_ms: int | None,
        size: int = 0,
        timestamp: float | None = None,
    ):
        ts = timestamp or time.time()
        with self._conn() as conn:
            conn.execute(
                """
                INSERT INTO flows (
                    id, url, method, status_code,
                    request_headers, request_body,
                    response_headers, response_body,
                    latency_ms, size, timestamp
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    status_code=excluded.status_code,
                    response_headers=excluded.response_headers,
                    response_body=excluded.response_body,
                    latency_ms=excluded.latency_ms,
                    size=excluded.size
                """,
                (
                    flow_id, url, method, status_code,
                    json.dumps(request_headers),
                    request_body,
                    json.dumps(response_headers) if response_headers else None,
                    response_body,
                    latency_ms, size, ts,
                ),
            )

    # ── Read: Summary ──

    def get_summary(self, limit: int = 20, offset: int = 0) -> dict:
        with self._conn() as conn:
            total = conn.execute("SELECT COUNT(*) FROM flows").fetchone()[0]
            rows = conn.execute(
                """
                SELECT id, url, method, status_code,
                       response_headers, latency_ms, size, timestamp
                FROM flows ORDER BY timestamp DESC
                LIMIT ? OFFSET ?
                """,
                (limit, offset),
            ).fetchall()

        flows = []
        for r in rows:
            ct = "unknown"
            if r["response_headers"]:
                hdrs = json.loads(r["response_headers"])
                ct = hdrs.get("content-type", hdrs.get("Content-Type", "unknown"))
            flows.append({
                "id": r["id"],
                "method": r["method"],
                "url": r["url"],
                "status_code": r["status_code"],
                "content_type": ct,
                "latency_ms": r["latency_ms"],
                "size": r["size"],
                "timestamp": r["timestamp"],
            })
        return {"total": total, "flows": flows}

    # ── Read: Detail ──

    def get_detail(self, flow_id: str, include: list[str] | None = None) -> dict | None:
        if include is None:
            include = ["metadata"]

        with self._conn() as conn:
            row = conn.execute("SELECT * FROM flows WHERE id = ?", (flow_id,)).fetchone()

        if not row:
            return None

        result: dict[str, Any] = {
            "id": row["id"],
            "method": row["method"],
            "url": row["url"],
            "status_code": row["status_code"],
            "latency_ms": row["latency_ms"],
        }

        req_headers = json.loads(row["request_headers"]) if row["request_headers"] else {}
        resp_headers = json.loads(row["response_headers"]) if row["response_headers"] else {}

        result["request_content_type"] = req_headers.get(
            "Content-Type", req_headers.get("content-type", "unknown")
        )
        result["response_content_type"] = resp_headers.get(
            "Content-Type", resp_headers.get("content-type", "unknown")
        )
        result["request_size"] = len(row["request_body"] or "")
        result["response_size"] = row["size"] or 0

        if "requestHeaders" in include:
            result.setdefault("request", {})["headers"] = req_headers
        if "requestBody" in include:
            body = row["request_body"] or ""
            result.setdefault("request", {})["body"] = body[:10000]
            result.setdefault("request", {})["body_truncated"] = len(body) > 10000
        if "responseHeaders" in include:
            result.setdefault("response", {})["headers"] = resp_headers
        if "responseBody" in include:
            body = row["response_body"] or ""
            result.setdefault("response", {})["body"] = body[:10000]
            result.setdefault("response", {})["body_truncated"] = len(body) > 10000

        return result

    def get_raw_body(self, flow_id: str, source: str = "response_body") -> str | None:
        """Get untruncated body for extraction/analysis tools."""
        col_map = {
            "response_body": "response_body",
            "request_body": "request_body",
            "response_header": "response_headers",
            "request_header": "request_headers",
        }
        col = col_map.get(source, "response_body")
        with self._conn() as conn:
            row = conn.execute(f"SELECT {col} FROM flows WHERE id = ?", (flow_id,)).fetchone()
        if not row:
            return None
        return row[0]

    def get_headers_batch(self, limit: int = 100) -> list[dict]:
        """Get request headers for multiple recent flows in one query (for auth detection)."""
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT id, url, request_headers FROM flows ORDER BY timestamp DESC LIMIT ?",
                (limit,),
            ).fetchall()
        results = []
        for r in rows:
            hdrs = json.loads(r["request_headers"]) if r["request_headers"] else {}
            results.append({"id": r["id"], "url": r["url"], "headers": hdrs})
        return results

    # ── Read: Search ──

    def search(
        self,
        query: str | None = None,
        domain: str | None = None,
        method: str | None = None,
        status_code: int | None = None,
        limit: int = 50,
    ) -> list[dict]:
        sql = "SELECT id, url, method, status_code, latency_ms, size, timestamp FROM flows WHERE 1=1"
        params: list[Any] = []

        if domain:
            sql += " AND url LIKE ?"
            params.append(f"%{domain}%")
        if method:
            sql += " AND method = ?"
            params.append(method.upper())
        if status_code:
            sql += " AND status_code = ?"
            params.append(status_code)
        if query:
            sql += " AND (url LIKE ? OR request_body LIKE ? OR response_body LIKE ?)"
            w = f"%{query}%"
            params.extend([w, w, w])

        sql += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)

        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [dict(r) for r in rows]

    # ── Read: Full flow for replay ──

    def get_flow_for_replay(self, flow_id: str) -> dict | None:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT method, url, request_headers, request_body FROM flows WHERE id = ?",
                (flow_id,),
            ).fetchone()
        if not row:
            return None
        return {
            "method": row["method"],
            "url": row["url"],
            "headers": json.loads(row["request_headers"]),
            "body": row["request_body"],
        }

    # ── Utility ──

    def clear(self) -> int:
        with self._conn() as conn:
            count = conn.execute("SELECT COUNT(*) FROM flows").fetchone()[0]
            conn.execute("DELETE FROM flows")
        return count

    def generate_curl(self, flow_id: str) -> str | None:
        flow = self.get_flow_for_replay(flow_id)
        if not flow:
            return None
        cmd = ["curl", "-X", flow["method"]]
        cmd.append(shlex.quote(flow["url"]))
        for k, v in flow["headers"].items():
            cmd.extend(["-H", shlex.quote(f"{k}: {v}")])
        if flow["body"]:
            cmd.extend(["-d", shlex.quote(flow["body"])])
        return " ".join(cmd)

    # ── Session Variables ──

    def set_session_var(self, name: str, value: str, source_flow_id: str = ""):
        with self._conn() as conn:
            conn.execute(
                """
                INSERT INTO session_vars (name, value, source_flow_id, created_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(name) DO UPDATE SET value=excluded.value, created_at=excluded.created_at
                """,
                (name, value, source_flow_id, time.time()),
            )

    def get_session_var(self, name: str) -> str | None:
        with self._conn() as conn:
            row = conn.execute("SELECT value FROM session_vars WHERE name = ?", (name,)).fetchone()
        return row["value"] if row else None

    def get_all_session_vars(self) -> dict[str, str]:
        with self._conn() as conn:
            rows = conn.execute("SELECT name, value FROM session_vars").fetchall()
        return {r["name"]: r["value"] for r in rows}

    # ── Interception Rules ──

    def add_rule(self, rule_id: str, **kwargs) -> str:
        with self._conn() as conn:
            conn.execute(
                """
                INSERT INTO interception_rules (id, url_pattern, method, resource_type, action_type, key, value, search_pattern, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    rule_id,
                    kwargs.get("url_pattern"),
                    kwargs.get("method"),
                    kwargs.get("resource_type", "request"),
                    kwargs.get("action_type"),
                    kwargs.get("key"),
                    kwargs.get("value"),
                    kwargs.get("search_pattern"),
                    time.time(),
                ),
            )
        return rule_id

    def get_active_rules(self) -> list[dict]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM interception_rules WHERE active = 1"
            ).fetchall()
        return [dict(r) for r in rows]

    def remove_rule(self, rule_id: str) -> bool:
        with self._conn() as conn:
            cursor = conn.execute("DELETE FROM interception_rules WHERE id = ?", (rule_id,))
        return cursor.rowcount > 0


# Global instance
traffic_db = TrafficDB()
