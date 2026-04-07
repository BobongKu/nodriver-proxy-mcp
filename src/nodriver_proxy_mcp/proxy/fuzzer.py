"""Fuzzer engine — sends multiple payloads and detects anomalies."""

import time
import asyncio
import httpx
import logging
import re
from collections import Counter
from typing import List, Dict, Any, Tuple

from .recorder import traffic_db
from .controller import proxy_manager

logger = logging.getLogger(__name__)


def _proxy_url() -> str | None:
    """Return the proxy URL if proxy is running, else None."""
    if proxy_manager.running:
        return f"http://127.0.0.1:{proxy_manager.port}"
    return None


async def run_fuzz(
    flow_id: str,
    payloads: List[str],
    target_pattern: str = "FUZZ",
    baseline_requests: int = 3,
    concurrency: int = 5,
    timeout: int = 15
) -> Dict[str, Any]:
    """
    Replay a flow replacing the target pattern with given payloads.
    Detects anomalies based on Status Code, Latency, Body Length, and Error Keywords.
    """
    flow = traffic_db.get_flow_for_replay(flow_id)
    if not flow:
        return {"error": f"Flow {flow_id} not found"}

    url_template = flow["url"]
    headers_template = flow["headers"].copy()
    body_template = flow["body"] or ""

    # Check if target_pattern exists
    has_target = (
        target_pattern in url_template or
        target_pattern in body_template or
        any(target_pattern in v for v in headers_template.values())
    )

    if not has_target:
        return {"error": f"Target pattern '{target_pattern}' not found in the original request"}

    # Remove hop-by-hop headers
    for h in ["Host", "Content-Length", "Transfer-Encoding"]:
        headers_template.pop(h, None)

    async with httpx.AsyncClient(verify=False, follow_redirects=False, timeout=timeout, proxy=_proxy_url()) as client:
        # 1. Establish Baseline
        baseline_results = []
        baseline_url = url_template.replace(target_pattern, "")
        baseline_body = body_template.replace(target_pattern, "")
        baseline_headers = {k: v.replace(target_pattern, "") for k, v in headers_template.items()}
        for _ in range(baseline_requests):
            # Send clean request (FUZZ marker removed) as baseline
            start_time = time.monotonic()
            try:
                resp = await client.request(
                    method=flow["method"],
                    url=baseline_url,
                    headers=baseline_headers,
                    content=baseline_body.encode(),
                )
                latency = int((time.monotonic() - start_time) * 1000)
                baseline_results.append({
                    "status": resp.status_code,
                    "length": len(resp.content),
                    "latency": latency
                })
            except Exception:
                pass # Ignore baseline failures for now

        if not baseline_results:
            return {"error": "Failed to establish baseline (all baseline requests failed)"}

        # Calculate baseline stats — use mode for status code (handles 302 redirects)
        status_counts = Counter(r["status"] for r in baseline_results)
        avg_status = status_counts.most_common(1)[0][0]
        avg_length = sum(r["length"] for r in baseline_results) / len(baseline_results)
        avg_latency = sum(r["latency"] for r in baseline_results) / len(baseline_results)
        
        # Max acceptable variance
        length_threshold_diff = max(50, avg_length * 0.10) # 10% or 50 bytes
        latency_threshold = avg_latency * 3 + 200 # 3x + 200ms

        # 2. Fuzzing execution
        results = []
        
        semaphore = asyncio.Semaphore(concurrency)

        async def _send_payload(payload: str) -> Dict[str, Any]:
            async with semaphore:
                p_url = url_template.replace(target_pattern, payload)
                p_body = body_template.replace(target_pattern, payload)
                p_headers = {k: v.replace(target_pattern, payload) for k, v in headers_template.items()}
                
                req_start = time.monotonic()
                try:
                    resp = await client.request(
                        method=flow["method"],
                        url=p_url,
                        headers=p_headers,
                        content=p_body.encode(),
                    )
                    latency = int((time.monotonic() - req_start) * 1000)
                    body_text = resp.text
                    
                    return {
                        "payload": payload,
                        "status_code": resp.status_code,
                        "length": len(resp.content),
                        "latency_ms": latency,
                        "body_full": body_text,
                        "body_preview": body_text[:300],
                        "error": None
                    }
                except Exception as e:
                    return {
                        "payload": payload,
                        "status_code": 0,
                        "length": 0,
                        "latency_ms": int((time.monotonic() - req_start) * 1000),
                        "body_preview": "",
                        "error": str(e)
                    }

        # 3. Fuzzing execution & Anomaly Detection (Chunked to prevent OOM)
        anomalies = []
        network_errors = []
        sql_errors = [
            "syntax error", "mysql_fetch", "ora-", "postgresql", "sqlite3",
            "unclosed quotation", "unterminated", "sql syntax", "mysql_num_rows",
            "pg_query", "odbc_exec", "microsoft ole db", "jet database engine",
        ]

        chunk_size = 50
        for i in range(0, len(payloads), chunk_size):
            chunk = payloads[i:i + chunk_size]
            tasks = [_send_payload(p) for p in chunk]
            completed = await asyncio.gather(*tasks)

            for res in completed:
                if res["error"]:
                    network_errors.append({
                        "payload": res["payload"],
                        "error": res["error"],
                        "latency_ms": res["latency_ms"],
                    })
                    continue

                is_anomaly = False
                reasons = []

                # Rule 1: Status Code Change
                if res["status_code"] != avg_status:
                    is_anomaly = True
                    reasons.append(f"Status {res['status_code']} (baseline: {avg_status})")

                # Rule 2: Significant Length Difference
                if abs(res["length"] - avg_length) > length_threshold_diff:
                    is_anomaly = True
                    reasons.append(f"Length {res['length']} (baseline: ~{avg_length})")

                # Rule 3: Significant Latency (Time-based SQLi / DoS)
                if res["latency_ms"] > latency_threshold and res["latency_ms"] > 1000:
                    is_anomaly = True
                    reasons.append(f"Latency {res['latency_ms']}ms (baseline: ~{avg_latency}ms)")

                # Rule 4: Error Keywords — search FULL body, not just preview
                body_lower = res["body_full"].lower()
                found_errors = [err for err in sql_errors if err in body_lower]
                if found_errors:
                    is_anomaly = True
                    reasons.append(f"Error keywords: {', '.join(found_errors)}")

                # Strip full body before storing to save memory
                del res["body_full"]
                res["is_anomaly"] = is_anomaly
                res["anomaly_reasons"] = reasons
                
                if is_anomaly:
                    anomalies.append(res)

    # Build network error summary
    net_err_summary = {}
    if network_errors:
        net_err_summary = {
            "total": len(network_errors),
            "unique_errors": list(set(e["error"][:100] for e in network_errors))[:5],
            "first_failure_at": network_errors[0]["payload"],
            "samples": network_errors[:3],
        }

    return {
        "baseline": {
            "status_code": avg_status,
            "avg_length": int(avg_length),
            "avg_latency_ms": int(avg_latency)
        },
        "total_requests": len(payloads),
        "successful_requests": len(payloads) - len(network_errors),
        "anomalies_found": len(anomalies),
        "anomalies": anomalies,
        "network_errors": net_err_summary,
    }
