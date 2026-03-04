"""
VibeCrack Engine - AI Analyzer (Claude API)

Uses the Anthropic Claude API to generate:
1. A comprehensive security analysis (AI Summary)
2. An exploit testing playbook with EXECUTED verification commands and real output

Both outputs are stored on the scan document for the frontend to display.
"""

import json
import logging
import os
import socket
import ssl
import subprocess
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

import requests

# Lazy imports: anthropic and firebase_client may not be installed/available
_firebase_client = None

def _get_firebase():
    global _firebase_client
    if _firebase_client is None:
        from engine.orchestrator import firebase_client
        _firebase_client = firebase_client
    return _firebase_client

logger = logging.getLogger(__name__)

MODEL = "claude-haiku-4-5-20251001"
MAX_TOKENS = 8192

SYSTEM_PROMPT = """You are a senior cybersecurity analyst specialized in pentesting and web vulnerability analysis. You are analyzing the results of an automated VibeCrack scan.

The user is a developer with limited technical knowledge ("vibe coder") who needs clear and practical guidance.

Analyze the provided scan data and generate TWO text blocks, separated EXACTLY by the line:
---PLAYBOOK---

=== BLOCK 1: SECURITY ANALYSIS ===

Generate a complete Markdown report with these sections:

# Security Analysis - [domain]

## Executive Summary
2-3 paragraphs in SIMPLE language explaining the overall security situation. No unnecessary technical jargon.

## Score: [score]/100 (Grade [grade])
Explain what this score means in practice.

## Exposed Secrets and Credentials
COMPLETE LIST of ALL secrets, tokens, passwords, API keys found. For EACH one:
- **Type**: (API Key, Token, Password, etc.)
- **URL where it was found**: Exact URL
- **Value found**: The complete value of the secret/token as it appears in the scan
- **Risk**: What an attacker can do with this

If no secrets were found, say "No exposed secrets found."

## Top 5 Most Urgent Issues
For each one:
1. What the problem is (1 sentence)
2. Why it is dangerous (1 sentence)
3. How to fix it with READY-TO-USE code to copy and paste

## Analysis by Category
For each score category (SSL, Headers, Injection, etc.):
- Category score
- What was found
- Practical recommendation

## All Vulnerabilities
Complete list of ALL vulnerabilities found, organized by severity.

=== BLOCK 2: EXPLOIT PLAYBOOK (ALREADY EXECUTED) ===

The verification commands have ALREADY BEEN EXECUTED automatically. The real results are in the "proofResult" field of each vulnerability.

Generate a Markdown playbook that shows the REAL RESULTS:

# Exploit Playbook - [domain]

> WARNING: Use ONLY on applications you have AUTHORIZATION to test.

For EACH vulnerability that has "proofResult" (organize by severity):

### [SEVERITY] [title]
**URL**: [affected url]

**Command executed:**
```bash
[the command that was executed - proofResult.command field]
```

**ACTUAL result obtained:**
```
[the real command output - proofResult.output field]
```

**Result analysis:**
[Explain what this result PROVES about the vulnerability. Be specific about what is wrong in the response.]

**How to fix:**
[Ready-to-use code to fix]

---

For vulnerabilities WITHOUT proofResult, show the command that the user can run manually.

IMPORTANT: Focus on REAL results. Do not fabricate results. Use EXACTLY what is in proofResult.output."""


def generate_ai_analysis(scan_id: str, *, data_store=None) -> dict[str, str]:
    """Call Claude API to generate AI analysis and exploit playbook.

    Returns a dict with keys 'aiSummary' and 'exploitPlaybook'.
    """
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        raise RuntimeError("ANTHROPIC_API_KEY not set")

    # Gather all scan data
    scan_data = _gather_scan_data(scan_id, data_store=data_store)

    # Execute verification commands and attach real output
    logger.info("Executing verification commands for scan %s...", scan_id)
    domain = scan_data.get("domain", "")
    for vuln in scan_data.get("vulnerabilities", []):
        proof = _execute_proof(vuln, domain)
        if proof:
            vuln["proofResult"] = proof

    logger.info("Calling Claude API for scan %s analysis...", scan_id)

    import anthropic
    client = anthropic.Anthropic(api_key=api_key)

    message = client.messages.create(
        model=MODEL,
        max_tokens=MAX_TOKENS,
        system=SYSTEM_PROMPT,
        messages=[
            {
                "role": "user",
                "content": f"Here are the complete security scan data, including the REAL verification command results (proofResult field). Analyze everything and generate the report + playbook:\n\n```json\n{json.dumps(scan_data, indent=2, default=str, ensure_ascii=False)}\n```",
            }
        ],
    )

    response_text = message.content[0].text
    logger.info(
        "Claude API response received (%d chars, %d input tokens, %d output tokens)",
        len(response_text),
        message.usage.input_tokens,
        message.usage.output_tokens,
    )

    # Split response into two blocks
    if "---PLAYBOOK---" in response_text:
        parts = response_text.split("---PLAYBOOK---", 1)
        ai_summary = parts[0].strip()
        exploit_playbook = parts[1].strip()
    else:
        ai_summary = response_text
        exploit_playbook = ""

    return {
        "aiSummary": ai_summary,
        "exploitPlaybook": exploit_playbook,
    }


# ---------------------------------------------------------------------------
# Proof execution - runs safe verification commands for each vulnerability
# ---------------------------------------------------------------------------

def _execute_proof(vuln: dict, domain: str) -> dict[str, str] | None:
    """Execute a safe verification command for a vulnerability and return the output."""
    scanner = vuln.get("scanner", "")
    affected_url = vuln.get("affectedUrl", "")
    evidence = vuln.get("evidence", {})
    title = vuln.get("title", "")

    if not affected_url and not domain:
        return None

    try:
        if scanner == "headers_scanner":
            return _proof_headers(affected_url or domain)

        elif scanner == "ssl_scanner":
            return _proof_ssl(affected_url or domain)

        elif scanner == "directory_scanner":
            return _proof_directory(affected_url)

        elif scanner == "secrets_scanner":
            source_url = evidence.get("url", affected_url) if isinstance(evidence, dict) else affected_url
            return _proof_secrets(source_url, evidence)

        elif scanner == "endpoint_scanner":
            return _proof_endpoint(affected_url)

        elif scanner == "xss_scanner":
            payload_url = evidence.get("url", affected_url) if isinstance(evidence, dict) else affected_url
            return _proof_xss(payload_url, evidence)

        elif scanner == "recon_scanner":
            return _proof_recon(affected_url, title)

        elif scanner == "csrf_scanner":
            return _proof_csrf(affected_url)

        elif scanner == "subdomain_scanner":
            return _proof_subdomain(affected_url, title)

        elif scanner == "access_control_scanner":
            return _proof_endpoint(affected_url)

        elif scanner == "xss_browser_scanner":
            payload_url = evidence.get("url", affected_url) if isinstance(evidence, dict) else affected_url
            return _proof_xss(payload_url, evidence)

        elif scanner == "crawler":
            return None  # Crawler only produces info findings

    except Exception as e:
        logger.debug("Proof execution failed for %s: %s", scanner, e)
        return None

    return None


def _proof_headers(url: str) -> dict[str, str]:
    """Check response headers."""
    resp = requests.head(url, timeout=10, allow_redirects=True, verify=False)
    header_lines = [f"HTTP/{resp.raw.version / 10:.1f} {resp.status_code}"]
    for k, v in resp.headers.items():
        header_lines.append(f"{k}: {v}")
    output = "\n".join(header_lines)
    return {
        "command": f"curl -I -s {url}",
        "output": output[:2000],
    }


def _proof_ssl(url: str) -> dict[str, str]:
    """Check SSL certificate info."""
    parsed = urlparse(url)
    hostname = parsed.hostname or url.replace("https://", "").replace("http://", "").split("/")[0]
    port = parsed.port or 443

    ctx = ssl.create_default_context()
    with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
        s.settimeout(10)
        s.connect((hostname, port))
        cert = s.getpeercert()

    lines = []
    lines.append(f"Subject: {dict(x[0] for x in cert.get('subject', []))}")
    lines.append(f"Issuer: {dict(x[0] for x in cert.get('issuer', []))}")
    lines.append(f"Not Before: {cert.get('notBefore')}")
    lines.append(f"Not After: {cert.get('notAfter')}")
    lines.append(f"SANs: {[x[1] for x in cert.get('subjectAltName', [])]}")
    output = "\n".join(lines)

    return {
        "command": f"openssl s_client -connect {hostname}:{port} 2>/dev/null | openssl x509 -noout -text",
        "output": output[:2000],
    }


def _proof_directory(url: str) -> dict[str, str]:
    """Check if a file/directory is exposed."""
    resp = requests.get(url, timeout=10, allow_redirects=False, verify=False)
    status_line = f"HTTP {resp.status_code}"
    content_type = resp.headers.get("Content-Type", "unknown")
    body_snippet = resp.text[:500] if resp.text else "(empty)"
    output = f"{status_line}\nContent-Type: {content_type}\nContent-Length: {len(resp.content)}\n\n--- Body (first 500 chars) ---\n{body_snippet}"
    return {
        "command": f"curl -s {url}",
        "output": output[:2000],
    }


def _proof_secrets(source_url: str, evidence: dict) -> dict[str, str]:
    """Fetch the source where secrets were found."""
    if not source_url:
        return None
    resp = requests.get(source_url, timeout=10, verify=False)
    # Find relevant snippet around secret
    payload = evidence.get("payload", "") if isinstance(evidence, dict) else ""
    body = resp.text
    snippet = ""
    if payload and payload in body:
        idx = body.index(payload)
        start = max(0, idx - 100)
        end = min(len(body), idx + len(payload) + 100)
        snippet = f"...{body[start:end]}..."
    else:
        snippet = body[:500]

    return {
        "command": f"curl -s {source_url} | grep -i 'api_key\\|secret\\|token\\|password'",
        "output": snippet[:2000],
    }


def _proof_endpoint(url: str) -> dict[str, str]:
    """Check endpoint access without auth."""
    resp = requests.get(url, timeout=10, allow_redirects=False, verify=False)
    body_snippet = resp.text[:300] if resp.text else "(empty)"
    output = f"HTTP {resp.status_code}\nContent-Type: {resp.headers.get('Content-Type', 'unknown')}\n\n{body_snippet}"
    return {
        "command": f"curl -s -w '\\nHTTP_CODE: %{{http_code}}' {url}",
        "output": output[:2000],
    }


def _proof_xss(url: str, evidence: dict) -> dict[str, str]:
    """Verify XSS by checking if payload is reflected."""
    payload = evidence.get("payload", "") if isinstance(evidence, dict) else ""
    resp = requests.get(url, timeout=10, verify=False)
    reflected = "YES - PAYLOAD REFLECTED!" if payload and payload in resp.text else "Not reflected in this check"
    body_snippet = resp.text[:500]
    output = f"HTTP {resp.status_code}\nPayload reflected: {reflected}\n\n--- Response ---\n{body_snippet}"
    return {
        "command": f"curl -s \"{url}\"",
        "output": output[:2000],
    }


def _proof_recon(url: str, title: str) -> dict[str, str]:
    """Check recon findings (HTTP methods, cookies, etc.)."""
    if "cookie" in title.lower():
        resp = requests.get(url, timeout=10, verify=False)
        cookie_headers = [f"Set-Cookie: {v}" for k, v in resp.headers.items() if k.lower() == "set-cookie"]
        output = "\n".join(cookie_headers) if cookie_headers else "No Set-Cookie headers"
        return {
            "command": f"curl -I -s {url} | grep -i set-cookie",
            "output": output[:2000],
        }
    elif "method" in title.lower() or "OPTIONS" in title:
        resp = requests.options(url, timeout=10, verify=False)
        allow = resp.headers.get("Allow", "Not specified")
        output = f"HTTP {resp.status_code}\nAllow: {allow}"
        return {
            "command": f"curl -X OPTIONS -I -s {url}",
            "output": output[:2000],
        }
    return None


def _proof_csrf(url: str) -> dict[str, str]:
    """Check for CSRF tokens in forms."""
    resp = requests.get(url, timeout=10, verify=False)
    body_lower = resp.text.lower()
    has_csrf = any(t in body_lower for t in ["csrf", "_token", "authenticity_token"])
    cookie_headers = [f"Set-Cookie: {v}" for k, v in resp.headers.items() if k.lower() == "set-cookie"]
    output = f"HTTP {resp.status_code}\nCSRF token in HTML: {'YES' if has_csrf else 'NOT FOUND'}\n\nCookies:\n" + ("\n".join(cookie_headers) if cookie_headers else "No cookies")
    return {
        "command": f"curl -s {url} | grep -i 'csrf\\|_token'",
        "output": output[:2000],
    }


def _proof_subdomain(url: str, title: str) -> dict[str, str]:
    """Check subdomain resolution."""
    parsed = urlparse(url)
    hostname = parsed.hostname or url
    try:
        ip = socket.gethostbyname(hostname)
        try:
            resp = requests.get(url, timeout=10, verify=False, allow_redirects=True)
            output = f"DNS: {hostname} -> {ip}\nHTTP {resp.status_code}\nServer: {resp.headers.get('Server', 'unknown')}"
        except Exception:
            output = f"DNS: {hostname} -> {ip}\nHTTP: Connection failed"
    except socket.gaierror:
        output = f"DNS: {hostname} -> NXDOMAIN (does not resolve)"
    return {
        "command": f"dig +short {hostname} && curl -s -o /dev/null -w '%{{http_code}}' {url}",
        "output": output[:2000],
    }


# ---------------------------------------------------------------------------
# Firestore data gathering
# ---------------------------------------------------------------------------

def _gather_scan_data(scan_id: str, *, data_store=None) -> dict[str, Any]:
    """Read all relevant scan data for the AI analysis."""
    if data_store:
        combined = data_store.get_scan_with_vulns_and_score(scan_id)
        scan = combined
        vulns_raw = combined.get("vulnerabilities", [])
        score_data = combined.get("score_data") or None
    else:
        _fb = _get_firebase()
        _fb._ensure_db()
        db = _fb.db

        scan_doc = db.collection("scans").document(scan_id).get()
        if not scan_doc.exists:
            raise ValueError(f"Scan {scan_id} not found")
        scan = scan_doc.to_dict()

        vulns_raw = [
            doc.to_dict()
            for doc in db.collection("vulnerabilities")
            .where("scanId", "==", scan_id)
            .stream()
        ]

        scores = list(
            db.collection("scores_history")
            .where("scanId", "==", scan_id)
            .limit(1)
            .stream()
        )
        score_data = None
        if scores:
            sd = scores[0].to_dict()
            score_data = {
                "overallScore": sd.get("overallScore"),
                "grade": sd.get("grade"),
                "categories": sd.get("categories", {}),
            }

    # Sort by severity
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    vulns_raw.sort(key=lambda v: severity_order.get(v.get("severity", "info"), 5))

    # Simplify vulnerability data for the prompt
    vulns = []
    for v in vulns_raw:
        vulns.append({
            "severity": v.get("severity"),
            "title": v.get("title"),
            "description": v.get("description"),
            "scanner": v.get("scanner"),
            "affectedUrl": v.get("affectedUrl"),
            "evidence": v.get("evidence", {}),
            "remediation": v.get("remediation"),
            "owaspCategory": v.get("owaspCategory"),
            "cvssScore": v.get("cvssScore"),
        })

    return {
        "domain": scan.get("domain"),
        "scanType": scan.get("scanType"),
        "modules": scan.get("modules", []),
        "detectedTech": scan.get("detectedTech", []),
        "score": scan.get("score"),
        "grade": scan.get("grade"),
        "summary": scan.get("summary", {}),
        "scoreBreakdown": score_data,
        "totalVulnerabilities": len(vulns),
        "vulnerabilities": vulns,
    }
