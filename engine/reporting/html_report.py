"""
VibeCrack - Self-contained HTML Report Generator

Produces a single .html file with embedded CSS. No external dependencies.
"""

from datetime import datetime, timezone
from html import escape

SEVERITY_COLORS = {
    "critical": "#dc2626",
    "high": "#ef4444",
    "medium": "#f97316",
    "low": "#eab308",
    "info": "#3b82f6",
}

GRADE_COLORS = {
    "A+": "#16a34a",
    "A": "#22c55e",
    "B": "#eab308",
    "C": "#f97316",
    "D": "#ef4444",
    "F": "#dc2626",
}

CATEGORY_LABELS = {
    "ssl_tls": "SSL / TLS",
    "headers": "Security Headers",
    "injection": "Injection",
    "authentication": "Authentication",
    "secrets_exposure": "Secrets Exposure",
    "configuration": "Configuration",
    "information_disclosure": "Info Disclosure",
}


def generate_html_report(data_store, scan_id: str) -> str:
    """Generate a self-contained HTML report string."""
    scan = data_store.get_scan_data(scan_id)
    findings = data_store.get_vulnerabilities(scan_id)
    score_data = data_store.get_score(scan_id) or {}

    domain = escape(scan.get("domain", "Unknown"))
    scan_type = escape(scan.get("scanType", "full"))
    overall_score = score_data.get("overallScore", 0)
    grade = score_data.get("grade", "?")
    categories = score_data.get("categories", {})
    summary = scan.get("summary", {})
    detected_tech = scan.get("detectedTech", [])
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    # Sort findings
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda f: sev_order.get(f.get("severity", "info"), 5))

    grade_color = GRADE_COLORS.get(grade, "#888")

    # Build category rows
    cat_rows = ""
    for key, data in categories.items():
        label = CATEGORY_LABELS.get(key, key)
        cat_grade = data.get("grade", "?")
        cat_score = data.get("score", 0)
        cat_color = GRADE_COLORS.get(cat_grade, "#888")
        cat_rows += f"""
        <tr>
            <td>{escape(label)}</td>
            <td style="text-align:right">{cat_score}</td>
            <td style="text-align:center;color:{cat_color};font-weight:bold">{cat_grade}</td>
        </tr>"""

    # Build findings HTML
    findings_html = ""
    for f in findings:
        sev = f.get("severity", "info")
        color = SEVERITY_COLORS.get(sev, "#888")
        title = escape(f.get("title", ""))
        desc = escape(f.get("description", ""))
        url = escape(f.get("affectedUrl", ""))
        scanner = escape(f.get("scanner", ""))
        remediation = escape(f.get("remediation", ""))
        evidence = f.get("evidence", {})
        if isinstance(evidence, dict):
            evidence_text = escape(evidence.get("detail", str(evidence)))
        else:
            evidence_text = escape(str(evidence))

        findings_html += f"""
        <div class="finding">
            <div class="finding-header">
                <span class="severity-badge" style="background:{color}">{sev.upper()}</span>
                <span class="finding-title">{title}</span>
                <span class="scanner-badge">{scanner}</span>
            </div>
            {f'<div class="finding-url">{url}</div>' if url else ''}
            <div class="finding-desc">{desc}</div>
            {f'<div class="finding-evidence"><strong>Evidence:</strong><pre>{evidence_text}</pre></div>' if evidence_text and evidence_text != '{}' else ''}
            {f'<div class="finding-remediation"><strong>Remediation:</strong> {remediation}</div>' if remediation else ''}
        </div>"""

    # Build tech badges
    tech_html = ""
    for t in detected_tech:
        tech_html += f'<span class="tech-badge">{escape(t)}</span> '

    # Summary counts
    crit = summary.get("critical", 0)
    high = summary.get("high", 0)
    med = summary.get("medium", 0)
    low = summary.get("low", 0)
    info = summary.get("info", 0)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>VibeCrack Report - {domain}</title>
<style>
:root {{
    --bg: #0f0f23;
    --surface: #1a1a2e;
    --surface2: #16213e;
    --text: #e0e0e0;
    --text-dim: #888;
    --accent: #a855f7;
    --border: #2a2a4a;
}}
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    background: var(--bg);
    color: var(--text);
    line-height: 1.6;
    padding: 2rem;
    max-width: 960px;
    margin: 0 auto;
}}
h1 {{ color: var(--accent); font-size: 1.8rem; margin-bottom: 0.5rem; }}
h2 {{ color: var(--accent); font-size: 1.3rem; margin: 2rem 0 1rem; border-bottom: 1px solid var(--border); padding-bottom: 0.5rem; }}
.header {{ text-align: center; margin-bottom: 2rem; }}
.header .domain {{ font-size: 1.2rem; color: var(--text-dim); }}
.header .timestamp {{ font-size: 0.85rem; color: var(--text-dim); margin-top: 0.25rem; }}
.score-card {{
    background: var(--surface);
    border-radius: 12px;
    padding: 2rem;
    text-align: center;
    margin: 1.5rem 0;
    border: 1px solid var(--border);
}}
.score-number {{ font-size: 3.5rem; font-weight: 800; color: {grade_color}; }}
.score-grade {{ font-size: 1.5rem; color: {grade_color}; font-weight: 700; }}
.summary-bar {{
    display: flex;
    gap: 1rem;
    justify-content: center;
    flex-wrap: wrap;
    margin: 1rem 0;
}}
.summary-item {{
    background: var(--surface2);
    border-radius: 8px;
    padding: 0.5rem 1rem;
    text-align: center;
    min-width: 80px;
}}
.summary-item .count {{ font-size: 1.5rem; font-weight: 700; }}
.summary-item .label {{ font-size: 0.75rem; text-transform: uppercase; color: var(--text-dim); }}
table {{
    width: 100%;
    border-collapse: collapse;
    background: var(--surface);
    border-radius: 8px;
    overflow: hidden;
}}
th, td {{ padding: 0.75rem 1rem; text-align: left; border-bottom: 1px solid var(--border); }}
th {{ background: var(--surface2); font-weight: 600; font-size: 0.85rem; text-transform: uppercase; color: var(--text-dim); }}
.finding {{
    background: var(--surface);
    border-radius: 8px;
    padding: 1rem 1.25rem;
    margin-bottom: 0.75rem;
    border: 1px solid var(--border);
}}
.finding-header {{ display: flex; align-items: center; gap: 0.75rem; flex-wrap: wrap; }}
.severity-badge {{
    display: inline-block;
    padding: 0.2rem 0.6rem;
    border-radius: 4px;
    font-size: 0.7rem;
    font-weight: 700;
    color: #fff;
    text-transform: uppercase;
    letter-spacing: 0.05em;
}}
.finding-title {{ font-weight: 600; flex: 1; }}
.scanner-badge {{
    background: var(--surface2);
    padding: 0.15rem 0.5rem;
    border-radius: 4px;
    font-size: 0.75rem;
    color: var(--text-dim);
}}
.finding-url {{ font-size: 0.85rem; color: var(--accent); margin-top: 0.4rem; word-break: break-all; }}
.finding-desc {{ margin-top: 0.5rem; font-size: 0.9rem; color: var(--text-dim); }}
.finding-evidence {{ margin-top: 0.5rem; font-size: 0.85rem; }}
.finding-evidence pre {{
    background: var(--bg);
    padding: 0.5rem;
    border-radius: 4px;
    overflow-x: auto;
    font-size: 0.8rem;
    margin-top: 0.25rem;
    max-height: 150px;
}}
.finding-remediation {{ margin-top: 0.5rem; font-size: 0.85rem; color: #22c55e; }}
.tech-badge {{
    display: inline-block;
    background: var(--surface2);
    padding: 0.2rem 0.6rem;
    border-radius: 4px;
    font-size: 0.8rem;
    margin: 0.2rem;
}}
.cta {{
    text-align: center;
    margin-top: 3rem;
    padding: 1.5rem;
    background: var(--surface);
    border-radius: 12px;
    border: 1px solid var(--accent);
}}
.cta a {{ color: var(--accent); text-decoration: none; font-weight: 700; }}
.cta a:hover {{ text-decoration: underline; }}
</style>
</head>
<body>

<div class="header">
    <h1>VibeCrack Security Report</h1>
    <div class="domain">{domain}</div>
    <div class="timestamp">{scan_type.capitalize()} scan - {timestamp}</div>
</div>

<div class="score-card">
    <div class="score-number">{overall_score}</div>
    <div class="score-grade">Grade: {grade}</div>
</div>

<div class="summary-bar">
    <div class="summary-item"><div class="count" style="color:{SEVERITY_COLORS['critical']}">{crit}</div><div class="label">Critical</div></div>
    <div class="summary-item"><div class="count" style="color:{SEVERITY_COLORS['high']}">{high}</div><div class="label">High</div></div>
    <div class="summary-item"><div class="count" style="color:{SEVERITY_COLORS['medium']}">{med}</div><div class="label">Medium</div></div>
    <div class="summary-item"><div class="count" style="color:{SEVERITY_COLORS['low']}">{low}</div><div class="label">Low</div></div>
    <div class="summary-item"><div class="count" style="color:{SEVERITY_COLORS['info']}">{info}</div><div class="label">Info</div></div>
</div>

{f'<h2>Detected Technologies</h2><p>{tech_html}</p>' if tech_html else ''}

<h2>Score Breakdown</h2>
<table>
    <thead><tr><th>Category</th><th style="text-align:right">Score</th><th style="text-align:center">Grade</th></tr></thead>
    <tbody>{cat_rows}</tbody>
</table>

<h2>Findings ({len(findings)})</h2>
{findings_html if findings_html else '<p style="color:var(--text-dim)">No vulnerabilities found.</p>'}

<div class="cta">
    <p>Want dashboards, scan history, and team features?</p>
    <p><a href="https://vibecrack.com">Try VibeCrack Cloud &rarr;</a></p>
</div>

<p style="text-align:center;color:var(--text-dim);margin-top:2rem;font-size:0.8rem;">
    Generated by VibeCrack v0.1.0 - Open Source Security Scanner
</p>

</body>
</html>"""
