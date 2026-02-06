"""
HackerPA Engine - PDF Report Generator

Generates two types of reports:
1. Executive Report (CEO level) - Risk overview, financial impact, overall score
2. Technical Report (Dev level) - Detailed vulnerabilities, evidence, remediation code

Uses ReportLab for PDF generation.
"""

import io
import logging
from datetime import datetime, timezone
from typing import Any

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm, cm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
    HRFlowable,
)

from engine.orchestrator import firebase_client

logger = logging.getLogger(__name__)

# Color mapping
SEVERITY_COLORS = {
    "critical": colors.HexColor("#dc2626"),
    "high": colors.HexColor("#ef4444"),
    "medium": colors.HexColor("#f97316"),
    "low": colors.HexColor("#eab308"),
    "info": colors.HexColor("#3b82f6"),
}

GRADE_COLORS = {
    "A+": colors.HexColor("#22c55e"),
    "A": colors.HexColor("#22c55e"),
    "B": colors.HexColor("#84cc16"),
    "C": colors.HexColor("#eab308"),
    "D": colors.HexColor("#f97316"),
    "F": colors.HexColor("#ef4444"),
}


def _build_styles() -> dict[str, ParagraphStyle]:
    """Create custom paragraph styles for the report."""
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle(
            "CustomTitle", parent=base["Title"],
            fontSize=24, spaceAfter=12, textColor=colors.HexColor("#111827"),
        ),
        "h1": ParagraphStyle(
            "CustomH1", parent=base["Heading1"],
            fontSize=18, spaceBefore=20, spaceAfter=8,
            textColor=colors.HexColor("#111827"),
        ),
        "h2": ParagraphStyle(
            "CustomH2", parent=base["Heading2"],
            fontSize=14, spaceBefore=14, spaceAfter=6,
            textColor=colors.HexColor("#374151"),
        ),
        "body": ParagraphStyle(
            "CustomBody", parent=base["Normal"],
            fontSize=10, spaceAfter=6, leading=14,
            textColor=colors.HexColor("#4b5563"),
        ),
        "small": ParagraphStyle(
            "CustomSmall", parent=base["Normal"],
            fontSize=8, textColor=colors.HexColor("#9ca3af"),
        ),
        "code": ParagraphStyle(
            "CustomCode", parent=base["Code"],
            fontSize=8, leading=10, backColor=colors.HexColor("#f3f4f6"),
            textColor=colors.HexColor("#1f2937"),
            leftIndent=10, rightIndent=10,
            spaceBefore=4, spaceAfter=4,
        ),
        "severity_critical": ParagraphStyle(
            "SevCritical", parent=base["Normal"],
            fontSize=10, textColor=SEVERITY_COLORS["critical"], fontName="Helvetica-Bold",
        ),
        "severity_high": ParagraphStyle(
            "SevHigh", parent=base["Normal"],
            fontSize=10, textColor=SEVERITY_COLORS["high"], fontName="Helvetica-Bold",
        ),
        "severity_medium": ParagraphStyle(
            "SevMedium", parent=base["Normal"],
            fontSize=10, textColor=SEVERITY_COLORS["medium"], fontName="Helvetica-Bold",
        ),
        "severity_low": ParagraphStyle(
            "SevLow", parent=base["Normal"],
            fontSize=10, textColor=SEVERITY_COLORS["low"],
        ),
        "severity_info": ParagraphStyle(
            "SevInfo", parent=base["Normal"],
            fontSize=10, textColor=SEVERITY_COLORS["info"],
        ),
    }


def generate_report(scan_id: str, report_type: str = "full") -> bytes:
    """Generate a PDF report for a scan.

    Args:
        scan_id: Firestore scan document ID
        report_type: "executive" (CEO), "technical" (dev), or "full" (both)

    Returns:
        PDF file content as bytes
    """
    firebase_client._ensure_db()
    db = firebase_client.db

    # Fetch data
    scan_doc = db.collection("scans").document(scan_id).get()
    if not scan_doc.exists:
        raise ValueError(f"Scan {scan_id} not found")
    scan = scan_doc.to_dict()

    vulns = [
        doc.to_dict()
        for doc in db.collection("vulnerabilities")
        .where("scanId", "==", scan_id)
        .stream()
    ]

    # Sort by severity
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    vulns.sort(key=lambda v: severity_order.get(v.get("severity", "info"), 5))

    # Fetch score
    scores = list(
        db.collection("scores_history")
        .where("scanId", "==", scan_id)
        .limit(1)
        .stream()
    )
    score_data = scores[0].to_dict() if scores else None

    # Build PDF
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer, pagesize=A4,
        leftMargin=2 * cm, rightMargin=2 * cm,
        topMargin=2 * cm, bottomMargin=2 * cm,
    )

    styles = _build_styles()
    elements = []

    # Cover page
    elements.extend(_build_cover(scan, score_data, styles))
    elements.append(PageBreak())

    if report_type in ("executive", "full"):
        elements.extend(_build_executive_section(scan, vulns, score_data, styles))
        if report_type == "full":
            elements.append(PageBreak())

    if report_type in ("technical", "full"):
        elements.extend(_build_technical_section(scan, vulns, score_data, styles))

    # Footer info
    elements.append(Spacer(1, 20))
    elements.append(HRFlowable(width="100%", color=colors.HexColor("#e5e7eb")))
    elements.append(Spacer(1, 8))
    elements.append(Paragraph(
        f"Gerado por HackerPA Security Scanner em {datetime.now(timezone.utc).strftime('%d/%m/%Y %H:%M UTC')}",
        styles["small"],
    ))

    doc.build(elements)
    return buffer.getvalue()


def _build_cover(scan: dict, score_data: dict | None, styles: dict) -> list:
    """Build the cover page."""
    elements = []
    elements.append(Spacer(1, 60))
    elements.append(Paragraph("HackerPA", styles["title"]))
    elements.append(Paragraph("Relatorio de Seguranca", styles["h1"]))
    elements.append(Spacer(1, 20))

    # Target info
    info_data = [
        ["Dominio:", scan.get("domain", "--")],
        ["Tipo de Scan:", scan.get("scanType", "full").upper()],
        ["Status:", scan.get("status", "--").upper()],
        ["Data:", datetime.now(timezone.utc).strftime("%d/%m/%Y")],
    ]

    if score_data:
        info_data.append(["Score:", f"{score_data.get('overallScore', '--')}/100"])
        info_data.append(["Grau:", score_data.get("grade", "--")])

    info_table = Table(info_data, colWidths=[100, 300])
    info_table.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 11),
        ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor("#6b7280")),
        ("TEXTCOLOR", (1, 0), (1, -1), colors.HexColor("#111827")),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]))
    elements.append(info_table)

    # Summary counts
    summary = scan.get("summary", {})
    elements.append(Spacer(1, 30))
    elements.append(Paragraph("Resumo de Vulnerabilidades", styles["h2"]))

    summary_data = [
        ["Severidade", "Quantidade"],
        ["CRITICO", str(summary.get("critical", 0))],
        ["ALTO", str(summary.get("high", 0))],
        ["MEDIO", str(summary.get("medium", 0))],
        ["BAIXO", str(summary.get("low", 0))],
        ["INFO", str(summary.get("info", 0))],
    ]
    summary_table = Table(summary_data, colWidths=[200, 100])
    summary_table.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f3f4f6")),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e5e7eb")),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("TEXTCOLOR", (0, 1), (0, 1), SEVERITY_COLORS["critical"]),
        ("TEXTCOLOR", (0, 2), (0, 2), SEVERITY_COLORS["high"]),
        ("TEXTCOLOR", (0, 3), (0, 3), SEVERITY_COLORS["medium"]),
        ("TEXTCOLOR", (0, 4), (0, 4), SEVERITY_COLORS["low"]),
        ("TEXTCOLOR", (0, 5), (0, 5), SEVERITY_COLORS["info"]),
    ]))
    elements.append(summary_table)

    return elements


def _build_executive_section(scan: dict, vulns: list, score_data: dict | None, styles: dict) -> list:
    """Build the executive (CEO) section - high level risk overview."""
    elements = []
    elements.append(Paragraph("Relatorio Executivo", styles["title"]))
    elements.append(HRFlowable(width="100%", color=colors.HexColor("#10b981")))
    elements.append(Spacer(1, 12))

    # Overall assessment
    score = score_data.get("overallScore", 0) if score_data else 0
    grade = score_data.get("grade", "F") if score_data else "F"

    if score >= 90:
        assessment = "A aplicacao apresenta um nivel EXCELENTE de seguranca. Poucas melhorias necessarias."
    elif score >= 70:
        assessment = "A aplicacao apresenta um nivel BOM de seguranca, mas existem pontos de melhoria importantes."
    elif score >= 50:
        assessment = "A aplicacao apresenta vulnerabilidades MODERADAS que precisam de atencao. Risco operacional medio."
    elif score >= 30:
        assessment = "A aplicacao apresenta vulnerabilidades GRAVES. Risco alto de comprometimento. Acao imediata necessaria."
    else:
        assessment = "A aplicacao esta CRITICAMENTE vulneravel. Risco iminente de comprometimento. Acao URGENTE necessaria."

    elements.append(Paragraph("Avaliacao Geral", styles["h1"]))
    elements.append(Paragraph(f"Score: {score}/100 (Grau {grade})", styles["h2"]))
    elements.append(Paragraph(assessment, styles["body"]))
    elements.append(Spacer(1, 12))

    # Risk categories
    if score_data and "categories" in score_data:
        elements.append(Paragraph("Scores por Categoria", styles["h1"]))
        cat_labels = {
            "ssl_tls": "SSL/TLS",
            "headers": "Security Headers",
            "injection": "Protecao contra Injecao",
            "authentication": "Autenticacao",
            "secrets_exposure": "Exposicao de Secrets",
            "configuration": "Configuracao",
            "information_disclosure": "Divulgacao de Informacoes",
        }
        cat_data = [["Categoria", "Score", "Grau"]]
        for cat, data in score_data["categories"].items():
            cat_data.append([
                cat_labels.get(cat, cat),
                f"{data['score']}/100",
                data["grade"],
            ])
        cat_table = Table(cat_data, colWidths=[250, 80, 80])
        cat_table.setStyle(TableStyle([
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f3f4f6")),
            ("FONTSIZE", (0, 0), (-1, -1), 10),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e5e7eb")),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
        ]))
        elements.append(cat_table)
        elements.append(Spacer(1, 12))

    # Top risks
    critical_vulns = [v for v in vulns if v.get("severity") == "critical"]
    high_vulns = [v for v in vulns if v.get("severity") == "high"]

    if critical_vulns or high_vulns:
        elements.append(Paragraph("Riscos Prioritarios", styles["h1"]))
        elements.append(Paragraph(
            "Os seguintes problemas requerem atencao imediata:",
            styles["body"],
        ))

        for vuln in (critical_vulns + high_vulns)[:10]:
            sev = vuln.get("severity", "info").upper()
            sev_style = styles.get(f"severity_{vuln.get('severity', 'info')}", styles["body"])
            elements.append(Paragraph(f"[{sev}] {vuln.get('title', 'N/A')}", sev_style))
            elements.append(Paragraph(vuln.get("description", "")[:300], styles["body"]))
            elements.append(Spacer(1, 4))

    return elements


def _build_technical_section(scan: dict, vulns: list, score_data: dict | None, styles: dict) -> list:
    """Build the technical (Dev) section - detailed findings with remediation."""
    elements = []
    elements.append(Paragraph("Relatorio Tecnico", styles["title"]))
    elements.append(HRFlowable(width="100%", color=colors.HexColor("#3b82f6")))
    elements.append(Spacer(1, 12))

    elements.append(Paragraph(
        f"Total de vulnerabilidades encontradas: {len(vulns)}",
        styles["body"],
    ))
    elements.append(Spacer(1, 12))

    # Each vulnerability in detail
    for i, vuln in enumerate(vulns, 1):
        severity = vuln.get("severity", "info")
        sev_style = styles.get(f"severity_{severity}", styles["body"])

        elements.append(Paragraph(
            f"{i}. [{severity.upper()}] {vuln.get('title', 'N/A')}",
            sev_style,
        ))
        elements.append(Spacer(1, 4))

        # Description
        elements.append(Paragraph(
            f"<b>Descricao:</b> {vuln.get('description', 'N/A')}",
            styles["body"],
        ))

        # Affected URL
        affected = vuln.get("affectedUrl", "")
        if affected:
            elements.append(Paragraph(
                f"<b>URL Afetada:</b> {affected}",
                styles["body"],
            ))

        # Scanner & OWASP
        scanner = vuln.get("scanner", "")
        owasp = vuln.get("owaspCategory", "")
        cvss = vuln.get("cvssScore", 0)
        meta = []
        if scanner:
            meta.append(f"Scanner: {scanner}")
        if owasp:
            meta.append(f"OWASP: {owasp}")
        if cvss:
            meta.append(f"CVSS: {cvss}")
        if meta:
            elements.append(Paragraph(" | ".join(meta), styles["small"]))

        # Evidence
        evidence = vuln.get("evidence", {})
        if isinstance(evidence, dict):
            ev_parts = []
            if evidence.get("payload"):
                ev_parts.append(f"Payload: {evidence['payload']}")
            if evidence.get("response_snippet"):
                ev_parts.append(f"Resposta: {str(evidence['response_snippet'])[:200]}")
            if ev_parts:
                elements.append(Spacer(1, 4))
                elements.append(Paragraph("<b>Evidencia:</b>", styles["body"]))
                for part in ev_parts:
                    elements.append(Paragraph(part, styles["code"]))

        # Remediation
        remediation = vuln.get("remediation", "")
        if remediation:
            elements.append(Spacer(1, 4))
            elements.append(Paragraph("<b>Como Corrigir:</b>", styles["body"]))
            for line in remediation.split("\n"):
                if line.strip():
                    elements.append(Paragraph(line.strip(), styles["body"]))

        elements.append(Spacer(1, 8))
        elements.append(HRFlowable(width="100%", color=colors.HexColor("#f3f4f6")))
        elements.append(Spacer(1, 8))

    return elements


def generate_and_upload(scan_id: str, report_type: str = "full") -> str:
    """Generate a PDF report and upload it to Firebase Storage.

    Returns the Storage download URL.
    """
    from firebase_admin import storage as fb_storage

    pdf_bytes = generate_report(scan_id, report_type)

    # Upload to Firebase Storage
    bucket = fb_storage.bucket()
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    blob_path = f"reports/{scan_id}/{report_type}_{timestamp}.pdf"
    blob = bucket.blob(blob_path)
    blob.upload_from_string(pdf_bytes, content_type="application/pdf")
    blob.make_public()

    logger.info("PDF report uploaded to %s", blob.public_url)
    return blob.public_url
