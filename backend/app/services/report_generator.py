"""Report generator service – exports professional PDF, CSV, and JSON scan reports."""
import io
import json
import csv
from datetime import datetime
from typing import Dict, Any, List

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, HRFlowable
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT


def generate_scan_pdf(scan_data: Dict[str, Any], account_data: Dict[str, Any], findings: List[Dict[str, Any]]) -> bytes:
    """Generates a professional PDF assessment report."""
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=40,
        leftMargin=40,
        topMargin=40,
        bottomMargin=40,
    )

    styles = getSampleStyleSheet()
    
    # Custom styles
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=24,
        textColor=colors.HexColor('#0B1220'),
        spaceAfter=8,
        alignment=TA_LEFT,
    )
    subtitle_style = ParagraphStyle(
        'DocSubtitle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=12,
        textColor=colors.HexColor('#475569'),
        spaceAfter=15,
        alignment=TA_LEFT,
    )
    h2_style = ParagraphStyle(
        'Heading2',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=14,
        textColor=colors.HexColor('#1E293B'),
        spaceBefore=12,
        spaceAfter=6,
    )
    body_style = ParagraphStyle(
        'Body',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9,
        textColor=colors.HexColor('#334155'),
        leading=12,
    )
    cell_bold = ParagraphStyle(
        'CellBold',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=8,
        textColor=colors.HexColor('#0F172A'),
        leading=10,
    )
    cell_text = ParagraphStyle(
        'CellText',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=8,
        textColor=colors.HexColor('#334155'),
        leading=10,
    )

    story = []

    # Title Banner
    story.append(Paragraph("CloudShield Security Posture Assessment Report", title_style))
    story.append(Paragraph("Risk-Prioritised Cloud Misconfiguration & CIS Benchmark Audit", subtitle_style))
    story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor('#3B82F6'), spaceAfter=15))

    # Meta Table
    score = round(scan_data.get("account_risk_score", 0), 1)
    status_color = colors.HexColor('#DC2626') if score >= 70 else (colors.HexColor('#EA580C') if score >= 50 else (colors.HexColor('#CA8A04') if score >= 20 else colors.HexColor('#16A34A')))
    
    meta_info = [
        [Paragraph("<b>Target Account:</b>", cell_bold), Paragraph(str(account_data.get("name")), cell_text),
         Paragraph("<b>Assessment Date:</b>", cell_bold), Paragraph(datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"), cell_text)],
        [Paragraph("<b>Provider & Region:</b>", cell_bold), Paragraph(f"{account_data.get('provider', 'aws').upper()} ({account_data.get('region', 'us-east-1')})", cell_text),
         Paragraph("<b>Scan ID:</b>", cell_bold), Paragraph(f"#{scan_data.get('id')}", cell_text)],
        [Paragraph("<b>Account Risk Score:</b>", cell_bold), Paragraph(f"<b><font color='{status_color.hexval()}'>{score} / 100</font></b>", cell_bold),
         Paragraph("<b>Total Resources Evaluated:</b>", cell_bold), Paragraph(str(scan_data.get("total_resources", 0)), cell_text)],
    ]
    t_meta = Table(meta_info, colWidths=[130, 130, 130, 140])
    t_meta.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#F8FAFC')),
        ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor('#CBD5E1')),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#E2E8F0')),
        ('TOPPADDING', (0, 0), (-1, -1), 5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
    ]))
    story.append(t_meta)
    story.append(Spacer(1, 15))

    # Executive Summary & Severity Counts
    story.append(Paragraph("Executive Summary", h2_style))
    
    crit = sum(1 for f in findings if f.get("severity") == 5 or f.get("band") == "critical")
    high = sum(1 for f in findings if f.get("severity") == 4 or f.get("band") == "high")
    med = sum(1 for f in findings if f.get("severity") == 3 or f.get("band") == "medium")
    low = sum(1 for f in findings if f.get("severity", 0) <= 2 or f.get("band") == "low")
    
    sev_table_data = [
        [
            Paragraph("<b>Critical Risks</b>", cell_bold),
            Paragraph("<b>High Risks</b>", cell_bold),
            Paragraph("<b>Medium Risks</b>", cell_bold),
            Paragraph("<b>Low Risks</b>", cell_bold),
            Paragraph("<b>Total Findings</b>", cell_bold),
        ],
        [
            Paragraph(f"<font color='#DC2626'><b>{crit}</b></font>", ParagraphStyle('C', parent=cell_bold, fontSize=14, alignment=TA_CENTER)),
            Paragraph(f"<font color='#EA580C'><b>{high}</b></font>", ParagraphStyle('H', parent=cell_bold, fontSize=14, alignment=TA_CENTER)),
            Paragraph(f"<font color='#CA8A04'><b>{med}</b></font>", ParagraphStyle('M', parent=cell_bold, fontSize=14, alignment=TA_CENTER)),
            Paragraph(f"<font color='#2563EB'><b>{low}</b></font>", ParagraphStyle('L', parent=cell_bold, fontSize=14, alignment=TA_CENTER)),
            Paragraph(f"<b>{len(findings)}</b>", ParagraphStyle('T', parent=cell_bold, fontSize=14, alignment=TA_CENTER)),
        ]
    ]
    t_sev = Table(sev_table_data, colWidths=[105, 105, 105, 105, 110])
    t_sev.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#0F172A')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor('#94A3B8')),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#E2E8F0')),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
    ]))
    story.append(t_sev)
    story.append(Spacer(1, 15))

    # Prioritised Findings Table
    story.append(Paragraph("Risk-Prioritised Findings (Top Action Items)", h2_style))
    story.append(Paragraph("Ranked by Risk Score (Severity × Exposure × Data Sensitivity):", body_style))
    story.append(Spacer(1, 6))

    sorted_findings = sorted(findings, key=lambda x: x.get("risk_score", 0), reverse=True)

    findings_table_data = [
        [
            Paragraph("<b>Score</b>", cell_bold),
            Paragraph("<b>Band</b>", cell_bold),
            Paragraph("<b>Control</b>", cell_bold),
            Paragraph("<b>Finding & Resource</b>", cell_bold),
            Paragraph("<b>Remediation</b>", cell_bold),
        ]
    ]

    for f in sorted_findings[:25]:
        score_val = f.get("risk_score", 0)
        band_str = str(f.get("band", "medium")).upper()
        band_col = '#DC2626' if band_str == 'CRITICAL' else ('#EA580C' if band_str == 'HIGH' else ('#CA8A04' if band_str == 'MEDIUM' else '#2563EB'))
        
        findings_table_data.append([
            Paragraph(f"<b>{score_val}</b>", cell_bold),
            Paragraph(f"<font color='{band_col}'><b>{band_str}</b></font>", cell_bold),
            Paragraph(str(f.get("cis_control", f.get("check_id"))), cell_text),
            Paragraph(f"<b>{f.get('title')}</b><br/><font color='#64748B'>{f.get('resource_id')}</font>", cell_text),
            Paragraph(str(f.get("remediation", "Review IAM/Security configuration."))[:140] + ("..." if len(str(f.get("remediation", ""))) > 140 else ""), cell_text),
        ])

    t_findings = Table(findings_table_data, colWidths=[40, 55, 65, 200, 170])
    t_findings.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1E293B')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor('#94A3B8')),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#E2E8F0')),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
    ]))
    story.append(t_findings)

    doc.build(story)
    return buffer.getvalue()


def generate_scan_csv(findings: List[Dict[str, Any]]) -> str:
    """Generates CSV format of all findings."""
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "ID", "Check ID", "Title", "Category", "Resource ID", "Resource Type",
        "Region", "Severity", "Exposure", "Data Sensitivity", "Risk Score",
        "Band", "CIS Control", "Status", "Remediation", "CLI Fix"
    ])
    for f in findings:
        writer.writerow([
            f.get("id"),
            f.get("check_id"),
            f.get("title"),
            f.get("category"),
            f.get("resource_id"),
            f.get("resource_type"),
            f.get("region"),
            f.get("severity"),
            f.get("exposure"),
            f.get("data_sensitivity"),
            f.get("risk_score"),
            f.get("band"),
            f.get("cis_control"),
            f.get("status"),
            f.get("remediation"),
            f.get("cli_fix"),
        ])
    return output.getvalue()
