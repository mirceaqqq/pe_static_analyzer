import base64
import io
from pathlib import Path
from typing import Dict, Any

try:
    import matplotlib.pyplot as plt
except Exception:
    plt = None

from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from reportlab.lib.units import cm
from reportlab.lib import colors
from reportlab.lib.styles import ParagraphStyle
from reportlab.platypus import Paragraph
from reportlab.lib.enums import TA_LEFT

from src.core.analyzer import AnalysisResult


def _chart_images(result: AnalysisResult) -> Dict[str, str]:
    if plt is None:
        return {}
    imgs = {}
    # Entropy bar chart
    sections = [s["name"] for s in result.sections if s.get("name")]
    entropies = [s.get("entropy", 0) for s in result.sections if s.get("name")]
    if sections and entropies:
        fig, ax = plt.subplots(figsize=(5, 2.5))
        ax.bar(sections[:15], entropies[:15], color="#3b82f6")
        ax.set_ylabel("Entropie")
        ax.set_xticklabels(sections[:15], rotation=45, ha="right", fontsize=8)
        ax.set_ylim(0, 8)
        buf = io.BytesIO()
        fig.tight_layout()
        fig.savefig(buf, format="png")
        plt.close(fig)
        buf.seek(0)
        imgs["entropy"] = base64.b64encode(buf.read()).decode()
    # VT pie
    stats = result.vt_report.get("stats", {}) if result.vt_report else {}
    if stats:
        fig, ax = plt.subplots(figsize=(3, 3))
        labels = list(stats.keys())
        values = list(stats.values())
        ax.pie(values, labels=labels, autopct="%1.0f%%")
        buf = io.BytesIO()
        fig.tight_layout()
        fig.savefig(buf, format="png")
        plt.close(fig)
        buf.seek(0)
        imgs["vt"] = base64.b64encode(buf.read()).decode()
    return imgs


def generate_html_report(result: AnalysisResult, path: str):
    imgs = _chart_images(result)
    vt_ratio = result.vt_report.get("detection_ratio", "-") if result.vt_report else "-"
    packer = result.packer_detected or "-"
    signed = result.signatures.get("verified") if result.signatures else False
    signed_txt = "Valid" if signed else ("Unsigned" if result.signatures else "Unknown")
    sections_rows = "".join(
        f"<tr><td>{s.get('name','')}</td><td>{s.get('virtual_address','')}</td><td>{s.get('entropy','')}</td><td>{s.get('characteristics','')}</td></tr>"
        for s in result.sections
    )
    hashes_rows = "".join(f"<tr><td>{k}</td><td>{v}</td></tr>" for k, v in result.file_hash.items())
    entropy_img = f"<img src='data:image/png;base64,{imgs.get('entropy')}' style='max-width:100%;'/>" if imgs.get("entropy") else "<i>fara graf</i>"
    vt_img = f"<img src='data:image/png;base64,{imgs.get('vt')}' style='max-width:250px;'/>" if imgs.get("vt") else "<i>fara graf</i>"
    html = f"""
    <html>
    <head>
        <meta charset="utf-8"/>
        <style>
        body {{ font-family: Arial, sans-serif; background: #0f172a; color: #e2e8f0; padding: 20px; }}
        h1, h2 {{ color: #a5b4fc; }}
        table {{ width: 100%; border-collapse: collapse; margin: 10px 0; }}
        th, td {{ border: 1px solid #1f2937; padding: 8px; }}
        th {{ background: #1f2937; }}
        .card {{ background: #111827; padding: 12px; border-radius: 8px; margin-bottom: 12px; }}
        </style>
    </head>
    <body>
        <h1>PE Static Analyzer - Raport</h1>
        <div class="card">
            <strong>Fisier:</strong> {result.file_path}<br/>
            <strong>Risc:</strong> {result.risk_level} ({result.suspicion_score:.1f}/100)<br/>
            <strong>VT:</strong> {vt_ratio}<br/>
            <strong>Packer:</strong> {packer}<br/>
            <strong>Semnatura:</strong> {signed_txt}<br/>
            <strong>Durata:</strong> {result.analysis_duration:.2f}s
        </div>
        <h2>Hash-uri</h2>
        <table><tr><th>Tip</th><th>Valoare</th></tr>{hashes_rows}</table>
        <h2>Sectiuni</h2>
        <table><tr><th>Nume</th><th>VA</th><th>Entropie</th><th>Caracteristici</th></tr>{sections_rows}</table>
        <h2>Entropie (chart)</h2>
        {entropy_img}
        <h2>VirusTotal</h2>
        {vt_img}
    </body>
    </html>
    """
    Path(path).write_text(html, encoding="utf-8")


def _draw_paragraph(c, text: str, x: float, y: float, width: float):
    style = ParagraphStyle(
        "normal",
        fontName="Helvetica",
        fontSize=10,
        textColor=colors.white,
        alignment=TA_LEFT,
        leading=12,
    )
    p = Paragraph(text, style)
    _, h = p.wrap(width, 1000)
    p.drawOn(c, x, y - h)
    return h


def generate_pdf_report(result: AnalysisResult, path: str):
    c = canvas.Canvas(path, pagesize=A4)
    width, height = A4
    margin = 2 * cm

    c.setFillColor(colors.HexColor("#0f172a"))
    c.rect(0, 0, width, height, fill=1, stroke=0)
    c.setFillColor(colors.white)

    # Header
    c.setFont("Helvetica-Bold", 16)
    c.drawString(margin, height - margin, "PE Static Analyzer - Raport")

    c.setFont("Helvetica", 10)
    vt_ratio = result.vt_report.get("detection_ratio", "-") if result.vt_report else "-"
    signer = result.signatures.get("signer", "Unknown") if result.signatures else "Unknown"
    verified = result.signatures.get("verified") if result.signatures else False
    signer_text = f"Semnatura: {'Valid' if verified else 'Invalid/Unsigned'} ({signer})"

    summary_lines = [
        f"Fisier: {result.file_path}",
        f"Risc: {result.risk_level} ({result.suspicion_score:.1f}/100)",
        f"VT: {vt_ratio}",
        f"Packer: {result.packer_detected or '-'}",
        signer_text,
        f"Durata analiza: {result.analysis_duration:.2f}s",
    ]
    y = height - margin - 20
    for line in summary_lines:
        c.drawString(margin, y, line)
        y -= 14

    imgs = _chart_images(result)
    next_y = y - 10
    if imgs.get("entropy"):
        entropy_bytes = base64.b64decode(imgs["entropy"])
        entropy_path = Path("temp") / "charts_entropy.png"
        entropy_path.parent.mkdir(parents=True, exist_ok=True)
        entropy_path.write_bytes(entropy_bytes)
        c.drawImage(str(entropy_path), margin, next_y - 140, width=240, preserveAspectRatio=True, mask='auto')
    if imgs.get("vt"):
        vt_bytes = base64.b64decode(imgs["vt"])
        vt_path = Path("temp") / "charts_vt.png"
        vt_path.write_bytes(vt_bytes)
        c.drawImage(str(vt_path), margin + 260, next_y - 140, width=140, preserveAspectRatio=True, mask='auto')
    next_y -= 150

    # Risk breakdown + anomalies + heuristics
    items = ["Context despre risc:"]
    if result.scoring_breakdown:
        items.append("De ce este riscant:")
        items.extend([f"- {b}" for b in result.scoring_breakdown[:8]])
    if result.anomalies:
        items.append("Anomalii detectate (pot indica packer/obfuscation):")
        items.extend([f"- {a}" for a in result.anomalies[:8]])
    if result.heuristic_flags:
        items.append("Flag-uri heuristice (comportamente suspecte):")
        items.extend([f"- {h}" for h in result.heuristic_flags[:8]])
    if result.yara_matches:
        items.append("Potriviri YARA (semnaturi malware/packers):")
        items.extend([f"- {m.get('rule','')} ({m.get('namespace','')})" for m in result.yara_matches[:8]])
    _draw_paragraph(c, "<br/>".join(items), margin, next_y, width - 2 * margin)
    next_y -= 140

    # Hashes short
    hash_lines = [f"{k}: {v}" for k, v in list(result.file_hash.items())[:6]]
    c.setFont("Helvetica-Bold", 11)
    c.drawString(margin, next_y, "Hash-uri")
    c.setFont("Helvetica", 9)
    hy = next_y - 12
    for hl in hash_lines:
        c.drawString(margin, hy, hl)
        hy -= 12
    next_y = hy - 10

    # Sections (first 6)
    c.setFont("Helvetica-Bold", 11)
    c.drawString(margin, next_y, "Sectiuni")
    c.setFont("Helvetica", 9)
    sy = next_y - 12
    for sec in result.sections[:6]:
        rwx = "RWX" if sec.get("executable") and sec.get("writable") else "RX" if sec.get("executable") else "R"
        line = f"{sec.get('name','')} VA:{sec.get('virtual_address','')} Ent:{sec.get('entropy','')} Perm:{rwx}"
        c.drawString(margin, sy, line)
        sy -= 12

    # VT stats text
    if result.vt_report:
        stats = result.vt_report.get("stats", {})
        if stats:
            sy -= 6
            c.setFont("Helvetica-Bold", 11)
            c.drawString(margin, sy, "VT stats")
            sy -= 12
            c.setFont("Helvetica", 9)
            for k, v in stats.items():
                c.drawString(margin, sy, f"{k}: {v}")
                sy -= 12

    # Extra storytelling about the file
    story = [
        "Interpretare rapida:",
        "- Daca VT raporteaza pozitivi si exista flag-uri heuristice/entropie mare, creste sansele de malware pack-uit.",
        "- Anomaliile (overlay, RWX, timestamp suspect) pot indica tampering sau packer.",
        "- Semnatura valida reduce riscul, dar daca lipseste sau e invalida, scorul ramane ridicat.",
        "- Potrivirile YARA arata posibile familii sau packere, verifica manual regulile pentru context.",
    ]
    _draw_paragraph(c, "<br/>".join(story), margin, sy - 20, width - 2 * margin)

    c.showPage()
    c.save()
