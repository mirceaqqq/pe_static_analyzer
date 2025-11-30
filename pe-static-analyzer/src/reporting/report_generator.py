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

from src.core.analyzer import AnalysisResult


def _chart_images(result: AnalysisResult) -> Dict[str, str]:
    """
    Returnează imagini base64 (PNG) pentru entropie și VT pie (dacă matplotlib e disponibil).
    """
    if plt is None:
        return {}
    imgs = {}
    # Entropy bar chart
    sections = [s["name"] for s in result.sections if s.get("name")]
    entropies = [s.get("entropy", 0) for s in result.sections if s.get("name")]
    if sections and entropies:
        fig, ax = plt.subplots(figsize=(4, 2.5))
        ax.bar(sections[:15], entropies[:15], color="#3b82f6")
        ax.set_ylabel("Entropie")
        ax.set_xticklabels(sections[:15], rotation=45, ha="right")
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


def generate_pdf_report(result: AnalysisResult, path: str):
    """
    PDF simplu cu reportlab + grafice (daca matplotlib e prezent).
    """
    c = canvas.Canvas(path, pagesize=A4)
    width, height = A4
    c.setFont("Helvetica-Bold", 14)
    c.drawString(2 * cm, height - 2 * cm, "PE Static Analyzer - Raport")
    c.setFont("Helvetica", 10)
    c.drawString(2 * cm, height - 3 * cm, f"Fisier: {result.file_path}")
    c.drawString(2 * cm, height - 3.6 * cm, f"Risc: {result.risk_level} ({result.suspicion_score:.1f}/100)")
    vt_ratio = result.vt_report.get("detection_ratio", "-") if result.vt_report else "-"
    c.drawString(2 * cm, height - 4.2 * cm, f"VT: {vt_ratio}")
    c.drawString(2 * cm, height - 4.8 * cm, f"Packer: {result.packer_detected or '-'}")
    c.drawString(2 * cm, height - 5.4 * cm, f"Semnatura: {'Valid' if result.signatures.get('verified') else 'Unknown/Unsigned'}")

    imgs = _chart_images(result)
    y = height - 7 * cm
    if imgs.get("entropy"):
        entropy_bytes = base64.b64decode(imgs["entropy"])
        entropy_path = Path("temp") / "charts_entropy.png"
        entropy_path.parent.mkdir(parents=True, exist_ok=True)
        entropy_path.write_bytes(entropy_bytes)
        c.drawImage(str(entropy_path), 2 * cm, y, width=10 * cm, preserveAspectRatio=True, mask='auto')
        y -= 8 * cm
    if imgs.get("vt"):
        vt_bytes = base64.b64decode(imgs["vt"])
        vt_path = Path("temp") / "charts_vt.png"
        vt_path.write_bytes(vt_bytes)
        c.drawImage(str(vt_path), 2 * cm, y, width=6 * cm, preserveAspectRatio=True, mask='auto')
    c.showPage()
    c.save()
