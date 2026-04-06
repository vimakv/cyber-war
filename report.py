from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
import datetime

def generate_report(url, result):

    doc = SimpleDocTemplate("report.pdf")
    styles = getSampleStyleSheet()

    content = []

    # ================= TITLE =================
    content.append(Paragraph("Vulnerability Scan Report", styles["Title"]))
    content.append(Spacer(1, 10))

    # ================= META =================
    content.append(Paragraph(f"<b>Target URL:</b> {url}", styles["Normal"]))
    content.append(Paragraph(
        f"<b>Scan Time:</b> {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        styles["Normal"]
    ))
    content.append(Spacer(1, 15))

    # ================= RESULTS =================
    content.append(Paragraph("<b>Scan Results:</b>", styles["Heading2"]))
    content.append(Spacer(1, 10))

    for key, value in result.items():

        if isinstance(value, dict):
            status = value.get("status", "Unknown")
            reason = value.get("reason", "")

            line = f"<b>{key}:</b> {status}"

            if reason:
                line += f" - {reason}"

            content.append(Paragraph(line, styles["Normal"]))

        elif key == "AI":
            content.append(Spacer(1, 10))
            content.append(Paragraph("<b>AI Analysis:</b>", styles["Heading3"]))
            content.append(Spacer(1, 5))
            content.append(Paragraph(value, styles["Normal"]))

        else:
            content.append(Paragraph(f"<b>{key}:</b> {value}", styles["Normal"]))

        content.append(Spacer(1, 8))

    # ================= SUMMARY =================
    content.append(Spacer(1, 15))
    content.append(Paragraph("<b>Security Summary:</b>", styles["Heading2"]))
    content.append(Spacer(1, 10))

    summary = "Ensure proper input validation, secure coding practices, and proper security headers configuration."
    content.append(Paragraph(summary, styles["Normal"]))

    # ================= BUILD =================
    doc.build(content)