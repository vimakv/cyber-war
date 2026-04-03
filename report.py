from fpdf import FPDF
from datetime import datetime
import os

def generate_report(url, res):
    pdf = FPDF()
    pdf.add_page()

    # LOGO
    if os.path.exists("logo.png"):
        pdf.image("logo.png", x=10, y=8, w=30)

    pdf.set_font("Arial", "B", 16)
    pdf.cell(0, 10, "Cyber War Report", ln=True, align="C")

    pdf.ln(10)

    pdf.set_font("Arial", size=12)
    pdf.cell(0, 8, f"Date: {datetime.now()}", ln=True)
    pdf.multi_cell(0, 8, f"URL: {url}")

    pdf.ln(5)

    for k, v in res.items():
        if "Safe" in v:
            pdf.set_text_color(0,200,0)
        else:
            pdf.set_text_color(255,0,0)

        pdf.multi_cell(0,8,f"{k}: {v}")
        pdf.set_text_color(0,0,0)

    pdf.output("scan_report.pdf")

    # HTML REPORT
    html = f"<h1>Cyber War Report</h1><p>{url}</p>"
    for k,v in res.items():
        color="green" if "Safe" in v else "red"
        html += f"<p style='color:{color}'>{k}: {v}</p>"

    with open("scan_report.html","w") as f:
        f.write(html)