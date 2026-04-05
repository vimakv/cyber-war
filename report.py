from fpdf import FPDF
from datetime import datetime

def generate_report(url, result):

    pdf = FPDF()
    pdf.add_page()

    pdf.set_font("Arial", "B", 16)
    pdf.cell(200, 10, "Cyber War Scan Report", ln=True, align="C")

    pdf.ln(10)

    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, f"Date: {datetime.now()}", ln=True)
    pdf.cell(200, 10, f"URL: {url}", ln=True)

    pdf.ln(10)

    for k, v in result.items():

        # 🎨 COLOR
        if "Vulnerable" in v:
            pdf.set_text_color(255, 0, 0)   # RED
        elif "Safe" in v:
            pdf.set_text_color(0, 150, 0)   # GREEN
        else:
            pdf.set_text_color(255, 165, 0) # ORANGE

        pdf.cell(200, 10, f"{k}: {v}", ln=True)

    pdf.output("scan_report.pdf")

    # -------- HTML REPORT --------
    html = f"""
    <h2>Cyber War Report</h2>
    <p><b>URL:</b> {url}</p>
    <p><b>Date:</b> {datetime.now()}</p>
    """

    for k,v in result.items():
        html += f"<p><b>{k}</b>: {v}</p>"

    with open("scan_report.html","w") as f:
        f.write(html)