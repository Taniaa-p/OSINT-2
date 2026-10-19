"""Convert the report .docx to PDF without Word: mammoth (docx -> HTML) + headless Chrome."""
import subprocess
import sys
from pathlib import Path

import mammoth

ROOT = Path(__file__).resolve().parent.parent
DOCX = ROOT / "docs" / "OSINT_Visualization_Platform_Report.docx"
HTML = ROOT / "docs" / "_report_print.html"
PDF = ROOT / "docs" / "OSINT_Visualization_Platform_Report.pdf"
CHROME = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
CSS = """
@page { size: A4; margin: 18mm 16mm; }
body { font-family: 'Times New Roman', serif; font-size: 11pt; line-height: 1.4; color: #000; }
h1 { font-size: 17pt; margin: 20px 0 8px; page-break-after: avoid; }
h2 { font-size: 13pt; margin: 14px 0 6px; page-break-after: avoid; }
p { margin: 0 0 6px; text-align: justify; }
table { border-collapse: collapse; width: 100%; margin: 4px 0 10px; font-size: 8.5pt; page-break-inside: auto; }
td, th { border: 1px solid #777; padding: 3px 5px; vertical-align: top; text-align: left; }
tr:first-child td { background: #d9e2f3; font-weight: bold; }
img { max-width: 100%; display: block; margin: 6px auto 2px; page-break-inside: avoid; }
ul { margin: 2px 0 6px 18px; padding: 0; } li { margin-bottom: 2px; }
.title { page-break-after: always; padding-top: 170px; }
.title p { text-align: center; font-size: 13pt; margin-bottom: 10px; }
.title p:nth-child(1) { font-size: 26pt; font-weight: bold; margin-bottom: 14px; }
.title p:nth-child(2) { font-size: 14pt; margin-bottom: 60px; }
.title p:nth-child(3) { font-size: 19pt; }
.title p:nth-child(4) { margin-bottom: 50px; }
td p { text-align: left; margin: 0; }
p em { }
"""

with open(DOCX, "rb") as f:
    body = mammoth.convert_to_html(f).value
# first block up to the TOC heading is the title page
body = body.replace("<p><strong>Table of Contents</strong></p>",
                    "</div><p><strong>Table of Contents</strong></p>", 1)
body = body.replace("<h1>Abstract</h1>", '<h1 style="page-break-before:always">Abstract</h1>', 1)
HTML.write_text(f"<!doctype html><html><head><meta charset='utf-8'><style>{CSS}</style></head>"
                f"<body><div class='title'>{body}</body></html>", encoding="utf-8")
subprocess.run([CHROME, "--headless=new", "--disable-gpu", "--no-pdf-header-footer",
                f"--print-to-pdf={PDF}", HTML.as_uri()], check=True, capture_output=True)
HTML.unlink()
print("wrote", PDF)
