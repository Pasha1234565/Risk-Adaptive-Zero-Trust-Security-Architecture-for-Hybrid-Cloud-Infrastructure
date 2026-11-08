#!/usr/bin/env python3
"""Build Literature and survey.pdf from Literature_and_survey.md using reportlab."""

import re
from pathlib import Path

from reportlab.lib.pagesizes import A4
from reportlab.lib.units import inch
from reportlab.lib.enums import TA_JUSTIFY, TA_CENTER
from reportlab.lib.colors import HexColor
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
    HRFlowable,
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

SRC = Path("Literature_and_survey.md")
OUT = Path("Literature and survey.pdf")

assert SRC.exists(), f"Missing source: {SRC}"

raw = SRC.read_text(encoding="utf-8")

styles = getSampleStyleSheet()

body_style = ParagraphStyle(
    "BodyJustified",
    parent=styles["Normal"],
    alignment=TA_JUSTIFY,
    fontName="Helvetica",
    fontSize=10.5,
    leading=15,
    spaceAfter=8,
)

heading1 = ParagraphStyle(
    "H1Custom",
    parent=styles["Heading1"],
    fontName="Helvetica-Bold",
    fontSize=16,
    textColor=HexColor("#1F3B5B"),
    spaceBefore=14,
    spaceAfter=8,
    alignment=TA_CENTER,
)

heading2 = ParagraphStyle(
    "H2Custom",
    parent=styles["Heading2"],
    fontName="Helvetica-Bold",
    fontSize=13,
    textColor=HexColor("#1F3B5B"),
    spaceBefore=12,
    spaceAfter=6,
)

heading3 = ParagraphStyle(
    "H3Custom",
    parent=styles["Heading3"],
    fontName="Helvetica-Bold",
    fontSize=11.5,
    textColor=HexColor("#244B6E"),
    spaceBefore=8,
    spaceAfter=4,
)

title_style = ParagraphStyle(
    "DocTitle",
    parent=styles["Title"],
    fontName="Helvetica-Bold",
    fontSize=20,
    textColor=HexColor("#1F3B5B"),
    spaceAfter=4,
    alignment=TA_CENTER,
)

subtitle_style = ParagraphStyle(
    "DocSubtitle",
    parent=styles["Normal"],
    fontName="Helvetica-Oblique",
    fontSize=11,
    textColor=HexColor("#555555"),
    spaceAfter=4,
    alignment=TA_CENTER,
)

quote_style = ParagraphStyle(
    "NoteQuote",
    parent=body_style,
    leftIndent=16,
    rightIndent=16,
    fontName="Helvetica-Oblique",
    textColor=HexColor("#444444"),
    borderColor=HexColor("#CCCCCC"),
    borderWidth=0,
    backColor=HexColor("#F6F6F6"),
    spaceBefore=4,
    spaceAfter=8,
)

bullet_style = ParagraphStyle(
    "BulletBody",
    parent=body_style,
    leftIndent=18,
    bulletIndent=6,
    spaceAfter=4,
)

table_cell_style = ParagraphStyle(
    "TableCell",
    parent=body_style,
    fontSize=8.5,
    leading=11,
    alignment=TA_JUSTIFY,
    spaceAfter=0,
)

table_header_style = ParagraphStyle(
    "TableHeader",
    parent=table_cell_style,
    fontName="Helvetica-Bold",
    textColor=colors.white,
    fontSize=9,
    leading=12,
)


def md_heading(line: str):
    m = re.match(r"^#{1,3}\s+(.*)$", line.strip())
    if not m:
        return None, line
    level = m.group(0).count("#")
    text = m.group(1).strip()
    if level == 1:
        return "h1", text
    if level == 2:
        return "h2", text
    return "h3", text


def md_ul(lines, start_idx):
    items = []
    idx = start_idx
    while idx < len(lines):
        ln = lines[idx]
        if ln.strip().startswith("- "):
            text = ln.strip()[2:].strip()
            items.append(text)
            idx += 1
            continue
        if ln.strip() == "":
            idx += 1
            continue
        break
    return idx, items


def build_flowables(lines):
    flowables = []
    i = 0
    in_table = False
    table_lines = []
    table_header_seen = False

    while i < len(lines):
        raw_line = lines[i]
        stripped = raw_line.strip()

        if stripped == "":
            i += 1
            continue

        if stripped.startswith("> "):
            note_text = stripped[2:].strip()
            flowables.append(Paragraph(note_text, quote_style))
            i += 1
            continue

        if stripped.startswith("|") and stripped.endswith("|"):
            if not in_table:
                in_table = True
                table_lines = []
                table_header_seen = False
            table_lines.append(stripped)
            i += 1
            continue

        if in_table:
            flowables.append(make_table_from_lines(table_lines))
            in_table = False
            table_lines = []

        if stripped.startswith("#"):
            kind, text = md_heading(raw_line)
            if kind == "h1":
                flowables.append(Paragraph(text, heading1))
            elif kind == "h2":
                flowables.append(Paragraph(text, heading2))
            elif kind == "h3":
                flowables.append(Paragraph(text, heading3))
            i += 1
            continue

        if stripped.startswith("- "):
            idx, items = md_ul(lines, i)
            for item in items:
                flowables.append(Paragraph(f"• {item}", bullet_style))
            i = idx
            continue

        normalized = stripped.replace("\n", " ").strip()
        if normalized:
            flowables.append(Paragraph(normalized, body_style))
        i += 1

    if in_table and table_lines:
        flowables.append(make_table_from_lines(table_lines))

    return flowables


def make_table_from_lines(tlines):
    rows = []
    for row in tlines:
        cells = [c.strip() for c in row.strip("|").split("|")]
        rows.append(cells)

    if not rows:
        return Spacer(1, 1)

    header = rows[0]
    data_rows = rows[1:]

    wrapped_header = [Paragraph(f'<b>{escape_for_rich_text(c)}</b>', table_header_style) for c in header]
    wrapped_rows = []
    for r in data_rows:
        wrapped_rows.append([Paragraph(escape_for_rich_text(c) if c else "", table_cell_style) for c in r])

    table_data = [wrapped_header] + wrapped_rows

    col_count = len(header)
    t = Table(table_data, repeatRows=1)
    t.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), HexColor("#1F3B5B")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.5, HexColor("#CCCCCC")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, HexColor("#EEF2F7")]),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    return t


def escape_for_rich_text(text: str) -> str:
    return (
        text
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace("\n", "<br/>")
    )


def build_pdf():
    out_path_str = str(OUT)
    doc = SimpleDocTemplate(
        out_path_str,
        pagesize=A4,
        topMargin=0.9 * inch,
        bottomMargin=0.9 * inch,
        leftMargin=0.9 * inch,
        rightMargin=0.9 * inch,
        title="Literature Survey and Requirement Analysis",
        author="Farhaan Pasha (R23EK009)",
    )

    lines = [ln for ln in raw.splitlines()]
    story = []

    # Front matter title from the first H1 in the file
    front_title_added = False
    for idx, line in enumerate(lines):
        kind, text = md_heading(line)
        if kind == "h1" and not front_title_added:
            story.append(Paragraph(text, title_style))
            story.append(HRFlowable(width="60%", thickness=1, color=HexColor("#1F3B5B")))
            story.append(Spacer(1, 6))
            front_title_added = True
            continue
        if kind == "h1":
            break
        if kind == "h2":
            break

    # Add subtitle lines if present before first heading
    if front_title_added:
        for line in lines:
            stripped = line.strip()
            if stripped.startswith("#"):
                break
            if stripped and not stripped.startswith(">") and not stripped.startswith("|"):
                story.append(Paragraph(stripped, subtitle_style))
                break

    story.extend(build_flowables(lines))
    doc.build(story)
    print(f"PDF written: {out_path_str}")


if __name__ == "__main__":
    build_pdf()
