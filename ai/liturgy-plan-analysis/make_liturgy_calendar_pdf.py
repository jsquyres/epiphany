#!/usr/bin/env python3

import argparse
import calendar
import json
from collections import defaultdict
from datetime import date, timedelta

from reportlab.lib import colors
from reportlab.lib.pagesizes import landscape, letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)


PAGE_SIZE = landscape(letter)
WEEKDAY_LABELS = ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"]

MUSIC_COLOR = colors.HexColor("#cfeecf")
NO_MUSIC_COLOR = colors.HexColor("#f8d9ad")
EMPTY_DAY_COLOR = colors.white
OUTSIDE_MONTH_COLOR = colors.HexColor("#eeeeee")
GRID_COLOR = colors.HexColor("#707070")
HEADER_COLOR = colors.HexColor("#e2e8f0")


def parse_args():
    parser = argparse.ArgumentParser(
        description="Create a landscape monthly calendar PDF from liturgy-plan-analysis.json."
    )
    parser.add_argument(
        "--input",
        default="liturgy-plan-analysis.json",
        help="Input liturgy-plan-analysis JSON file",
    )
    parser.add_argument(
        "--output",
        default="liturgy-plan-calendar.pdf",
        help="Output PDF file",
    )
    return parser.parse_args()


def parse_iso_date(value):
    if not isinstance(value, str) or len(value) < 10:
        return None
    try:
        return date.fromisoformat(value[:10])
    except ValueError:
        return None


def plan_has_music(plan):
    music = (plan.get("analysis") or {}).get("music")
    return isinstance(music, list) and len(music) > 0


def plan_liturgy_dates(plan):
    analysis = plan.get("analysis") or {}
    dates = set()

    for value in analysis.get("liturgy_dates") or []:
        parsed = parse_iso_date(value)
        if parsed:
            dates.add(parsed)

    liturgy_date = parse_iso_date(analysis.get("liturgy_date"))
    if liturgy_date:
        dates.add(liturgy_date)

        if analysis.get("date_scope") == "weekend":
            saturday = liturgy_date - timedelta(days=1)
            if saturday.weekday() == 5:
                dates.add(saturday)

    return dates


def shared_weekend_dates(plan, plan_dates):
    analysis = plan.get("analysis") or {}
    if analysis.get("date_scope") != "weekend":
        return set()

    shared_dates = set()
    for liturgy_date in plan_dates:
        if liturgy_date.weekday() == 6:
            saturday = liturgy_date - timedelta(days=1)
            if saturday in plan_dates:
                shared_dates.update({saturday, liturgy_date})
        elif liturgy_date.weekday() == 5:
            sunday = liturgy_date + timedelta(days=1)
            if sunday in plan_dates:
                shared_dates.update({liturgy_date, sunday})
    return shared_dates


def collect_calendar_data(data):
    by_date = defaultdict(lambda: {"with_music": 0, "without_music": 0, "plans": []})
    by_month_plans = defaultdict(lambda: {"with_music": 0, "without_music": 0, "total": 0})

    for plan in data.get("plans", []):
        analysis = plan.get("analysis") or {}
        if analysis.get("is_liturgy_plan") is not True:
            continue

        has_music = plan_has_music(plan)
        primary_date = parse_iso_date(analysis.get("liturgy_date"))
        plan_dates = plan_liturgy_dates(plan)
        if not primary_date and plan_dates:
            primary_date = min(plan_dates)

        if primary_date:
            month_key = (primary_date.year, primary_date.month)
            by_month_plans[month_key]["total"] += 1
            if has_music:
                by_month_plans[month_key]["with_music"] += 1
            else:
                by_month_plans[month_key]["without_music"] += 1

        shared_dates = shared_weekend_dates(plan, plan_dates)

        for liturgy_date in plan_dates:
            entry = by_date[liturgy_date]
            entry["plans"].append(plan)
            if liturgy_date in shared_dates:
                entry["shared_weekend"] = True
            if has_music:
                entry["with_music"] += 1
            else:
                entry["without_music"] += 1

    return by_date, by_month_plans


def month_date_counts(year, month, by_date):
    with_music = 0
    without_music = 0

    for liturgy_date, entry in by_date.items():
        if liturgy_date.year != year or liturgy_date.month != month:
            continue
        if entry["with_music"] > 0:
            with_music += 1
        else:
            without_music += 1

    return {
        "with_music": with_music,
        "without_music": without_music,
        "total": with_music + without_music,
    }


def day_background(liturgy_date, by_date):
    if liturgy_date not in by_date:
        return EMPTY_DAY_COLOR
    if by_date[liturgy_date]["with_music"] > 0:
        return MUSIC_COLOR
    return NO_MUSIC_COLOR


def make_year_page(year, months, by_month_plans, styles):
    story = [
        Spacer(1, 0.45 * inch),
        Paragraph(str(year), styles["YearTitle"]),
        Spacer(1, 0.25 * inch),
    ]

    table_data = [["Month", "With music", "Without music", "Total"]]
    for month in months:
        counts = by_month_plans[(year, month)]
        table_data.append([
            calendar.month_name[month],
            counts["with_music"],
            counts["without_music"],
            counts["total"],
        ])

    row_count = len(table_data)
    available_table_height = PAGE_SIZE[1] - 2.2 * inch
    row_height = min(0.34 * inch, available_table_height / row_count)
    table = Table(
        table_data,
        colWidths=[2.4 * inch, 1.5 * inch, 1.5 * inch, 1.2 * inch],
        rowHeights=[row_height] * row_count,
        hAlign="CENTER",
    )
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), HEADER_COLOR),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("ALIGN", (1, 0), (-1, -1), "RIGHT"),
        ("GRID", (0, 0), (-1, -1), 0.5, GRID_COLOR),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f7f7f7")]),
        ("FONTSIZE", (0, 0), (-1, -1), 12),
        ("LEADING", (0, 0), (-1, -1), 14),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(table)
    story.append(PageBreak())
    return story


def month_weeks(year, month):
    cal = calendar.Calendar(firstweekday=6)
    return cal.monthdatescalendar(year, month)


def day_cell_content(liturgy_date, month, by_date, styles):
    if liturgy_date.month != month:
        return ""

    parts = [Paragraph(str(liturgy_date.day), styles["DayNumber"])]
    entry = by_date.get(liturgy_date, {})
    labels = []
    if len(entry.get("plans") or []) > 1:
        labels.append("Multiple")
    if entry.get("shared_weekend"):
        labels.append("Sat/Sun")
    if labels:
        label_text = " / ".join(labels)
        parts.append(Paragraph(label_text, styles["DayLabel"]))
    return parts


def make_month_page(year, month, by_date, styles):
    month_name = calendar.month_name[month]
    counts = month_date_counts(year, month, by_date)

    story = [
        Paragraph(f"{month_name} {year}", styles["MonthTitle"]),
        Paragraph(
            (
                f"{counts['total']} dates with liturgy plans "
                f"({counts['with_music']} with music, {counts['without_music']} without music)"
            ),
            styles["MonthSubtitle"],
        ),
        Spacer(1, 0.15 * inch),
    ]

    table_data = [WEEKDAY_LABELS]
    weeks = month_weeks(year, month)
    for week in weeks:
        row = []
        for liturgy_date in week:
            row.append(day_cell_content(liturgy_date, month, by_date, styles))
        table_data.append(row)

    available_width = PAGE_SIZE[0] - 0.7 * inch
    available_height = PAGE_SIZE[1] - 1.65 * inch
    header_height = 0.35 * inch
    cell_size = min(available_width / 7, (available_height - header_height) / len(weeks))

    table = Table(
        table_data,
        colWidths=[cell_size] * 7,
        rowHeights=[header_height] + [cell_size] * len(weeks),
        hAlign="CENTER",
    )

    style = TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), HEADER_COLOR),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("ALIGN", (0, 0), (-1, 0), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("GRID", (0, 0), (-1, -1), 0.75, GRID_COLOR),
        ("FONTSIZE", (0, 0), (-1, 0), 11),
        ("LEFTPADDING", (0, 1), (-1, -1), 8),
        ("TOPPADDING", (0, 1), (-1, -1), 8),
    ])

    for row_index, week in enumerate(weeks, start=1):
        for col_index, liturgy_date in enumerate(week):
            if liturgy_date.month != month:
                background = OUTSIDE_MONTH_COLOR
            else:
                background = day_background(liturgy_date, by_date)
            style.add("BACKGROUND", (col_index, row_index), (col_index, row_index), background)

    table.setStyle(style)
    story.append(table)
    story.append(PageBreak())
    return story


def build_pdf(input_file, output_file):
    with open(input_file) as f:
        data = json.load(f)

    by_date, by_month_plans = collect_calendar_data(data)
    months = sorted({(liturgy_date.year, liturgy_date.month) for liturgy_date in by_date})
    months_by_year = defaultdict(list)
    for year, month in months:
        months_by_year[year].append(month)

    stylesheet = getSampleStyleSheet()
    styles = {
        "YearTitle": ParagraphStyle(
            "YearTitle",
            parent=stylesheet["Title"],
            fontName="Helvetica-Bold",
            fontSize=66,
            leading=74,
            alignment=1,
        ),
        "MonthTitle": ParagraphStyle(
            "MonthTitle",
            parent=stylesheet["Title"],
            fontName="Helvetica-Bold",
            fontSize=32,
            leading=38,
            alignment=1,
            spaceAfter=4,
        ),
        "MonthSubtitle": ParagraphStyle(
            "MonthSubtitle",
            parent=stylesheet["Normal"],
            fontName="Helvetica",
            fontSize=14,
            leading=18,
            alignment=1,
        ),
        "DayNumber": ParagraphStyle(
            "DayNumber",
            parent=stylesheet["Normal"],
            fontName="Helvetica-Bold",
            fontSize=30,
            leading=32,
            textColor=colors.black,
            spaceAfter=2,
        ),
        "DayLabel": ParagraphStyle(
            "DayLabel",
            parent=stylesheet["Normal"],
            fontName="Helvetica-Bold",
            fontSize=8,
            leading=7,
            textColor=colors.black,
            spaceBefore=0,
            spaceAfter=0,
        ),
    }

    story = []
    for year in sorted(months_by_year):
        story.extend(make_year_page(year, months_by_year[year], by_month_plans, styles))
        for month in months_by_year[year]:
            story.extend(make_month_page(year, month, by_date, styles))

    if story and isinstance(story[-1], PageBreak):
        story.pop()

    doc = SimpleDocTemplate(
        output_file,
        pagesize=PAGE_SIZE,
        rightMargin=0.35 * inch,
        leftMargin=0.35 * inch,
        topMargin=0.25 * inch,
        bottomMargin=0.25 * inch,
    )
    doc.build(story)

    return len(months), len(months_by_year), len(by_date)


def main():
    args = parse_args()
    month_count, year_count, date_count = build_pdf(args.input, args.output)
    print(
        f"Wrote {args.output} with {year_count} year title pages, "
        f"{month_count} month pages, and {date_count} liturgy-plan dates."
    )


if __name__ == "__main__":
    main()
