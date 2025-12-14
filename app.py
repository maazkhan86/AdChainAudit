from __future__ import annotations

import csv
import io
from datetime import datetime

import streamlit as st

from analyzer import parse_ads_txt, analyze, to_report_json


def build_text_report(summary: dict, issues: list[dict], max_examples: int = 5) -> str:
    """Human-readable report for non-technical users."""
    lines: list[str] = []
    lines.append("AdChainAudit Report")
    lines.append("=" * 60)
    lines.append(f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC")
    lines.append("")

    totals = summary.get("totals", {})
    rels = summary.get("relationships", {})
    lines.append("Summary")
    lines.append("-" * 60)
    lines.append(f"Entries parsed: {totals.get('entries', 0)}")
    lines.append(f"DIRECT: {rels.get('DIRECT', 0)}")
    lines.append(f"RESELLER: {rels.get('RESELLER', 0)}")
    lines.append(f"Missing CAID entries: {summary.get('missing_caid_entries', 0)}")
    lines.append(f"Relationship ambiguity pairs: {summary.get('relationship_ambiguity_pairs', 0)}")
    lines.append(f"Risk score (0-100): {summary.get('risk_score_0_100', 0)}")
    lines.append("")

    lines.append("Potential red flags")
    lines.append("-" * 60)
    if not issues:
        lines.append("No red flags detected with the current rule set.")
        return "\n".join(lines)

    for idx, issue in enumerate(issues, start=1):
        sev = issue.get("severity", "")
        title = issue.get("title", "")
        detail = issue.get("detail", "")
        examples = issue.get("examples", [])[:max_examples]

        lines.append(f"{idx}. [{sev}] {title}")
        lines.append(f"   {detail}")

        if examples:
            lines.append("   Examples:")
            for e in examples:
                ln = e.get("line_no", "?")
                raw = (e.get("raw", "") or "").rstrip("\n")
                lines.append(f"   - L{ln}: {raw}")
        lines.append("")

    return "\n".join(lines)


def build_csv_issues(issues: list[dict], max_examples: int = 3) -> str:
    """CSV of issues (one row per issue) for Excel / buyers / procurement."""
    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow(["severity", "title", "detail", "example_lines"])
    for issue in issues:
        sev = issue.get("severity", "")
        title = issue.get("title", "")
        detail = issue.get("detail", "")
        examples = issue.get("examples", [])[:max_examples]
        example_lines = " | ".join(
            [f"L{e.get('line_no','?')}: {(e.get('raw','') or '').strip()}" for e in examples]
        )
        writer.writerow([sev, title, detail, example_lines])

    return output.getvalue()


def build_pdf_report(summary: dict, issues: list[dict], max_examples: int = 4) -> bytes | None:
    """
    Generates a simple PDF in-memory.
    Returns PDF bytes if reportlab is available, else None.
    """
    try:
        from reportlab
