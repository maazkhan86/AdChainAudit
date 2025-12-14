from __future__ import annotations

import csv
import io
from datetime import datetime

import streamlit as st

from analyzer import parse_ads_txt, analyze, to_report_json


# ----------------- helpers: exports -----------------

def build_text_report(summary: dict, issues: list[dict], max_examples: int = 5) -> str:
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
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.units import mm
        from reportlab.pdfgen import canvas
    except Exception:
        return None

    buffer = io.BytesIO()
    c = canvas.Canvas(buffer, pagesize=A4)
    width, height = A4

    left = 18 * mm
    top = height - 18 * mm
    line_h = 5.2 * mm

    def draw_line(text: str, x: float, y: float) -> float:
        max_chars = 110
        chunks = [text[i : i + max_chars] for i in range(0, len(text), max_chars)] or [""]
        for chunk in chunks:
            c.drawString(x, y, chunk)
            y -= line_h
            if y < 18 * mm:
                c.showPage()
                y = top
        return y

    y = top
    c.setFont("Helvetica-Bold", 14)
    y = draw_line("AdChainAudit Report", left, y)
    c.setFont("Helvetica", 9)
    y = draw_line(f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC", left, y)
    y -= line_h

    c.setFont("Helvetica-Bold", 11)
    y = draw_line("Summary", left, y)
    c.setFont("Helvetica", 9)

    totals = summary.get("totals", {})
    rels = summary.get("relationships", {})
    summary_lines = [
        f"Entries parsed: {totals.get('entries', 0)}",
        f"DIRECT: {rels.get('DIRECT', 0)}",
        f"RESELLER: {rels.get('RESELLER', 0)}",
        f"Missing CAID entries: {summary.get('missing_caid_entries', 0)}",
        f"Relationship ambiguity pairs: {summary.get('relationship_ambiguity_pairs', 0)}",
        f"Risk score (0-100): {summary.get('risk_score_0_100', 0)}",
    ]
    for s in summary_lines:
        y = draw_line(f"- {s}", left, y)

    y -= line_h
    c.setFont("Helvetica-Bold", 11)
    y = draw_line("Potential red flags", left, y)
    c.setFont("Helvetica", 9)

    if not issues:
        y = draw_line("No red flags detected with the current rule set.", left, y)
    else:
        for idx, issue in enumerate(issues, start=1):
            sev = issue.get("severity", "")
            title = issue.get("title", "")
            detail = issue.get("detail", "")
            examples = issue.get("examples", [])[:max_examples]

            y = draw_line(f"{idx}. [{sev}] {title}", left, y)
            y = draw_line(f"   {detail}", left, y)
            if examples:
                y = draw_line("   Examples:", left, y)
                for e in examples:
                    ln = e.get("line_no", "?")
                    raw = (e.get("raw", "") or "").strip()
                    y = draw_line(f"   - L{ln}: {raw}", left, y)
            y -= line_h

    c.save()
    buffer.seek(0)
    return buffer.getvalue()


# ----------------- UI -----------------

st.set_page_config(page_title="AdChainAudit", layout="wide")

st.title("🛡️ AdChainAudit")
st.caption(
    "Audit the ad supply chain starting with ads.txt. Upload a file or paste contents to generate a buyer focused red flag summary."
)

with st.sidebar:
    st.header("⚙️ Options")
    show_meta = st.toggle("Show meta or variable lines (if present)", value=False)
    max_examples = st.slider("Examples per issue (UI)", 5, 25, 12, step=1)
    export_examples = st.slider("Examples per issue (exports)", 1, 10, 4, step=1)

tab_upload, tab_paste = st.tabs(["📤 Upload ads.txt", "📋 Paste ads.txt"])

# ✅ Cleaner help: collapsed, minimal space
with st.expander("Need help finding a website ads.txt?", expanded=False):
    st.markdown(
        """
**Quick way:**
- Open: `https://example.com/ads.txt` (replace `example.com` with the website)

**Then:**
- Copy and paste into the *Paste ads.txt* tab, or
- Save as a text file named `ads.txt` and upload it

**Tips:**
- Try both `example.com/ads.txt` and `www.example.com/ads.txt`
- If a site does not publish ads.txt, that itself is a useful signal
"""
    )

content = None

with tab_upload:
    uploaded = st.file_uploader("Upload your ads.txt file", type=["txt"])
    if uploaded is not None:
        content = uploaded.getvalue().decode("utf-8", errors="ignore")

with tab_paste:
    pasted = st.text_area("Paste ads.txt contents here", height=260, placeholder="Paste ads.txt lines...")
    if pasted.strip():
        content = pasted

if not content:
    st.info("Upload an ads.txt file or paste its contents to begin.")
    st.stop()

records = parse_ads_txt(content)
summary, issues = analyze(records)

# KPI row
c1, c2, c3, c4 = st.columns(4)
c1.metric("Entries parsed", summary["totals"]["entries"])
c2.metric("DIRECT", summary["relationships"].get("DIRECT", 0))
c3.metric("RESELLER", summary["relationships"].get("RESELLER", 0))
c4.metric("Risk score (0 to 100)", summary["risk_score_0_100"])

# Summary
st.subheader("🧾 Summary")
st.write(
    f"- **Relationship ambiguity pairs:** {summary['relationship_ambiguity_pairs']}\n"
    f"- **Entries missing CAID (field #4):** {summary['missing_caid_entries']}\n"
)

# Issues
st.subheader("🚩 Potential red flags")
if not issues:
    st.success("No red flags detected with the current rule set.")
else:
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    issues_sorted = sorted(issues, key=lambda x: order.get(x["severity"], 99))

    for issue in issues_sorted:
        sev = issue["severity"]
        title = issue["title"]
        detail = issue["detail"]
        examples = issue.get("examples", [])[:max_examples]

        expanded = sev in ("CRITICAL", "HIGH")
        with st.expander(f"{sev} - {title}", expanded=expanded):
            st.write(detail)
            if examples:
                st.markdown("**Examples (line level evidence):**")
                st.code("\n".join([f"L{e.get('line_no')}: {(e.get('raw','') or '').rstrip()}" for e in examples]))

# Optional meta lines
if show_meta and summary["totals"]["meta_lines"] > 0:
    st.subheader("🧩 Meta or variable lines")
    meta = [r for r in records if r.record_type == "meta"]
    for m in meta[:200]:
        st.write(f"- `L{m.line_no}` **{m.meta_key}** = `{m.meta_value}`")

# Exports
st.subheader("⬇️ Export")

report_json = to_report_json(summary, issues)
report_txt = build_text_report(summary, issues, max_examples=export_examples)
report_csv = build_csv_issues(issues, max_examples=export_examples)
pdf_bytes = build_pdf_report(summary, issues, max_examples=export_examples)

colA, colB, colC, colD = st.columns(4)

with colA:
    st.download_button(
        label="📦 Download JSON",
        data=report_json,
        file_name="adchainaudit_report.json",
        mime="application/json",
    )

with colB:
    st.download_button(
        label="📝 Download TXT",
        data=report_txt,
        file_name="adchainaudit_report.txt",
        mime="text/plain",
    )

with colC:
    st.download_button(
        label="📊 Download CSV",
        data=report_csv,
        file_name="adchainaudit_issues.csv",
        mime="text/csv",
    )

with colD:
    if pdf_bytes is None:
        st.caption("📄 PDF requires reportlab in requirements.txt")
    else:
        st.download_button(
            label="📄 Download PDF",
            data=pdf_bytes,
            file_name="adchainaudit_report.pdf",
            mime="application/pdf",
        )

with st.expander("Preview: TXT report", expanded=False):
    st.code(report_txt)

# ✅ Open-source + contribution block (clean, not too big)
st.markdown("---")
with st.expander("Open source, MIT license, and contributions", expanded=False):
    st.markdown(
        """
AdChainAudit is **open source** under the **MIT License**.

- 🌟 GitHub repo (for technical users who want to contribute or extend it):  
  https://github.com/maazkhan86/AdChainAudit

- 🤝 Want to help? New rules, better scoring, sellers.json checks, and supply chain mapping are welcome.
"""
    )

st.caption("Tip: Exports are useful evidence snapshots because ads.txt can change over time.")
