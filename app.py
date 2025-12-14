# app.py
from __future__ import annotations

from pathlib import Path
from typing import Optional, Dict, List, Tuple

import streamlit as st

from analyzer import analyze_ads_txt, report_to_csv_bytes, report_to_json_bytes, report_to_txt_bytes

APP_TITLE = "AdChainAudit"

SAMPLE_PATH = Path("samples/thestar_ads_20251214.txt")
SAMPLE_LABEL = "thestar.com.my/ads.txt (snapshot: 14 Dec 2025)"
SAMPLE_SOURCE_NOTE = (
    "Sample snapshot source: thestar.com.my/ads.txt (captured 14 Dec 2025). "
    "ads.txt changes over time; treat this as a demo input."
)

GITHUB_REPO_URL = "https://github.com/maazkhan86/AdChainAudit"


@st.cache_data(show_spinner=False)
def load_sample_text() -> str:
    if SAMPLE_PATH.exists():
        return SAMPLE_PATH.read_text(encoding="utf-8", errors="replace")
    return (
        "# Sample file missing.\n"
        "# Please add: samples/thestar_ads_20251214.txt\n"
        "# Paste your thestar.com.my/ads.txt snapshot (14 Dec 2025) into that file.\n"
    )


def set_ads_text(text: str, label: Optional[str] = None) -> None:
    st.session_state["ads_text"] = text
    if label is not None:
        st.session_state["source_label"] = label


def get_ads_text() -> str:
    return st.session_state.get("ads_text", "")


def get_source_label() -> str:
    return st.session_state.get("source_label", "Uploaded/Pasted ads.txt")


# -------------------------------
# Theme logic (marketing-friendly)
# -------------------------------

SEV_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
SEV_BADGE = {"CRITICAL": "🟥", "HIGH": "🟧", "MEDIUM": "🟨", "LOW": "🟦"}

RULE_THEME = {
    "MALFORMED_LINE": "Format & spec compliance",
    "INVALID_RELATIONSHIP": "Format & spec compliance",
    "RELATIONSHIP_AMBIGUITY": "Selling relationship clarity",
    "MISSING_CAID": "Verification signals (optional)",
}

THEME_INFO = {
    "Format & spec compliance": {
        "why": "If the ads.txt is messy or non-standard, it becomes harder to trust automated checks and validate who’s authorized to sell inventory.",
        "questions": [
            "Can the publisher clean the file to be spec-compliant (3–4 fields, correct relationship values)?",
            "Are inline comments or formatting causing interpretation issues?",
        ],
    },
    "Selling relationship clarity": {
        "why": "If the same seller appears as both DIRECT and RESELLER, it can be unclear which route is preferred and whether intermediaries are being added unnecessarily.",
        "questions": [
            "Which route is preferred for our buys for this publisher?",
            "Can we prioritize DIRECT where available and justify reseller paths?",
        ],
    },
    "Verification signals (optional)": {
        "why": "Verification fields (like CAID) can help at scale, but many publishers omit them. This is usually an extra signal, not a hard red flag.",
        "questions": [
            "Optional: can the publisher/seller include CAID where applicable?",
        ],
    },
}


def theme_for_rule(rule_id: str) -> str:
    return RULE_THEME.get(rule_id, "Other")


def max_severity(findings: List[dict]) -> str:
    if not findings:
        return "LOW"
    best = "LOW"
    for f in findings:
        sev = f.get("severity", "LOW")
        if SEV_ORDER.get(sev, 1) > SEV_ORDER.get(best, 1):
            best = sev
    return best


def group_findings_by_theme(findings: List[dict]) -> Dict[str, List[dict]]:
    buckets: Dict[str, List[dict]] = {}
    for f in findings:
        rid = f.get("rule_id", "OTHER")
        theme = theme_for_rule(rid)
        buckets.setdefault(theme, []).append(f)

    ordered: Dict[str, List[dict]] = {}
    for k in ["Format & spec compliance", "Selling relationship clarity", "Verification signals (optional)", "Other"]:
        if k in buckets:
            ordered[k] = buckets[k]
    for k, v in buckets.items():
        if k not in ordered:
            ordered[k] = v
    return ordered


def top_rule_counts_in_theme(findings: List[dict], n: int = 3) -> List[Tuple[str, int]]:
    counts: Dict[str, int] = {}
    for f in findings:
        rid = f.get("rule_id", "OTHER")
        counts[rid] = counts.get(rid, 0) + 1
    items = sorted(counts.items(), key=lambda x: x[1], reverse=True)
    return items[:n]


def main() -> None:
    st.set_page_config(page_title=APP_TITLE, page_icon="🛡️", layout="wide")

    st.markdown(f"# 🛡️ {APP_TITLE}")
    st.caption(
        "Audit the ad supply chain starting with ads.txt. "
        "Upload or paste an ads.txt file to generate a buyer-focused red-flag summary."
    )

    # Top row (removed open-source banner)
    c1, c2 = st.columns([1.15, 1.25])

    with c1:
        if st.button("⚡ Try sample ads.txt", use_container_width=True):
            set_ads_text(load_sample_text(), SAMPLE_LABEL)
            st.rerun()

    with c2:
        st.link_button("👩‍💻 GitHub (technical)", GITHUB_REPO_URL, use_container_width=True)

    with st.expander("📌 How to get a site’s ads.txt (quick)", expanded=False):
        st.markdown(
            """
1. Open: `https://example.com/ads.txt`  
2. If it 404s, try: `https://www.example.com/ads.txt`  
3. Copy all text and paste it here, or save as `ads.txt` and upload.
"""
        )

    with st.expander("🧮 How the risk score works (simple)", expanded=False):
        st.markdown(
            """
- Score starts at **100** (cleanest).
- We apply **penalties by rule severity** (HIGH issues reduce more than LOW).
- Repeated issues have **diminishing impact** (the 100th repeat matters less than the 2nd).
- Final score stays between **0 and 100**.

**Risk levels**
- **LOW**: 80–100  
- **MEDIUM**: 55–79  
- **HIGH**: 0–54  

This is a **sanity-check score** to prioritize questions. It doesn’t prove fraud by itself.
"""
        )

    include_optional = st.checkbox("Include optional signals (e.g., missing CAID)", value=False)

    tab_upload, tab_paste = st.tabs(["📤 Upload ads.txt", "📋 Paste ads.txt"])

    with tab_upload:
        uploaded = st.file_uploader("Upload an ads.txt file", type=["txt"])
        if uploaded is not None:
            uploaded_text = uploaded.getvalue().decode("utf-8", errors="replace")
            set_ads_text(uploaded_text, getattr(uploaded, "name", "Uploaded ads.txt"))

    with tab_paste:
        ads_text = st.text_area(
            "Paste ads.txt contents here",
            value=get_ads_text(),
            height=220,
            placeholder="Paste the full contents of ads.txt here…",
        )
        set_ads_text(ads_text, get_source_label())

    # ✅ Make sample usage VERY visible
    if get_source_label() == SAMPLE_LABEL:
        st.error(f"🚨 SAMPLE LOADED: {SAMPLE_SOURCE_NOTE}", icon="⚠️")

    st.divider()

    run = st.button("🔎 Run audit", type="primary")
    if run:
        text = get_ads_text().strip()
        if not text:
            st.warning("Please upload or paste an ads.txt first (or click “Try sample ads.txt”).")
            st.stop()

        with st.spinner("Analyzing…"):
            report = analyze_ads_txt(
                text=text,
                source_label=get_source_label(),
                include_optional_checks=include_optional,
            )

        # Metrics
        top = st.columns([1.1, 1.1, 1.1, 1.7])
        top[0].metric("Risk score", report["summary"]["risk_score"])
        top[1].metric("Risk level", report["summary"]["risk_level"])
        top[2].metric("Findings", report["summary"]["finding_count"])
        top[3].metric("Entries", report["summary"]["entry_count"])

        findings = report.get("findings", [])
        if not findings:
            st.success("No red flags detected by the current rule set.")
        else:
            st.subheader("Themes summary (what to focus on)")
            buckets = group_findings_by_theme(findings)

            theme_cols = st.columns(min(4, max(1, len(buckets))))
            for i, (theme, fs) in enumerate(list(buckets.items())[:4]):
                sev = max_severity(fs)
                badge = SEV_BADGE.get(sev, "🟦")
                theme_cols[i].metric(f"{badge} {theme}", len(fs))

            st.caption("Tip: Start with the highest-severity theme and the most repeated issue inside it.")

            for theme, fs in buckets.items():
                sev = max_severity(fs)
                badge = SEV_BADGE.get(sev, "🟦")
                info = THEME_INFO.get(theme, {})
                why = info.get("why", "Grouped issues for easier review.")
                questions = info.get("questions", [])

                top_rules = top_rule_counts_in_theme(fs, n=3)
                top_rules_str = ", ".join([f"{rid} ({cnt})" for rid, cnt in top_rules]) if top_rules else "—"

                with st.expander(f"{badge} {theme} — {len(fs)} signals (max severity: {sev})", expanded=False):
                    st.markdown(f"**Why it matters:** {why}")
                    st.markdown(f"**Most repeated signals:** {top_rules_str}")

                    if questions:
                        st.markdown("**Questions to ask (practical):**")
                        for q in questions:
                            st.markdown(f"- {q}")

                    st.markdown("**Example evidence (first 5):**")
                    shown = 0
                    for f in fs:
                        ev = f.get("evidence", {})
                        ln = ev.get("line_no")
                        line = ev.get("line", "")
                        title = f.get("title", "Finding")
                        if ln is not None and line:
                            st.caption(f"- {title}")
                            st.code(f"Line {ln}: {line}".strip())
                            shown += 1
                        if shown >= 5:
                            break
                    if len(fs) > 5:
                        st.caption(f"Showing 5 examples out of {len(fs)}. Use CSV export for the full list.")

            with st.expander("📋 See raw finding list (advanced)", expanded=False):
                st.caption("Ungrouped list. Can be repetitive for large files.")
                for f in findings[:50]:
                    sev = f.get("severity", "LOW")
                    title = f.get("title", "Finding")
                    badge = SEV_BADGE.get(sev, "🟦")
                    with st.expander(f"{badge} [{sev}] {title}", expanded=False):
                        why = f.get("why_buyer_cares", "")
                        if why:
                            st.write(why)
                        ev = f.get("evidence", {})
                        ln = ev.get("line_no")
                        line = ev.get("line", "")
                        if ln is not None:
                            st.code(f"Line {ln}: {line}".strip())
                        rec = f.get("recommendation", "")
                        if rec:
                            st.markdown(f"**What to do:** {rec}")
                if len(findings) > 50:
                    st.caption(f"Showing first 50 findings out of {len(findings)}.")

        st.subheader("Exports")
        dl = st.columns([1, 1, 1, 1])
        dl[0].download_button(
            "⬇️ JSON",
            data=report_to_json_bytes(report),
            file_name="adchainaudit_report.json",
            mime="application/json",
            use_container_width=True,
        )
        dl[1].download_button(
            "⬇️ TXT",
            data=report_to_txt_bytes(report),
            file_name="adchainaudit_report.txt",
            mime="text/plain",
            use_container_width=True,
        )
        dl[2].download_button(
            "⬇️ CSV",
            data=report_to_csv_bytes(report),
            file_name="adchainaudit_findings.csv",
            mime="text/csv",
            use_container_width=True,
        )
        dl[3].download_button(
            "⬇️ Sample ads.txt",
            data=load_sample_text().encode("utf-8", errors="replace"),
            file_name="sample_thestar_ads_20251214.txt",
            mime="text/plain",
            use_container_width=True,
        )

    st.caption("Built in public. Feedback, feature ideas, and collaborators welcome 🤝")


if __name__ == "__main__":
    main()
