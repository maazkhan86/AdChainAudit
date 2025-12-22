# app.py
from __future__ import annotations

from pathlib import Path
from typing import Optional, Dict, List, Tuple

import streamlit as st
import requests

from analyzer import analyze_ads_txt, report_to_csv_bytes, report_to_json_bytes, report_to_txt_bytes
from phase2_sellers_json import run_sellers_json_verification

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
# Seller verification interpretation
# -------------------------------
def explain_match_rate(avg_match_rate: float, unreachable: int) -> Tuple[str, str]:
    if avg_match_rate >= 0.85:
        interp = "✅ Strong verification coverage. Most seller IDs listed in ads.txt are confirmed by sellers.json."
        action = "Next: Focus on the remaining mismatches and confirm the preferred DIRECT path for your buys."
    elif avg_match_rate >= 0.60:
        interp = "🟨 Mixed verification. A meaningful share of seller IDs could not be confirmed via sellers.json."
        action = "Next: Ask the publisher/SSP to confirm the correct seller account IDs and the preferred buying path (DIRECT where possible)."
    elif avg_match_rate >= 0.30:
        interp = "🟧 Weak verification. Many seller IDs in ads.txt were not found in sellers.json."
        action = "Next: Treat this as a transparency risk. Request clarification on seller IDs and avoid unnecessary reseller-heavy paths."
    else:
        interp = "🟥 Very low verification. Most seller IDs could not be validated via sellers.json."
        action = "Next: Escalate with your publisher/SSP. Ask for confirmation of authorized paths and consider tighter SPO controls."

    if unreachable > 0:
        action += " Note: some ad systems were unreachable or blocked, which also reduces verification confidence."

    return interp, action


# -------------------------------
# Fetch ads.txt (with safe fallback + debug)
# -------------------------------
def _normalize_site(s: str) -> str:
    s = (s or "").strip().lower()
    s = s.replace("http://", "").replace("https://", "")
    s = s.strip("/")
    return s


def _looks_like_ads_txt(text: str) -> bool:
    if not text or len(text) < 20:
        return False
    # ads.txt almost always has commas separating fields
    return "," in text


def _looks_like_html_block(text: str, content_type: str) -> bool:
    ct = (content_type or "").lower()
    head = (text or "")[:600].lower()
    if "text/html" in ct:
        return True
    if "<html" in head or "<!doctype html" in head:
        return True
    # common block-page terms (light heuristic)
    if "access denied" in head or "request blocked" in head or "captcha" in head:
        return True
    return False


def fetch_ads_txt_for_site(
    site: str,
    *,
    timeout: Tuple[int, int] = (5, 15),
    allow_http_fallback: bool = False,
) -> Dict:
    """
    Attempts a list of candidate URLs.
    Returns a dict with:
      ok, text, chosen_url, chosen_status, chosen_content_type,
      attempts: [{url,status,content_type,looks_html,looks_ads,bytes,error}]
    """
    site = _normalize_site(site)
    if not site:
        return {
            "ok": False,
            "text": None,
            "chosen_url": None,
            "chosen_status": None,
            "chosen_content_type": None,
            "attempts": [],
            "reason": "No domain provided",
        }

    schemes = ["https"]
    if allow_http_fallback:
        schemes.append("http")

    candidates = []
    for scheme in schemes:
        candidates.extend(
            [
                f"{scheme}://{site}/ads.txt",
                f"{scheme}://www.{site}/ads.txt",
            ]
        )

    headers = {
        "User-Agent": "AdChainAudit/0.2 (+https://github.com/maazkhan86/AdChainAudit)",
        "Accept": "text/plain,text/*;q=0.9,*/*;q=0.8",
    }

    attempts = []
    for url in candidates:
        try:
            r = requests.get(url, headers=headers, timeout=timeout, allow_redirects=True)
            status = r.status_code
            ctype = r.headers.get("Content-Type", "")
            text = r.text or ""
            looks_html = _looks_like_html_block(text, ctype)
            looks_ads = _looks_like_ads_txt(text)

            attempts.append(
                {
                    "url": url,
                    "status": status,
                    "content_type": ctype,
                    "looks_html": looks_html,
                    "looks_ads": looks_ads,
                    "bytes": len((r.content or b"")),
                    "error": None,
                }
            )

            if status == 200 and (not looks_html) and looks_ads:
                return {
                    "ok": True,
                    "text": text,
                    "chosen_url": url,
                    "chosen_status": status,
                    "chosen_content_type": ctype,
                    "attempts": attempts,
                    "reason": None,
                }

        except Exception as e:
            attempts.append(
                {
                    "url": url,
                    "status": None,
                    "content_type": None,
                    "looks_html": None,
                    "looks_ads": None,
                    "bytes": None,
                    "error": str(e),
                }
            )

    # If everything failed
    # Decide a friendly reason
    reason = "ads.txt not found or blocked"
    # If any attempt returned HTML with 200/403, likely blocked
    for a in attempts:
        if a["status"] in (200, 403, 401) and a.get("looks_html"):
            reason = "Request appears blocked (HTML response)"
            break
        if a["status"] == 404:
            reason = "ads.txt not found (404)"
    return {
        "ok": False,
        "text": None,
        "chosen_url": candidates[0] if candidates else None,
        "chosen_status": None,
        "chosen_content_type": None,
        "attempts": attempts,
        "reason": reason,
    }


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

    # Seller verification (sellers.json)
    "SELLERS_JSON_UNREACHABLE": "Seller verification (sellers.json)",
    "SELLER_ID_NOT_FOUND_IN_SELLERS_JSON": "Seller verification (sellers.json)",
    "SELLERS_JSON_INTERMEDIARY_SELLERS_PRESENT": "Seller verification (sellers.json)",
    "SELLERS_JSON_CONFIDENTIAL_SELLERS_PRESENT": "Seller verification (sellers.json)",
}

THEME_INFO = {
    "Format & spec compliance": {
        "why": "If the ads.txt is messy or non-standard, automated checks become less reliable and authorization becomes harder to validate.",
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
        "why": "The 4th field (Certification Authority ID) can help at scale, but many publishers omit it. This is usually an extra signal, not a hard red flag.",
        "questions": [
            "Optional: can the publisher/seller include Certification Authority ID where applicable?",
        ],
    },
    "Seller verification (sellers.json)": {
        "why": "sellers.json is published by ad systems (SSPs/exchanges) and describes seller accounts. Matching ads.txt seller IDs against sellers.json improves confidence and reduces ambiguity.",
        "questions": [
            "Are seller account IDs current and verifiable in sellers.json?",
            "If many IDs don’t match, can the publisher confirm the preferred selling path?",
            "If intermediaries dominate, is there a more direct route for our spend?",
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
    for k in [
        "Seller verification (sellers.json)",
        "Format & spec compliance",
        "Selling relationship clarity",
        "Verification signals (optional)",
        "Other",
    ]:
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
        "Upload, paste, or fetch a site’s ads.txt to generate a buyer-focused red-flag summary."
    )

    c1, c2 = st.columns([1.15, 1.25])
    with c1:
        if st.button("⚡ Try sample ads.txt", use_container_width=True):
            set_ads_text(load_sample_text(), SAMPLE_LABEL)
            st.rerun()
    with c2:
        st.link_button("👩‍💻 GitHub (technical)", GITHUB_REPO_URL, use_container_width=True)

    st.divider()

    # NEW: Fetch ads.txt from website (with fallback + debug)
    st.subheader("Get ads.txt")
    fc1, fc2 = st.columns([1.35, 0.65])
    with fc1:
        site = st.text_input("Website domain", placeholder="example.com", value="")
        allow_http = st.checkbox(
            "Try HTTP if HTTPS fails (optional)",
            value=False,
            help="Some sites do not serve ads.txt over HTTPS. This tries http:// as a fallback.",
        )
        show_debug = st.checkbox(
            "Show fetch debug details",
            value=False,
            help="Shows the exact URLs attempted and response status codes (useful if a site blocks requests).",
        )
        st.caption("We try: /ads.txt and /ads.txt on www. If blocked, you can always paste or upload manually.")
    with fc2:
        if st.button("🌐 Fetch ads.txt", use_container_width=True):
            s = _normalize_site(site)
            if not s:
                st.warning("Please enter a website domain first (example: example.com).")
            else:
                with st.spinner("Fetching ads.txt…"):
                    result = fetch_ads_txt_for_site(s, allow_http_fallback=allow_http)

                if result["ok"]:
                    text = result["text"] or ""
                    url = result["chosen_url"]
                    set_ads_text(text, f"Fetched: {url}")
                    st.success(f"ads.txt fetched successfully from {url}")
                    if show_debug:
                        with st.expander("Fetch debug details", expanded=True):
                            st.json(result["attempts"])
                    st.rerun()
                else:
                    st.error("Could not fetch ads.txt automatically.", icon="⚠️")
                    st.info(
                        "No problem, this is common. Some sites block automated requests.\n\n"
                        "**What to do:**\n"
                        "1) Open the ads.txt link in your browser\n"
                        "2) Copy all text\n"
                        "3) Paste it into the app (or download and upload the file)\n"
                    )
                    # Show likely first attempt
                    attempts = result.get("attempts", [])
                    first_url = attempts[0]["url"] if attempts else result.get("chosen_url", "")
                    st.markdown(f"Try this in your browser: `{first_url}`")
                    st.caption(f"Reason: {result.get('reason')}")
                    if show_debug:
                        with st.expander("Fetch debug details", expanded=True):
                            st.json(attempts)

    with st.expander("📌 Manual option (always works)", expanded=False):
        st.markdown(
            """
If automatic fetching is blocked, you can still audit ads.txt easily:

1. Open: `https://example.com/ads.txt`  
2. Copy all text  
3. Paste it in the app (or save as `ads.txt` and upload)
"""
        )

    st.divider()

    include_optional = st.checkbox(
        "Include optional signals (e.g., missing Certification Authority ID)",
        value=False,
    )

    verify_sellers = st.checkbox(
        "Verify seller accounts (sellers.json) — slower but adds stronger evidence",
        value=False,
        help="This fetches public sellers.json files from SSP/exchange domains listed in ads.txt. Some domains may block or rate-limit requests.",
    )

    max_domains = 25
    if verify_sellers:
        max_domains = st.slider(
            "Limit verification to this many ad-system domains (keeps it fast)",
            min_value=5,
            max_value=60,
            value=25,
            step=5,
        )

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

    if get_source_label() == SAMPLE_LABEL:
        st.error(f"🚨 SAMPLE LOADED: {SAMPLE_SOURCE_NOTE}", icon="⚠️")

    st.divider()

    run = st.button("🔎 Run audit", type="primary")
    if run:
        text = get_ads_text().strip()
        if not text:
            st.warning("Please fetch, upload, or paste an ads.txt first (or click “Try sample ads.txt”).")
            st.stop()

        with st.spinner("Analyzing ads.txt…"):
            report = analyze_ads_txt(
                text=text,
                source_label=get_source_label(),
                include_optional_checks=include_optional,
            )

        sellers_json_result = None
        if verify_sellers:
            with st.spinner("Verifying seller accounts via sellers.json…"):
                sellers_json_result = run_sellers_json_verification(
                    ads_txt=text,
                    max_domains=max_domains,
                    sleep_between=0.25,
                )

            report.setdefault("meta", {})["sellers_json_checks"] = True
            report.setdefault("summary", {})["sellers_json"] = sellers_json_result.get("summary", {})
            report.setdefault("findings", [])
            report["findings"].extend(sellers_json_result.get("findings", []))

        top = st.columns([1.1, 1.1, 1.1, 1.7])
        top[0].metric("Risk score", report["summary"]["risk_score"])
        top[1].metric("Risk level", report["summary"]["risk_level"])
        top[2].metric("Findings", report["summary"]["finding_count"])
        top[3].metric("Entries", report["summary"]["entry_count"])

        if sellers_json_result:
            s = sellers_json_result.get("summary", {})
            st.subheader("Seller verification summary (sellers.json)")
            cA, cB, cC, cD = st.columns(4)
            cA.metric("Domains checked", s.get("domains_checked", 0))
            cB.metric("Reachable", s.get("reachable", 0))
            cC.metric("Unreachable", s.get("unreachable", 0))
            cD.metric("Avg match rate", s.get("avg_match_rate", 0.0))

            avg = float(s.get("avg_match_rate", 0.0) or 0.0)
            unr = int(s.get("unreachable", 0) or 0)
            interp, action = explain_match_rate(avg, unr)

            st.info(interp)
            st.success(action)

            st.caption(
                "Tip: If some domains are blocked or rate-limited, verification may be incomplete. "
                "This is why sellers.json checks are treated as additional evidence, not the only truth."
            )

        findings = report.get("findings", [])
        if not findings:
            st.success("No red flags detected by the current rule set.")
        else:
            st.subheader("Themes summary")
            buckets = group_findings_by_theme(findings)

            theme_cols = st.columns(min(4, max(1, len(buckets))))
            for i, (theme, fs) in enumerate(list(buckets.items())[:4]):
                sev = max_severity(fs)
                badge = SEV_BADGE.get(sev, "🟦")
                theme_cols[i].metric(f"{badge} {theme}", len(fs))

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
                        st.markdown("**Questions to ask:**")
                        for q in questions:
                            st.markdown(f"- {q}")

                    st.markdown("**Example evidence (first 5):**")
                    shown = 0
                    for f in fs:
                        ev = f.get("evidence", {})
                        ln = ev.get("line_no")
                        line = ev.get("line", "")
                        title = f.get("title", "Finding")
                        if line:
                            st.caption(f"- {title}")
                            if ln is not None:
                                st.code(f"Line {ln}: {line}".strip())
                            else:
                                st.code(line.strip())
                            shown += 1
                        if shown >= 5:
                            break
                    if len(fs) > 5:
                        st.caption(f"Showing 5 examples out of {len(fs)}. Use CSV export for the full list.")

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
