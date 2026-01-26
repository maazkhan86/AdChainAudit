# app.py
from __future__ import annotations

import io
import json
import os
import re
import zipfile
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Tuple
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

import streamlit as st

# Phase 1
from analyzer import analyze_ads_txt, report_to_csv_bytes, report_to_json_bytes, report_to_txt_bytes

# Phase 2 (optional import safety)
try:
    from phase2_sellers_json import run_sellers_json_verification  # type: ignore
except Exception:  # pragma: no cover
    run_sellers_json_verification = None  # type: ignore


APP_VERSION = "0.8"
EVIDENCE_DIR = Path("evidence")
SAMPLES_DIR = Path("samples")
DEMO_SAMPLE_PATH = SAMPLES_DIR / "ads.txt"

DEMO_SNAPSHOT_NOTE = (
    "Sample snapshot source: thestar.com.my/ads.txt (captured 14 Dec 2025). "
    "ads.txt changes over time; treat this as a demo input."
)


# -----------------------------
# Helpers
# -----------------------------
def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _clean_domain_or_url(s: str) -> str:
    return (s or "").strip()


def _looks_like_url(s: str) -> bool:
    return s.lower().startswith("http://") or s.lower().startswith("https://")


def _normalize_domain(s: str) -> str:
    s = s.strip()
    s = re.sub(r"^https?://", "", s, flags=re.I)
    s = s.split("/", 1)[0]
    return s.strip()


def build_ads_txt_candidates(domain_or_url: str) -> Tuple[str, ...]:
    """
    Returns a list of URLs we will try (hardcoded logic):
      - If user provides a URL: try that, then http variant.
      - If user provides a domain: try https://domain/ads.txt, https://www.domain/ads.txt,
        then http variants.
    """
    s = _clean_domain_or_url(domain_or_url)
    if not s:
        return tuple()

    if _looks_like_url(s):
        url = s
        if url.lower().endswith("/"):
            url = url[:-1]
        # If user typed a site root, assume /ads.txt
        if not url.lower().endswith(".txt"):
            url = url + "/ads.txt"
        http_variant = re.sub(r"^https://", "http://", url, flags=re.I)
        return (url, http_variant) if http_variant != url else (url,)

    d = _normalize_domain(s)
    if not d:
        return tuple()

    https_main = f"https://{d}/ads.txt"
    https_www = f"https://www.{d}/ads.txt" if not d.lower().startswith("www.") else https_main
    http_main = f"http://{d}/ads.txt"
    http_www = f"http://www.{d}/ads.txt" if not d.lower().startswith("www.") else http_main

    # keep order + de-dupe
    urls = []
    for u in [https_main, https_www, http_main, http_www]:
        if u not in urls:
            urls.append(u)
    return tuple(urls)


def fetch_text(url: str, timeout_s: int = 8) -> Tuple[Optional[str], Dict[str, Any]]:
    """
    Fetch a URL with a realistic User-Agent. Returns (text, debug_meta).
    Debug meta is collected always (hardcoded), but only shown selectively in UI.
    """
    meta: Dict[str, Any] = {"url": url, "ok": False, "status": None, "error": None}

    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/120.0.0.0 Safari/537.36"
        ),
        "Accept": "text/plain,text/*;q=0.9,*/*;q=0.8",
    }

    req = Request(url=url, headers=headers, method="GET")
    try:
        with urlopen(req, timeout=timeout_s) as resp:
            status = getattr(resp, "status", None)
            meta["status"] = status
            raw = resp.read()
            # best-effort decode
            try:
                text = raw.decode("utf-8")
            except Exception:
                text = raw.decode("latin-1", errors="replace")
            meta["ok"] = True if (status is None or int(status) < 400) else False
            return text, meta
    except HTTPError as e:
        meta["status"] = getattr(e, "code", None)
        meta["error"] = f"HTTPError: {e}"
    except URLError as e:
        meta["error"] = f"URLError: {e}"
    except Exception as e:
        meta["error"] = f"Error: {e}"

    return None, meta


def fetch_ads_txt(domain_or_url: str) -> Tuple[Optional[str], Dict[str, Any]]:
    """
    Tries a sequence of candidate URLs (hardcoded).
    Returns (text, debug) where debug includes attempts[].
    """
    candidates = build_ads_txt_candidates(domain_or_url)
    debug: Dict[str, Any] = {"attempts": [], "chosen": None}

    for u in candidates:
        text, meta = fetch_text(u)
        debug["attempts"].append(meta)
        if text and meta.get("ok"):
            debug["chosen"] = u
            return text, debug

    return None, debug


def safe_pct(x: Any) -> str:
    try:
        return f"{float(x) * 100:.0f}%"
    except Exception:
        return "—"


def clamp_int(x: Any, lo: int, hi: int, default: int) -> int:
    try:
        v = int(x)
        return max(lo, min(hi, v))
    except Exception:
        return default


def pretty_level(level: Any) -> str:
    s = str(level or "").upper().strip()
    return s if s in {"LOW", "MEDIUM", "HIGH"} else "—"


def evidence_write_run(
    *,
    ads_txt_text: str,
    source_label: str,
    audit_report: Dict[str, Any],
    sellers_report: Optional[Dict[str, Any]],
    fetch_debug: Optional[Dict[str, Any]],
) -> Optional[Path]:
    """
    Evidence locker (Phase 2 add-on):
    - Stores inputs + outputs with timestamp under ./evidence/<timestamp>_<source>/
    - Helps reproducibility and provides “receipts” for internal sharing.
    """
    try:
        EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        safe_source = re.sub(r"[^a-zA-Z0-9._-]+", "_", (source_label or "ads.txt").strip())[:60]
        run_dir = EVIDENCE_DIR / f"{ts}_{safe_source}"
        run_dir.mkdir(parents=True, exist_ok=True)

        (run_dir / "input_ads.txt").write_text(ads_txt_text, encoding="utf-8", errors="ignore")
        (run_dir / "audit_report.json").write_bytes(report_to_json_bytes(audit_report))
        (run_dir / "audit_report.txt").write_bytes(report_to_txt_bytes(audit_report))
        (run_dir / "audit_report.csv").write_bytes(report_to_csv_bytes(audit_report))

        meta = {
            "generated_at": now_iso(),
            "app_version": APP_VERSION,
            "source_label": source_label,
        }
        if fetch_debug:
            meta["fetch_debug"] = fetch_debug
        (run_dir / "run_meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")

        if sellers_report is not None:
            (run_dir / "sellers_verification.json").write_text(
                json.dumps(sellers_report, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )

        return run_dir
    except Exception:
        # Don’t break the app if storage isn’t available.
        return None


def zip_dir_bytes(folder: Path) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for p in folder.rglob("*"):
            if p.is_file():
                zf.write(p, arcname=str(p.relative_to(folder)))
    return buf.getvalue()


def call_sellers_verification(ads_txt_text: str) -> Optional[Dict[str, Any]]:
    """
    Calls phase2 function with signature-guessing (so you don’t have to keep editing app.py).
    """
    if run_sellers_json_verification is None:
        return None

    fn = run_sellers_json_verification
    # Try common signatures safely.
    for kwargs in [
        {},  # run_sellers_json_verification(text)
        {"ads_txt_text": ads_txt_text},
        {"text": ads_txt_text},
        {"ads_txt": ads_txt_text},
        {"max_domains": 25},
        {"ads_txt_text": ads_txt_text, "max_domains": 25},
        {"text": ads_txt_text, "max_domains": 25},
    ]:
        try:
            if kwargs:
                return fn(**kwargs)  # type: ignore[arg-type]
            return fn(ads_txt_text)  # type: ignore[misc]
        except TypeError:
            continue
        except Exception as e:
            return {
                "summary": {"error": str(e)},
                "domain_stats": [],
                "findings": [
                    {
                        "severity": "MEDIUM",
                        "title": "Seller verification failed",
                        "why_buyer_cares": "Seller verification could not be completed in this run.",
                        "recommendation": "Try again, or proceed with Phase 1 signals only.",
                        "evidence": {"line_no": None, "line": str(e)},
                        "rule_id": "SELLERS_JSON_RUNTIME_ERROR",
                    }
                ],
            }

    # If all signatures fail:
    return {
        "summary": {"error": "Could not call run_sellers_json_verification (signature mismatch)."},
        "domain_stats": [],
        "findings": [],
    }


# -----------------------------
# UI styling
# -----------------------------
st.set_page_config(page_title="AdChainAudit", page_icon="🛡️", layout="wide")

st.markdown(
    """
<style>
/* App-like feel */
.block-container { padding-top: 1.25rem; padding-bottom: 2rem; max-width: 1200px; }
h1, h2, h3 { letter-spacing: -0.02em; }
small, .stCaption { opacity: 0.9; }

.card {
  border: 1px solid rgba(49, 51, 63, 0.12);
  border-radius: 16px;
  padding: 16px 16px;
  background: white;
  box-shadow: 0 1px 12px rgba(0,0,0,0.04);
}
.card-title { font-weight: 700; font-size: 0.95rem; margin-bottom: 10px; opacity: 0.95; }
.muted { opacity: 0.7; }
.pill {
  display: inline-block;
  padding: 6px 10px;
  border-radius: 999px;
  font-size: 12px;
  font-weight: 700;
  border: 1px solid rgba(49, 51, 63, 0.12);
  background: rgba(49, 51, 63, 0.03);
  margin-right: 6px;
  margin-bottom: 6px;
}
.pill-ok { background: rgba(0, 128, 0, 0.08); border-color: rgba(0, 128, 0, 0.20); }
.pill-warn { background: rgba(255, 165, 0, 0.10); border-color: rgba(255, 165, 0, 0.22); }
.pill-bad { background: rgba(255, 0, 0, 0.08); border-color: rgba(255, 0, 0, 0.18); }

.banner {
  border-radius: 14px;
  padding: 12px 14px;
  border: 1px solid rgba(49, 51, 63, 0.12);
  background: rgba(255, 0, 0, 0.06);
}

.stButton > button {
  border-radius: 12px !important;
  padding: 10px 14px !important;
  font-weight: 700 !important;
}

div[data-testid="stMetricValue"] { font-size: 34px; }
</style>
""",
    unsafe_allow_html=True,
)


# -----------------------------
# State
# -----------------------------
if "ads_text" not in st.session_state:
    st.session_state.ads_text = None
if "ads_source_label" not in st.session_state:
    st.session_state.ads_source_label = None
if "fetch_debug" not in st.session_state:
    st.session_state.fetch_debug = None
if "demo_loaded" not in st.session_state:
    st.session_state.demo_loaded = False
if "audit_report" not in st.session_state:
    st.session_state.audit_report = None
if "sellers_report" not in st.session_state:
    st.session_state.sellers_report = None
if "evidence_path" not in st.session_state:
    st.session_state.evidence_path = None


# -----------------------------
# Header
# -----------------------------
top_l, top_r = st.columns([3, 1])
with top_l:
    st.title("AdChainAudit")
    st.caption(
        "Sanity-check a publisher’s ads.txt and verify seller accounts via sellers.json. "
        "Built for media and marketing teams."
    )
with top_r:
    # Simple top action
    st.link_button("GitHub (technical)", "https://github.com/maazkhan86/AdChainAudit", use_container_width=True)

st.write("")

# -----------------------------
# Input area (App-like)
# -----------------------------
c1, c2, c3 = st.columns(3, gap="large")

with c1:
    st.markdown('<div class="card">', unsafe_allow_html=True)
    st.markdown('<div class="card-title">1) Get ads.txt</div>', unsafe_allow_html=True)
    domain_or_url = st.text_input(
        "Website domain or ads.txt URL",
        placeholder="example.com  or  https://example.com/ads.txt",
        label_visibility="collapsed",
    )
    fetch_btn = st.button("Fetch ads.txt", use_container_width=True)
    st.markdown('<div class="muted" style="margin-top:6px;">We try https first, then http. If blocked, upload or paste instead.</div>', unsafe_allow_html=True)
    st.markdown("</div>", unsafe_allow_html=True)

with c2:
    st.markdown('<div class="card">', unsafe_allow_html=True)
    st.markdown('<div class="card-title">2) Upload (optional)</div>', unsafe_allow_html=True)
    up = st.file_uploader("Upload ads.txt", type=["txt"], label_visibility="collapsed")
    demo_btn = st.button("Load demo sample", use_container_width=True)
    st.markdown("</div>", unsafe_allow_html=True)

with c3:
    st.markdown('<div class="card">', unsafe_allow_html=True)
    st.markdown('<div class="card-title">3) Paste (optional)</div>', unsafe_allow_html=True)
    pasted = st.text_area("Paste ads.txt", height=120, placeholder="Paste ads.txt text here…", label_visibility="collapsed")
    st.markdown("</div>", unsafe_allow_html=True)

# Actions: fetch / upload / demo / paste
if fetch_btn:
    if not domain_or_url.strip():
        st.warning("Enter a website domain or a full ads.txt URL first.")
    else:
        with st.spinner("Fetching ads.txt…"):
            text, dbg = fetch_ads_txt(domain_or_url.strip())
        st.session_state.fetch_debug = dbg
        if text:
            st.session_state.ads_text = text
            chosen = (dbg or {}).get("chosen") or domain_or_url.strip()
            st.session_state.ads_source_label = f"fetched:{chosen}"
            st.session_state.demo_loaded = False
            st.success("Fetched ads.txt successfully ✅")
        else:
            st.error("Couldn’t fetch ads.txt (blocked or not found). Use upload or paste instead.")
            # Show debug only on failure (hardcoded; no toggle)
            with st.expander("Fetch details (for troubleshooting)"):
                st.json(dbg)

if up is not None:
    try:
        raw = up.getvalue()
        text = raw.decode("utf-8")
    except Exception:
        text = (up.getvalue() or b"").decode("latin-1", errors="replace")

    st.session_state.ads_text = text
    st.session_state.ads_source_label = f"uploaded:{up.name}"
    st.session_state.demo_loaded = False
    st.session_state.fetch_debug = None

if demo_btn:
    if DEMO_SAMPLE_PATH.exists():
        demo_text = DEMO_SAMPLE_PATH.read_text(encoding="utf-8", errors="ignore")
        st.session_state.ads_text = demo_text
        st.session_state.ads_source_label = "demo:samples/ads.txt"
        st.session_state.demo_loaded = True
        st.session_state.fetch_debug = None
    else:
        st.error("Demo sample not found. Add it at ./samples/ads.txt in your repo and redeploy.")

if pasted and pasted.strip():
    st.session_state.ads_text = pasted.strip()
    st.session_state.ads_source_label = "pasted:textarea"
    st.session_state.demo_loaded = False
    st.session_state.fetch_debug = None

# Visible “input loaded” indicators
st.write("")
ads_text = st.session_state.ads_text
src = st.session_state.ads_source_label

if st.session_state.demo_loaded:
    st.markdown(f'<div class="banner"><b>Demo sample loaded ✅</b><br/>{DEMO_SNAPSHOT_NOTE}</div>', unsafe_allow_html=True)
elif ads_text:
    st.markdown(f'<div class="banner" style="background: rgba(0,128,0,0.06); border-color: rgba(0,128,0,0.18);"><b>Input ready ✅</b><br/><span class="muted">Source: {src}</span></div>', unsafe_allow_html=True)
else:
    st.info("Add an ads.txt input (fetch, upload, or paste) to run the audit.")

st.write("")

# Run button (always-on Phase 2 & optional checks are hardcoded ON)
run_col_l, run_col_r = st.columns([3, 2])
with run_col_r:
    run = st.button("Run audit", type="primary", use_container_width=True)

st.divider()

if run:
    if not ads_text:
        st.warning("Please add ads.txt input first (fetch, upload, or paste).")
    else:
        with st.spinner("Analyzing ads.txt…"):
            # Hardcoded ON (per your feedback)
            include_optional_checks = True
            audit_report = analyze_ads_txt(
                text=ads_text,
                source_label=src or "ads.txt",
                include_optional_checks=include_optional_checks,
            )

        sellers_report = None
        with st.spinner("Verifying seller accounts (sellers.json)…"):
            sellers_report = call_sellers_verification(ads_text)

        st.session_state.audit_report = audit_report
        st.session_state.sellers_report = sellers_report

        # Evidence locker (always on; silent if storage unavailable)
        ev_path = evidence_write_run(
            ads_txt_text=ads_text,
            source_label=src or "ads.txt",
            audit_report=audit_report,
            sellers_report=sellers_report,
            fetch_debug=st.session_state.fetch_debug,
        )
        st.session_state.evidence_path = ev_path

# -----------------------------
# Results
# -----------------------------
audit_report = st.session_state.audit_report
sellers_report = st.session_state.sellers_report

if audit_report:
    sm = audit_report.get("summary", {}) or {}
    risk_score = clamp_int(sm.get("risk_score"), 0, 100, default=0)
    risk_level = pretty_level(sm.get("risk_level"))
    findings_count = clamp_int(sm.get("finding_count"), 0, 10**9, default=0)
    entry_count = clamp_int(sm.get("entry_count"), 0, 10**9, default=0)

    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Risk score", risk_score)
    m2.metric("Risk level", risk_level)
    m3.metric("Findings", findings_count)
    m4.metric("Entries", entry_count)

    # Summary line
    rc = sm.get("rule_counts", {}) or {}
    low = rc.get("LOW", None)  # not used; analyzer uses per-rule counts, not per-severity
    st.subheader("Summary")
    # Build severity breakdown from findings list
    sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in audit_report.get("findings", []) or []:
        sev = str(f.get("severity", "")).upper()
        if sev in sev_counts:
            sev_counts[sev] += 1

    st.write(
        f"Found **{findings_count}** buyer-relevant flags. "
        f"Breakdown: **CRITICAL:** {sev_counts['CRITICAL']}, **HIGH:** {sev_counts['HIGH']}, "
        f"**MEDIUM:** {sev_counts['MEDIUM']}, **LOW:** {sev_counts['LOW']}."
    )

    # Download buttons
    dl1, dl2, dl3, dl4 = st.columns([1, 1, 1, 2], gap="small")
    with dl1:
        st.download_button(
            "Download JSON",
            data=report_to_json_bytes(audit_report),
            file_name="adchainaudit_report.json",
            mime="application/json",
            use_container_width=True,
        )
    with dl2:
        st.download_button(
            "Download TXT",
            data=report_to_txt_bytes(audit_report),
            file_name="adchainaudit_report.txt",
            mime="text/plain",
            use_container_width=True,
        )
    with dl3:
        st.download_button(
            "Download CSV",
            data=report_to_csv_bytes(audit_report),
            file_name="adchainaudit_findings.csv",
            mime="text/csv",
            use_container_width=True,
        )

    with dl4:
        ev_path = st.session_state.evidence_path
        if ev_path and Path(ev_path).exists():
            st.download_button(
                "Download buyer pack (ZIP)",
                data=zip_dir_bytes(Path(ev_path)),
                file_name=f"{Path(ev_path).name}.zip",
                mime="application/zip",
                use_container_width=True,
            )
        else:
            st.button("Download buyer pack (ZIP)", disabled=True, use_container_width=True)

    st.write("")
    st.subheader("Buyer-relevant red flags")

    # Group findings by severity with expandable sections
    findings = audit_report.get("findings", []) or []
    by_sev: Dict[str, list] = {"CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": []}
    for f in findings:
        sev = str(f.get("severity", "LOW")).upper()
        if sev not in by_sev:
            sev = "LOW"
        by_sev[sev].append(f)

    # Show the most important first
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        items = by_sev.get(sev, [])
        if not items:
            continue
        with st.expander(f"{sev} ({len(items)})", expanded=(sev in {"CRITICAL", "HIGH"})):
            # Keep this readable: show top 60, and provide count
            max_show = 60
            for i, f in enumerate(items[:max_show], start=1):
                ev = f.get("evidence", {}) or {}
                title = f.get("title", "Finding")
                why = f.get("why_buyer_cares", "")
                rec = f.get("recommendation", "")
                line_no = ev.get("line_no", None)
                line = ev.get("line", "")

                st.markdown(f"**{i}. {title}**")
                if why:
                    st.markdown(f"- *Why buyer cares:* {why}")
                if rec:
                    st.markdown(f"- *What to do:* {rec}")
                if line:
                    if line_no is not None:
                        st.code(f"Line {line_no}: {line}", language="text")
                    else:
                        st.code(line, language="text")
                st.write("")

            if len(items) > max_show:
                st.info(f"Showing top {max_show} items. Download CSV for the full list.")

    st.divider()

# -----------------------------
# Phase 2: sellers.json (summarized output)
# -----------------------------
if sellers_report:
    st.subheader("Seller verification (sellers.json) — summary")

    ssum = sellers_report.get("summary", {}) or {}
    domains_checked = clamp_int(ssum.get("domains_checked"), 0, 10**9, 0)
    reachable = clamp_int(ssum.get("reachable"), 0, 10**9, 0)
    unreachable = clamp_int(ssum.get("unreachable"), 0, 10**9, 0)
    total_ids = clamp_int(ssum.get("total_seller_ids_checked"), 0, 10**12, 0)
    matched_ids = clamp_int(ssum.get("total_seller_ids_matched"), 0, 10**12, 0)
    avg_match = ssum.get("avg_match_rate", None)

    p1, p2, p3, p4 = st.columns(4)
    p1.metric("Seller systems checked", domains_checked)
    p2.metric("Reachable sellers.json", reachable)
    p3.metric("Unreachable / blocked", unreachable)
    p4.metric("Avg match rate", safe_pct(avg_match))

    st.caption(
        "Match rate compares seller IDs seen in ads.txt to seller_id entries found in each ad system’s sellers.json. "
        "Low match rate can mean stale ads.txt entries, non-standard endpoints, or unclear selling relationships."
    )

    domain_stats = sellers_report.get("domain_stats", []) or []

    # Build quick buckets
    low_match = []
    ok_match = []
    blocked = []
    for d in domain_stats:
        status = d.get("status", None)
        json_ok = bool(d.get("json_ok", False))
        mr = d.get("match_rate", 0) or 0
        dom = d.get("domain", "")
        err = d.get("error", None)
        if not json_ok or status is None or (isinstance(status, int) and status >= 400) or err:
            blocked.append(d)
        elif mr < 0.2:
            low_match.append(d)
        else:
            ok_match.append(d)

    # Pills
    st.markdown(
        f"""
<span class="pill pill-ok">Good / usable: {len(ok_match)}</span>
<span class="pill pill-warn">Low match (&lt;20%): {len(low_match)}</span>
<span class="pill pill-bad">Unreachable / not JSON: {len(blocked)}</span>
""",
        unsafe_allow_html=True,
    )

    # Show a clean table: Top issues + worst match
    # Keep it simple: show top 10 worst reachable + list blocked domains
    reachable_rows = [d for d in domain_stats if d.get("json_ok") and d.get("status") == 200]
    reachable_sorted = sorted(reachable_rows, key=lambda x: (x.get("match_rate") or 0))
    worst10 = reachable_sorted[:10]

    if worst10:
        st.markdown("**Worst match (reachable sellers.json):**")
        table = []
        for d in worst10:
            table.append(
                {
                    "Domain": d.get("domain"),
                    "Seller IDs in ads.txt": d.get("seller_ids_in_ads_txt"),
                    "Matched": d.get("seller_ids_matched"),
                    "Match rate": f"{(d.get('match_rate') or 0):.2f}",
                }
            )
        st.dataframe(table, use_container_width=True, hide_index=True)

    if blocked:
        st.markdown("**Unreachable / blocked / not JSON (top):**")
        blk_table = []
        for d in blocked[:12]:
            blk_table.append(
                {
                    "Domain": d.get("domain"),
                    "Status": d.get("status"),
                    "Reason": (d.get("error") or "Not JSON / blocked")[:140],
                }
            )
        st.dataframe(blk_table, use_container_width=True, hide_index=True)

    # Turn the verbose findings into a short “what to do next”
    st.markdown("**What this means for a buyer**")
    bullets = []
    if len(low_match) > 0:
        bullets.append(
            f"- **{len(low_match)} seller systems have low match**: many seller IDs in ads.txt couldn’t be validated. "
            "Treat as a transparency question and ask for the preferred path (DIRECT where possible)."
        )
    if len(blocked) > 0:
        bullets.append(
            f"- **{len(blocked)} seller systems couldn’t be verified** (blocked/unreachable/not JSON). "
            "That’s a verification gap. You may need seller-side confirmation."
        )
    if not bullets:
        bullets.append(
            "- Most sellers.json files were reachable and match rates look reasonable. Use this as supporting evidence "
            "when tightening preferred paths."
        )
    st.markdown("\n".join(bullets))

    # Optional: show detailed findings (still available, but not a wall of JSON)
    with st.expander("Detailed seller-verification findings (advanced)"):
        sf = sellers_report.get("findings", []) or []
        # show a trimmed list
        max_show = 30
        for i, f in enumerate(sf[:max_show], start=1):
            st.markdown(f"**{i}. [{f.get('severity','')}] {f.get('title','')}**")
            if f.get("why_buyer_cares"):
                st.markdown(f"- *Why buyer cares:* {f.get('why_buyer_cares')}")
            if f.get("recommendation"):
                st.markdown(f"- *What to do:* {f.get('recommendation')}")
            ev = f.get("evidence", {}) or {}
            line = ev.get("line", "")
            if line:
                st.code(line, language="text")
            st.write("")
        if len(sf) > max_show:
            st.info(f"Showing top {max_show} items. Download the buyer pack ZIP for the full JSON.")

