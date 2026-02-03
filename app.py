# app.py
from __future__ import annotations

import io
import json
import re
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Tuple
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

import streamlit as st

from analyzer import analyze_ads_txt, report_to_csv_bytes, report_to_json_bytes, report_to_txt_bytes

try:
    from phase2_sellers_json import run_sellers_json_verification  # type: ignore
except Exception:
    run_sellers_json_verification = None  # type: ignore

from phase3_schain import parse_schain_text, analyze_schain


APP_VERSION = "0.9"
EVIDENCE_DIR = Path("evidence")
SAMPLES_DIR = Path("samples")
DEMO_ADS_PATH = SAMPLES_DIR / "ads.txt"
DEMO_SCHAIN_PATH = SAMPLES_DIR / "schain_sample.json"

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
    s = _clean_domain_or_url(domain_or_url)
    if not s:
        return tuple()

    if _looks_like_url(s):
        url = s.rstrip("/")
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

    urls = []
    for u in [https_main, https_www, http_main, http_www]:
        if u not in urls:
            urls.append(u)
    return tuple(urls)


def fetch_text(url: str, timeout_s: int = 8) -> Tuple[Optional[str], Dict[str, Any]]:
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


def zip_dir_bytes(folder: Path) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for p in folder.rglob("*"):
            if p.is_file():
                zf.write(p, arcname=str(p.relative_to(folder)))
    return buf.getvalue()


def evidence_write_run(
    *,
    ads_txt_text: str,
    source_label: str,
    audit_report: Dict[str, Any],
    sellers_report: Optional[Dict[str, Any]],
    fetch_debug: Optional[Dict[str, Any]],
    schain_text: Optional[str],
    schain_report: Optional[Dict[str, Any]],
) -> Optional[Path]:
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

        meta = {"generated_at": now_iso(), "app_version": APP_VERSION, "source_label": source_label}
        if fetch_debug:
            meta["fetch_debug"] = fetch_debug
        (run_dir / "run_meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")

        if sellers_report is not None:
            (run_dir / "sellers_verification.json").write_text(
                json.dumps(sellers_report, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )

        if schain_text and schain_report:
            (run_dir / "input_schain.json").write_text(schain_text, encoding="utf-8", errors="ignore")
            (run_dir / "schain_report.json").write_text(
                json.dumps(schain_report, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
            dot = schain_report.get("graphviz_dot")
            if dot:
                (run_dir / "schain_graph.dot").write_text(dot, encoding="utf-8")

        return run_dir
    except Exception:
        return None


def call_sellers_verification(ads_txt_text: str) -> Optional[Dict[str, Any]]:
    if run_sellers_json_verification is None:
        return None
    try:
        return run_sellers_json_verification(ads_txt_text)
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


# -----------------------------
# UI
# -----------------------------
st.set_page_config(page_title="AdChainAudit", page_icon="🛡️", layout="wide")

st.markdown(
    """
<style>
.block-container { padding-top: 1.25rem; padding-bottom: 2rem; max-width: 1200px; }
h1, h2, h3 { letter-spacing: -0.02em; }
.card {
  border: 1px solid rgba(49, 51, 63, 0.12);
  border-radius: 16px;
  padding: 16px 16px;
  background: white;
  box-shadow: 0 1px 12px rgba(0,0,0,0.04);
}
.card-title { font-weight: 800; font-size: 0.95rem; margin-bottom: 10px; opacity: 0.95; }
.muted { opacity: 0.7; }
.pill {
  display: inline-block;
  padding: 6px 10px;
  border-radius: 999px;
  font-size: 12px;
  font-weight: 800;
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
  background: rgba(0,128,0,0.06);
}
.banner-warn { background: rgba(255,165,0,0.10); border-color: rgba(255,165,0,0.22); }
.stButton > button { border-radius: 12px !important; padding: 10px 14px !important; font-weight: 800 !important; }
div[data-testid="stMetricValue"] { font-size: 34px; }
</style>
""",
    unsafe_allow_html=True,
)

# -----------------------------
# State
# -----------------------------
for k, v in {
    "ads_text": None,
    "ads_source_label": None,
    "fetch_debug": None,
    "demo_loaded": False,
    "audit_report": None,
    "sellers_report": None,
    "schain_text": None,
    "schain_report": None,
    "evidence_path": None,
}.items():
    if k not in st.session_state:
        st.session_state[k] = v


# -----------------------------
# Header
# -----------------------------
top_l, top_r = st.columns([3, 1])
with top_l:
    st.title("AdChainAudit")
    st.caption("Buyer-focused supply-path sanity checks: ads.txt + sellers.json + schain (Phase 3 quick view).")
with top_r:
    st.link_button("GitHub (technical)", "https://github.com/maazkhan86/AdChainAudit", use_container_width=True)

st.write("")

# -----------------------------
# Inputs
# -----------------------------
st.subheader("Inputs")

c1, c2, c3 = st.columns(3, gap="large")
with c1:
    st.markdown('<div class="card">', unsafe_allow_html=True)
    st.markdown('<div class="card-title">1) Fetch ads.txt</div>', unsafe_allow_html=True)
    domain_or_url = st.text_input("Website domain or ads.txt URL", placeholder="example.com", label_visibility="collapsed")
    fetch_btn = st.button("Fetch ads.txt", use_container_width=True)
    st.markdown('<div class="muted" style="margin-top:6px;">We try https then http. If blocked, upload or paste.</div>', unsafe_allow_html=True)
    st.markdown("</div>", unsafe_allow_html=True)

with c2:
    st.markdown('<div class="card">', unsafe_allow_html=True)
    st.markdown('<div class="card-title">2) Upload ads.txt (optional)</div>', unsafe_allow_html=True)
    up = st.file_uploader("Upload ads.txt", type=["txt"], label_visibility="collapsed")
    demo_btn = st.button("Load demo ads.txt", use_container_width=True)
    st.markdown("</div>", unsafe_allow_html=True)

with c3:
    st.markdown('<div class="card">', unsafe_allow_html=True)
    st.markdown('<div class="card-title">3) Paste ads.txt (optional)</div>', unsafe_allow_html=True)
    pasted = st.text_area("Paste ads.txt", height=120, placeholder="Paste ads.txt text here…", label_visibility="collapsed")
    st.markdown("</div>", unsafe_allow_html=True)

# schain inputs
st.write("")
s1, s2, s3 = st.columns(3, gap="large")
with s1:
    st.markdown('<div class="card">', unsafe_allow_html=True)
    st.markdown('<div class="card-title">4) Upload schain JSON (optional)</div>', unsafe_allow_html=True)
    sch_up = st.file_uploader("Upload schain JSON", type=["json", "txt"], label_visibility="collapsed", key="sch_up")
    sch_demo_btn = st.button("Load demo schain", use_container_width=True)
    st.markdown("</div>", unsafe_allow_html=True)

with s2:
    st.markdown('<div class="card">', unsafe_allow_html=True)
    st.markdown('<div class="card-title">5) Paste schain JSON (optional)</div>', unsafe_allow_html=True)
    sch_paste = st.text_area("Paste schain JSON", height=120, placeholder='{"ver":"1.0","complete":0,"nodes":[...]}', label_visibility="collapsed")
    st.markdown("</div>", unsafe_allow_html=True)

with s3:
    st.markdown('<div class="card">', unsafe_allow_html=True)
    st.markdown('<div class="card-title">Run</div>', unsafe_allow_html=True)
    run = st.button("Run audit", type="primary", use_container_width=True)
    st.markdown('<div class="muted" style="margin-top:6px;">Phase 2 (sellers.json) + optional signals are ON by default.</div>', unsafe_allow_html=True)
    st.markdown("</div>", unsafe_allow_html=True)

# Actions: ads.txt
if fetch_btn:
    if not domain_or_url.strip():
        st.warning("Enter a website domain or full ads.txt URL first.")
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
            with st.expander("Fetch details (troubleshooting)"):
                st.json(dbg)

if up is not None:
    try:
        st.session_state.ads_text = up.getvalue().decode("utf-8")
    except Exception:
        st.session_state.ads_text = (up.getvalue() or b"").decode("latin-1", errors="replace")
    st.session_state.ads_source_label = f"uploaded:{up.name}"
    st.session_state.demo_loaded = False
    st.session_state.fetch_debug = None

if demo_btn:
    if DEMO_ADS_PATH.exists():
        st.session_state.ads_text = DEMO_ADS_PATH.read_text(encoding="utf-8", errors="ignore")
        st.session_state.ads_source_label = "demo:samples/ads.txt"
        st.session_state.demo_loaded = True
        st.session_state.fetch_debug = None
    else:
        st.error("Demo ads.txt not found at ./samples/ads.txt")

if pasted and pasted.strip():
    st.session_state.ads_text = pasted.strip()
    st.session_state.ads_source_label = "pasted:textarea"
    st.session_state.demo_loaded = False
    st.session_state.fetch_debug = None

# Actions: schain
if sch_up is not None:
    try:
        st.session_state.schain_text = sch_up.getvalue().decode("utf-8")
    except Exception:
        st.session_state.schain_text = (sch_up.getvalue() or b"").decode("latin-1", errors="replace")

if sch_demo_btn:
    if DEMO_SCHAIN_PATH.exists():
        st.session_state.schain_text = DEMO_SCHAIN_PATH.read_text(encoding="utf-8", errors="ignore")
        st.success("Demo schain loaded ✅")
    else:
        st.error("Demo schain not found at ./samples/schain_sample.json")

if sch_paste and sch_paste.strip():
    st.session_state.schain_text = sch_paste.strip()

# Input banners
st.write("")
if st.session_state.ads_text:
    src = st.session_state.ads_source_label or "ads.txt"
    note = DEMO_SNAPSHOT_NOTE if st.session_state.demo_loaded else f"Source: {src}"
    st.markdown(f'<div class="banner"><b>ads.txt ready ✅</b><br/><span class="muted">{note}</span></div>', unsafe_allow_html=True)
else:
    st.markdown('<div class="banner banner-warn"><b>ads.txt missing</b><br/><span class="muted">Add an ads.txt input to run the audit.</span></div>', unsafe_allow_html=True)

if st.session_state.schain_text:
    st.markdown('<div class="banner"><b>schain ready ✅</b><br/><span class="muted">Phase 3 quick view will run if JSON is valid.</span></div>', unsafe_allow_html=True)

st.divider()

# -----------------------------
# Run
# -----------------------------
if run:
    if not st.session_state.ads_text:
        st.warning("Please add ads.txt input first (fetch, upload, or paste).")
    else:
        ads_text = st.session_state.ads_text
        src = st.session_state.ads_source_label or "ads.txt"

        with st.spinner("Analyzing ads.txt…"):
            audit_report = analyze_ads_txt(
                text=ads_text,
                source_label=src,
                include_optional_checks=True,  # hardcoded ON
            )

        with st.spinner("Verifying seller accounts (sellers.json)…"):
            sellers_report = call_sellers_verification(ads_text)

        schain_report = None
        sch_text = st.session_state.schain_text
        if sch_text and sch_text.strip():
            with st.spinner("Parsing schain (Phase 3 quick view)…"):
                sch_obj, err = parse_schain_text(sch_text)
                if err:
                    schain_report = {
                        "meta": {"generated_at": now_iso(), "source_label": "schain", "version": "0.1-phase3-quickview"},
                        "summary": {"error": err},
                        "nodes": [],
                        "findings": [],
                    }
                else:
                    schain_report = analyze_schain(
                        sch_obj, source_label="schain", ads_txt_text=ads_text
                    )

        st.session_state.audit_report = audit_report
        st.session_state.sellers_report = sellers_report
        st.session_state.schain_report = schain_report

        ev_path = evidence_write_run(
            ads_txt_text=ads_text,
            source_label=src,
            audit_report=audit_report,
            sellers_report=sellers_report,
            fetch_debug=st.session_state.fetch_debug,
            schain_text=sch_text,
            schain_report=schain_report,
        )
        st.session_state.evidence_path = ev_path

# -----------------------------
# Results
# -----------------------------
audit_report = st.session_state.audit_report
sellers_report = st.session_state.sellers_report
schain_report = st.session_state.schain_report

if audit_report:
    st.subheader("Phase 1 — ads.txt audit")

    sm = audit_report.get("summary", {}) or {}
    risk_score = clamp_int(sm.get("risk_score"), 0, 100, 0)
    risk_level = pretty_level(sm.get("risk_level"))
    findings_count = clamp_int(sm.get("finding_count"), 0, 10**9, 0)
    entry_count = clamp_int(sm.get("entry_count"), 0, 10**9, 0)

    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Risk score", risk_score)
    m2.metric("Risk level", risk_level)
    m3.metric("Findings", findings_count)
    m4.metric("Entries", entry_count)

    # Key takeaways
    top_rules = sm.get("top_rules", []) or []
    st.markdown("### Key takeaways")
    if top_rules:
        # Take top 3 issues
        bullets = []
        for r in top_rules[:3]:
            bullets.append(f"- **{r.get('rule_id')}** ({r.get('severity')}) — {r.get('count')} occurrences")
        st.markdown("\n".join(bullets))
    else:
        st.markdown("- No major issues detected by current rules.")

    # Top issues table
    st.markdown("### Top issues (what to ask / do)")
    if top_rules:
        rows = []
        for r in top_rules[:10]:
            rid = r.get("rule_id")
            sev = r.get("severity")
            cnt = r.get("count")
            action = "Ask publisher to fix formatting/authorization." if rid in {"MALFORMED_LINE", "INVALID_RELATIONSHIP"} else \
                     "Ask for preferred DIRECT route and clarify reselling." if rid in {"RELATIONSHIP_AMBIGUITY"} else \
                     "Optional cleanup; does not block buying." if rid == "MISSING_CAID" else \
                     "Investigate and validate."
            rows.append({"Rule": rid, "Severity": sev, "Count": cnt, "Buyer action": action})
        st.dataframe(rows, use_container_width=True, hide_index=True)
    else:
        st.info("No top issues to show.")

    # Top ad systems
    st.markdown("### Top ad systems referenced in ads.txt")
    top_domains = sm.get("top_ad_systems", []) or []
    if top_domains:
        st.dataframe(top_domains, use_container_width=True, hide_index=True)

    # Downloads
    dl1, dl2, dl3, dl4 = st.columns([1, 1, 1, 2], gap="small")
    with dl1:
        st.download_button("Download JSON", data=report_to_json_bytes(audit_report), file_name="adchainaudit_report.json",
                           mime="application/json", use_container_width=True)
    with dl2:
        st.download_button("Download TXT", data=report_to_txt_bytes(audit_report), file_name="adchainaudit_report.txt",
                           mime="text/plain", use_container_width=True)
    with dl3:
        st.download_button("Download CSV", data=report_to_csv_bytes(audit_report), file_name="adchainaudit_findings.csv",
                           mime="text/csv", use_container_width=True)
    with dl4:
        ev_path = st.session_state.evidence_path
        if ev_path and Path(ev_path).exists():
            st.download_button("Download buyer pack (ZIP)", data=zip_dir_bytes(Path(ev_path)),
                               file_name=f"{Path(ev_path).name}.zip", mime="application/zip", use_container_width=True)
        else:
            st.button("Download buyer pack (ZIP)", disabled=True, use_container_width=True)

    # Detailed findings (kept, but not the only thing)
    with st.expander("Detailed findings (advanced)", expanded=False):
        findings = audit_report.get("findings", []) or []
        # show only first 80 for UI sanity
        max_show = 80
        for i, f in enumerate(findings[:max_show], start=1):
            ev = f.get("evidence", {}) or {}
            st.markdown(f"**{i}. [{f.get('severity')}] {f.get('title')}**")
            if f.get("why_buyer_cares"):
                st.markdown(f"- *Why buyer cares:* {f.get('why_buyer_cares')}")
            if f.get("recommendation"):
                st.markdown(f"- *What to do:* {f.get('recommendation')}")
            line = ev.get("line", "")
            if line:
                ln = ev.get("line_no")
                if ln is not None:
                    st.code(f"Line {ln}: {line}", language="text")
                else:
                    st.code(line, language="text")
            st.write("")
        if len(findings) > max_show:
            st.info(f"Showing top {max_show} items. Download CSV for the full list.")

    st.divider()

# -----------------------------
# Phase 2 summary
# -----------------------------
if sellers_report:
    st.subheader("Phase 2 — sellers.json verification (summary)")

    ssum = sellers_report.get("summary", {}) or {}
    domains_checked = clamp_int(ssum.get("domains_checked"), 0, 10**9, 0)
    reachable = clamp_int(ssum.get("reachable"), 0, 10**9, 0)
    unreachable = clamp_int(ssum.get("unreachable"), 0, 10**9, 0)
    avg_match = ssum.get("avg_match_rate", None)

    p1, p2, p3, p4 = st.columns(4)
    p1.metric("Systems checked", domains_checked)
    p2.metric("Reachable", reachable)
    p3.metric("Unreachable", unreachable)
    p4.metric("Avg match rate", safe_pct(avg_match))

    domain_stats = sellers_report.get("domain_stats", []) or []

    low_match, ok_match, blocked = [], [], []
    for d in domain_stats:
        status = d.get("status", None)
        json_ok = bool(d.get("json_ok", False))
        mr = d.get("match_rate", 0) or 0
        err = d.get("error", None)
        if not json_ok or status is None or (isinstance(status, int) and status >= 400) or err:
            blocked.append(d)
        elif mr < 0.2:
            low_match.append(d)
        else:
            ok_match.append(d)

    st.markdown(
        f"""
<span class="pill pill-ok">Good/usable: {len(ok_match)}</span>
<span class="pill pill-warn">Low match (&lt;20%): {len(low_match)}</span>
<span class="pill pill-bad">Unreachable/not JSON: {len(blocked)}</span>
""",
        unsafe_allow_html=True,
    )

    reachable_rows = [d for d in domain_stats if d.get("json_ok") and d.get("status") == 200]
    reachable_sorted = sorted(reachable_rows, key=lambda x: (x.get("match_rate") or 0))
    worst10 = reachable_sorted[:10]

    if worst10:
        st.markdown("**Worst match (reachable sellers.json):**")
        st.dataframe(
            [
                {
                    "Domain": d.get("domain"),
                    "Seller IDs in ads.txt": d.get("seller_ids_in_ads_txt"),
                    "Matched": d.get("seller_ids_matched"),
                    "Match rate": f"{(d.get('match_rate') or 0):.2f}",
                }
                for d in worst10
            ],
            use_container_width=True,
            hide_index=True,
        )

    if blocked:
        st.markdown("**Unreachable / blocked / not JSON (top):**")
        st.dataframe(
            [
                {"Domain": d.get("domain"), "Status": d.get("status"), "Reason": (d.get("error") or "")[:140]}
                for d in blocked[:12]
            ],
            use_container_width=True,
            hide_index=True,
        )

    st.markdown("**Buyer actions**")
    bullets = []
    if len(low_match) > 0:
        bullets.append(
            f"- **{len(low_match)} systems have low match**: many seller IDs in ads.txt could not be validated. Ask for the preferred path (DIRECT where possible)."
        )
    if len(blocked) > 0:
        bullets.append(
            f"- **{len(blocked)} systems could not be verified** (blocked/unreachable/not JSON). Treat as a transparency gap; request confirmation."
        )
    if not bullets:
        bullets.append("- Sellers.json verification looks healthy overall. Use this to support SPO conversations.")
    st.markdown("\n".join(bullets))

    with st.expander("Detailed seller-verification findings (advanced)"):
        sf = sellers_report.get("findings", []) or []
        max_show = 30
        for i, f in enumerate(sf[:max_show], start=1):
            st.markdown(f"**{i}. [{f.get('severity','')}] {f.get('title','')}**")
            if f.get("why_buyer_cares"):
                st.markdown(f"- *Why buyer cares:* {f.get('why_buyer_cares')}")
            if f.get("recommendation"):
                st.markdown(f"- *What to do:* {f.get('recommendation')}")
            ev = f.get("evidence", {}) or {}
            if ev:
                st.code(json.dumps(ev, indent=2, ensure_ascii=False), language="json")
            st.write("")
        if len(sf) > max_show:
            st.info(f"Showing top {max_show}. Download the buyer pack ZIP for full JSON.")

    st.divider()

# -----------------------------
# Phase 3 quick view
# -----------------------------
if schain_report:
    st.subheader("Phase 3 — schain quick view")

    ssum = schain_report.get("summary", {}) or {}
    if ssum.get("error"):
        st.error(f"schain error: {ssum.get('error')}")
    else:
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Hops", clamp_int(ssum.get("hops"), 0, 10**6, 0))
        c2.metric("Complete", str(ssum.get("complete")))
        c3.metric("Direct hops", clamp_int(ssum.get("direct_hops"), 0, 10**6, 0))
        c4.metric("Reseller hops", clamp_int(ssum.get("reseller_hops"), 0, 10**6, 0))

        dot = schain_report.get("graphviz_dot")
        if dot:
            st.markdown("### Supply path visualization")
            st.graphviz_chart(dot, use_container_width=True)

        st.markdown("### Nodes")
        st.dataframe(schain_report.get("nodes", []) or [], use_container_width=True, hide_index=True)

        st.markdown("### schain findings (buyer-relevant)")
        f = schain_report.get("findings", []) or []
        if not f:
            st.info("No schain issues detected by current rules.")
        else:
            max_show = 20
            for i, x in enumerate(f[:max_show], start=1):
                st.markdown(f"**{i}. [{x.get('severity')}] {x.get('title')}**")
                if x.get("why_buyer_cares"):
                    st.markdown(f"- *Why buyer cares:* {x.get('why_buyer_cares')}")
                if x.get("recommendation"):
                    st.markdown(f"- *What to do:* {x.get('recommendation')}")
                if x.get("evidence"):
                    st.code(json.dumps(x.get("evidence"), indent=2, ensure_ascii=False), language="json")
                st.write("")
            if len(f) > max_show:
                st.info(f"Showing top {max_show}. Download buyer pack ZIP for full schain report.")
