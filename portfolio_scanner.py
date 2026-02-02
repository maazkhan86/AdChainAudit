# portfolio_scanner.py
from __future__ import annotations

import csv
import io
import json
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _looks_like_url(s: str) -> bool:
    s = (s or "").strip().lower()
    return s.startswith("http://") or s.startswith("https://")


def _normalize_domain(s: str) -> str:
    s = (s or "").strip()
    s = re.sub(r"^https?://", "", s, flags=re.I)
    s = s.split("/", 1)[0]
    return s.strip()


def build_ads_txt_candidates(domain_or_url: str) -> Tuple[str, ...]:
    s = (domain_or_url or "").strip()
    if not s:
        return tuple()

    if _looks_like_url(s):
        url = s[:-1] if s.endswith("/") else s
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

    urls: List[str] = []
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


def fetch_ads_txt(domain_or_url: str, timeout_s: int = 8) -> Tuple[Optional[str], Dict[str, Any]]:
    candidates = build_ads_txt_candidates(domain_or_url)
    debug: Dict[str, Any] = {"attempts": [], "chosen": None}
    for u in candidates:
        text, meta = fetch_text(u, timeout_s=timeout_s)
        debug["attempts"].append(meta)
        if text and meta.get("ok"):
            debug["chosen"] = u
            return text, debug
    return None, debug


def clamp_int(x: Any, lo: int, hi: int, default: int) -> int:
    try:
        v = int(x)
        return max(lo, min(hi, v))
    except Exception:
        return default


def safe_pct(x: Any) -> str:
    try:
        return f"{float(x) * 100:.0f}%"
    except Exception:
        return "—"


def portfolio_rows_to_csv_bytes(rows: List[Dict[str, Any]]) -> bytes:
    buf = io.StringIO()
    if not rows:
        buf.write("domain\n")
        return buf.getvalue().encode("utf-8")

    # stable header order
    keys = [
        "domain",
        "fetch_ok",
        "fetch_url",
        "fetch_status",
        "risk_score",
        "risk_level",
        "finding_count",
        "entry_count",
        "sellers_domains_checked",
        "sellers_reachable",
        "sellers_unreachable",
        "sellers_avg_match_rate",
        "notes",
    ]
    w = csv.DictWriter(buf, fieldnames=keys, extrasaction="ignore")
    w.writeheader()
    for r in rows:
        w.writerow(r)
    return buf.getvalue().encode("utf-8")


def run_portfolio_scan(
    *,
    domains: List[str],
    analyze_ads_txt_fn,  # analyzer.analyze_ads_txt
    sellers_verify_fn=None,  # phase2_sellers_json.run_sellers_json_verification
    timeout_s: int = 8,
    include_optional_checks: bool = True,
    include_phase2: bool = True,
    max_domains: int = 25,
) -> Dict[str, Any]:
    """
    Returns a portfolio report with:
      - rows: one row per domain
      - artifacts: per-domain detailed artifacts (ads.txt, audit_report, sellers_report, fetch_debug)
    """
    cleaned: List[str] = []
    for d in domains:
        s = (d or "").strip()
        if not s:
            continue
        cleaned.append(_normalize_domain(s) if not _looks_like_url(s) else s)
    # de-dupe preserve order
    seen = set()
    uniq: List[str] = []
    for d in cleaned:
        if d in seen:
            continue
        seen.add(d)
        uniq.append(d)

    uniq = uniq[:max_domains]

    rows: List[Dict[str, Any]] = []
    artifacts: Dict[str, Any] = {}

    fetched_ok = 0
    total_risk = 0
    risk_count = 0
    high_risk = 0

    for d in uniq:
        ads_text, dbg = fetch_ads_txt(d, timeout_s=timeout_s)
        fetch_ok = bool(ads_text)
        chosen = (dbg or {}).get("chosen")
        status = None
        if dbg and dbg.get("attempts"):
            # best-effort: status from chosen attempt if possible
            for a in dbg["attempts"]:
                if a.get("url") == chosen:
                    status = a.get("status")
                    break
            if status is None:
                status = dbg["attempts"][-1].get("status")

        row: Dict[str, Any] = {
            "domain": d,
            "fetch_ok": fetch_ok,
            "fetch_url": chosen or "",
            "fetch_status": status,
            "risk_score": "",
            "risk_level": "",
            "finding_count": "",
            "entry_count": "",
            "sellers_domains_checked": "",
            "sellers_reachable": "",
            "sellers_unreachable": "",
            "sellers_avg_match_rate": "",
            "notes": "",
        }

        domain_art: Dict[str, Any] = {"fetch_debug": dbg}

        if not fetch_ok:
            row["notes"] = "Could not fetch ads.txt (blocked/not found)."
            rows.append(row)
            artifacts[d] = domain_art
            continue

        fetched_ok += 1
        domain_art["ads_txt_text"] = ads_text

        audit_report = analyze_ads_txt_fn(
            text=ads_text,
            source_label=f"portfolio:{d}",
            include_optional_checks=include_optional_checks,
        )
        domain_art["audit_report"] = audit_report

        sm = (audit_report or {}).get("summary", {}) or {}
        risk_score = clamp_int(sm.get("risk_score"), 0, 100, 0)
        risk_level = str(sm.get("risk_level") or "").upper()
        finding_count = clamp_int(sm.get("finding_count"), 0, 10**9, 0)
        entry_count = clamp_int(sm.get("entry_count"), 0, 10**9, 0)

        row["risk_score"] = risk_score
        row["risk_level"] = risk_level
        row["finding_count"] = finding_count
        row["entry_count"] = entry_count

        total_risk += risk_score
        risk_count += 1
        if risk_level == "HIGH" or risk_score >= 70:
            high_risk += 1

        sellers_report = None
        if include_phase2 and sellers_verify_fn is not None:
            try:
                sellers_report = sellers_verify_fn(
                    ads_txt_text=ads_text,
                    max_domains=25,
                    timeout_s=6,
                    source_label=f"portfolio:{d}",
                    evidence_locker_enabled=False,  # portfolio evidence handled by app
                )
            except TypeError:
                # fallback signature
                sellers_report = sellers_verify_fn(ads_text)

        if sellers_report:
            domain_art["sellers_report"] = sellers_report
            ssum = sellers_report.get("summary", {}) or {}
            row["sellers_domains_checked"] = ssum.get("domains_checked", "")
            row["sellers_reachable"] = ssum.get("reachable", "")
            row["sellers_unreachable"] = ssum.get("unreachable", "")
            row["sellers_avg_match_rate"] = safe_pct(ssum.get("avg_match_rate", ""))

        rows.append(row)
        artifacts[d] = domain_art

    avg_risk = round(total_risk / risk_count, 1) if risk_count else None

    return {
        "meta": {
            "generated_at": _now_iso(),
            "version": "0.1-portfolio",
            "max_domains": max_domains,
            "timeout_s": timeout_s,
            "include_phase2": include_phase2 and sellers_verify_fn is not None,
        },
        "summary": {
            "domains_submitted": len(domains),
            "domains_scanned": len(uniq),
            "fetched_ok": fetched_ok,
            "fetched_failed": len(uniq) - fetched_ok,
            "avg_risk_score": avg_risk,
            "high_risk_domains": high_risk,
        },
        "rows": rows,
        "artifacts": artifacts,
    }


def report_to_json_bytes(report: Dict[str, Any]) -> bytes:
    return json.dumps(report, indent=2, ensure_ascii=False).encode("utf-8")
