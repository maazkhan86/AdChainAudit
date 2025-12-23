# analyzer.py
from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from io import StringIO
from typing import Dict, List, Optional, Tuple
import csv
import json
import math


ALLOWED_RELATIONSHIPS = {"DIRECT", "RESELLER"}
SEVERITIES_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}


@dataclass
class Evidence:
    line_no: Optional[int] = None
    line: str = ""


@dataclass
class Finding:
    rule_id: str
    severity: str  # CRITICAL/HIGH/MEDIUM/LOW
    title: str
    why_buyer_cares: str
    recommendation: str
    evidence: Evidence


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _strip_inline_comment(line: str) -> str:
    """
    Remove full-line and inline comments.
    Prevents false positives like:
      google.com, pub-1, DIRECT # comment
    """
    s = line.strip()
    if not s:
        return s
    if s.startswith("#"):
        return ""
    if "#" in s:
        s = s.split("#", 1)[0].strip()
    return s


def _split_fields(line: str) -> List[str]:
    return [p.strip() for p in line.split(",")]


def _risk_level(score: int) -> str:
    # Higher score = lower risk
    if score >= 80:
        return "LOW"
    if score >= 55:
        return "MEDIUM"
    return "HIGH"


def _severity_weight(sev: str) -> int:
    return {"CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 1}.get(sev.upper(), 1)


def _bump_max_severity(current: str, candidate: str) -> str:
    c = current.upper()
    n = candidate.upper()
    return n if SEVERITIES_ORDER.get(n, 0) > SEVERITIES_ORDER.get(c, 0) else c


def _severity_counts(findings: List[Finding]) -> Dict[str, int]:
    out = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        sev = (f.severity or "LOW").upper()
        out[sev] = out.get(sev, 0) + 1
    # remove zeros for cleaner UI if you want; keep all for consistency
    return out


def analyze_ads_txt(
    text: str,
    source_label: str = "ads.txt",
    include_optional_checks: bool = False,  # matches app.py
) -> Dict:
    raw_lines = (text or "").splitlines()

    # Parse lines into entries
    entry_rows: List[Tuple[int, str, List[str]]] = []
    for idx, raw in enumerate(raw_lines, start=1):
        cleaned = _strip_inline_comment(raw)
        if not cleaned:
            continue
        fields = _split_fields(cleaned)
        entry_rows.append((idx, cleaned, fields))

    findings: List[Finding] = []

    # Rule: malformed lines
    for line_no, line, fields in entry_rows:
        if len(fields) not in (3, 4):
            findings.append(
                Finding(
                    rule_id="MALFORMED_LINE",
                    severity="HIGH",
                    title="Malformed ads.txt line (unexpected number of fields)",
                    why_buyer_cares="Malformed lines reduce machine-readability and can create ambiguity in seller authorization.",
                    recommendation="Ask the publisher to fix formatting. Prefer clean, spec-compliant ads.txt.",
                    evidence=Evidence(line_no=line_no, line=line),
                )
            )

    # Rule: invalid relationship values
    for line_no, line, fields in entry_rows:
        if len(fields) >= 3:
            rel = fields[2].upper()
            if rel not in ALLOWED_RELATIONSHIPS:
                findings.append(
                    Finding(
                        rule_id="INVALID_RELATIONSHIP",
                        severity="HIGH",
                        title="Invalid relationship value (must be DIRECT or RESELLER)",
                        why_buyer_cares="If relationship isn't clearly declared, it's harder to validate the path and enforce preferred routes.",
                        recommendation="Ask the publisher to correct relationship values to DIRECT or RESELLER only.",
                        evidence=Evidence(line_no=line_no, line=line),
                    )
                )

    # Optional: missing CAID (4th field)
    if include_optional_checks:
        for line_no, line, fields in entry_rows:
            # Spec: 4th field optional. We treat missing as a LOW signal.
            if len(fields) == 3:
                findings.append(
                    Finding(
                        rule_id="MISSING_CAID",
                        severity="LOW",
                        title="Missing Certification Authority ID (CAID) field (optional signal)",
                        why_buyer_cares="CAID can help with verification at scale, but many publishers omit it today.",
                        recommendation="Optional: ask the publisher/seller to include CAID where applicable.",
                        evidence=Evidence(line_no=line_no, line=line),
                    )
                )

    # Rule: relationship ambiguity (same seller listed as DIRECT and RESELLER)
    seen: Dict[Tuple[str, str], set] = {}
    for line_no, line, fields in entry_rows:
        if len(fields) >= 3:
            key = (fields[0].lower(), fields[1])
            seen.setdefault(key, set()).add(fields[2].upper())

    ambiguous = {k for k, rels in seen.items() if ("DIRECT" in rels and "RESELLER" in rels)}
    if ambiguous:
        for line_no, line, fields in entry_rows:
            if len(fields) >= 3:
                key = (fields[0].lower(), fields[1])
                if key in ambiguous:
                    findings.append(
                        Finding(
                            rule_id="RELATIONSHIP_AMBIGUITY",
                            severity="MEDIUM",
                            title="Relationship ambiguity (seller appears as DIRECT and RESELLER)",
                            why_buyer_cares="Ambiguity makes it harder to enforce preferred paths and can hide extra intermediaries.",
                            recommendation="Ask which route is preferred and whether DIRECT is available for your buys.",
                            evidence=Evidence(line_no=line_no, line=line),
                        )
                    )

    # Metrics
    entry_count = len(entry_rows)
    direct_count = sum(1 for _, _, f in entry_rows if len(f) >= 3 and f[2].upper() == "DIRECT")
    reseller_count = sum(1 for _, _, f in entry_rows if len(f) >= 3 and f[2].upper() == "RESELLER")

    # Scoring: aggregate by rule with diminishing returns
    rule_counts: Dict[str, int] = {}
    rule_severity: Dict[str, str] = {}

    for f in findings:
        rid = f.rule_id
        rule_counts[rid] = rule_counts.get(rid, 0) + 1
        if rid not in rule_severity:
            rule_severity[rid] = (f.severity or "LOW").upper()
        else:
            rule_severity[rid] = _bump_max_severity(rule_severity[rid], f.severity)

    # Penalty uses log1p(count) so 1000 duplicates doesn't destroy score linearly
    penalty = 0.0
    for rid, cnt in rule_counts.items():
        sev = rule_severity.get(rid, "LOW")
        penalty += _severity_weight(sev) * math.log1p(cnt)

    # Tuning knob: multiplier controls how harsh score is
    score = int(round(100 - (penalty * 6)))
    score = max(0, min(100, score))
    level = _risk_level(score)

    sev_counts = _severity_counts(findings)
    findings_count = len(findings)

    # A short UI-friendly summary sentence
    # Example: "1804 flags (LOW 1374, MEDIUM 430). Score 62 (MEDIUM)."
    parts = []
    for k in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        if sev_counts.get(k, 0) > 0:
            parts.append(f"{k} {sev_counts[k]}")
    breakdown = ", ".join(parts) if parts else "no flags"
    one_liner = f"{findings_count} flags ({breakdown}). Score {score} ({level})."

    # --- Return object ---
    # IMPORTANT: top-level keys make app.py easy and stable.
    report = {
        # Top-level fields (app-friendly)
        "generated_at": _now_iso(),
        "source_label": source_label,
        "version": "0.4",
        "include_optional_checks": include_optional_checks,

        "risk_score": score,
        "risk_level": level,
        "entries": entry_count,
        "findings_count": findings_count,
        "severity_counts": sev_counts,
        "direct_count": direct_count,
        "reseller_count": reseller_count,
        "rule_counts": rule_counts,
        "one_liner": one_liner,

        # Backwards compatible sections
        "meta": {
            "generated_at": _now_iso(),
            "source_label": source_label,
            "version": "0.4",
            "include_optional_checks": include_optional_checks,
        },
        "summary": {
            "risk_score": score,
            "risk_level": level,
            "finding_count": findings_count,
            "entry_count": entry_count,
            "direct_count": direct_count,
            "reseller_count": reseller_count,
            "severity_counts": sev_counts,
            "rule_counts": rule_counts,
        },
        "findings": [asdict(f) for f in findings],
    }

    return report


def report_to_json_bytes(report: Dict) -> bytes:
    return json.dumps(report, indent=2, ensure_ascii=False).encode("utf-8")


def report_to_txt_bytes(report: Dict) -> bytes:
    s = StringIO()

    # Prefer top-level, fall back to summary/meta
    meta = report.get("meta", {})
    summary = report.get("summary", {})

    source = report.get("source_label") or meta.get("source_label", "ads.txt")
    generated = report.get("generated_at") or meta.get("generated_at", "")
    opt = report.get("include_optional_checks")
    if opt is None:
        opt = meta.get("include_optional_checks", False)

    risk_score = report.get("risk_score")
    if risk_score is None:
        risk_score = summary.get("risk_score")

    risk_level = report.get("risk_level") or summary.get("risk_level")

    entries = report.get("entries")
    if entries is None:
        entries = summary.get("entry_count")

    findings_count = report.get("findings_count")
    if findings_count is None:
        findings_count = summary.get("finding_count", len(report.get("findings", [])))

    direct_count = report.get("direct_count")
    if direct_count is None:
        direct_count = summary.get("direct_count")

    reseller_count = report.get("reseller_count")
    if reseller_count is None:
        reseller_count = summary.get("reseller_count")

    s.write("AdChainAudit report\n")
    s.write(f"Source: {source}\n")
    s.write(f"Generated: {generated}\n")
    s.write(f"Optional checks: {bool(opt)}\n\n")

    s.write(f"Risk score: {risk_score} ({risk_level})\n")
    s.write(f"Entries: {entries} | Findings: {findings_count}\n")
    s.write(f"DIRECT: {direct_count} | RESELLER: {reseller_count}\n\n")

    rc = report.get("rule_counts") or summary.get("rule_counts", {})
    if rc:
        s.write("Findings by rule:\n")
        for k, v in sorted(rc.items(), key=lambda x: x[1], reverse=True):
            s.write(f"- {k}: {v}\n")
        s.write("\n")

    for i, f in enumerate(report.get("findings", []), start=1):
        ev = f.get("evidence", {})
        s.write(f"{i}. [{f.get('severity')}] {f.get('title')}\n")
        s.write(f"   Why buyer cares: {f.get('why_buyer_cares')}\n")
        if ev.get("line_no") is not None:
            s.write(f"   Evidence: Line {ev.get('line_no')}: {ev.get('line','')}\n")
        rec = f.get("recommendation")
        if rec:
            s.write(f"   What to do: {rec}\n")
        s.write("\n")

    return s.getvalue().encode("utf-8")


def report_to_csv_bytes(report: Dict) -> bytes:
    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(["severity", "rule_id", "title", "line_no", "line", "why_buyer_cares", "recommendation"])
    for f in report.get("findings", []):
        ev = f.get("evidence", {})
        writer.writerow(
            [
                f.get("severity", ""),
                f.get("rule_id", ""),
                f.get("title", ""),
                ev.get("line_no", ""),
                ev.get("line", ""),
                f.get("why_buyer_cares", ""),
                f.get("recommendation", ""),
            ]
        )
    return output.getvalue().encode("utf-8")
