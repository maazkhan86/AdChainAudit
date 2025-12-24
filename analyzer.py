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

# If you later want to expand heuristics, keep these in one place.
SUSPICIOUS_RELATIONSHIPS = {"BOTH"}  # not valid for ads.txt but sometimes appears


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
    # Higher score = cleaner file = lower risk
    if score >= 80:
        return "LOW"
    if score >= 55:
        return "MEDIUM"
    return "HIGH"


def _severity_weight(sev: str) -> float:
    # Keep LOW minimal; optional signals should not crush the score.
    return {"CRITICAL": 10.0, "HIGH": 7.0, "MEDIUM": 4.0, "LOW": 0.8}.get(sev, 0.8)


def _clamp(x: int, lo: int = 0, hi: int = 100) -> int:
    return max(lo, min(hi, x))


def analyze_ads_txt(
    text: str,
    source_label: str = "ads.txt",
    include_optional_checks: bool = True,  # keep param for backwards compatibility
) -> Dict:
    raw_lines = text.splitlines()

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

    # Optional: missing CAID (4th field) - informational only (do not penalize score heavily)
    if include_optional_checks:
        for line_no, line, fields in entry_rows:
            if len(fields) == 3:
                findings.append(
                    Finding(
                        rule_id="MISSING_CAID",
                        severity="LOW",
                        title="Missing CAID field (optional signal)",
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

    # Heuristic: reseller-heavy file (not always bad, but worth asking)
    if entry_count >= 20:
        reseller_share = reseller_count / max(1, entry_count)
        if reseller_share >= 0.75:
            findings.append(
                Finding(
                    rule_id="RESELLER_HEAVY",
                    severity="MEDIUM",
                    title="Reseller-heavy ads.txt",
                    why_buyer_cares="A reseller-heavy setup can mean more hops, more fees, and less path control (not always wrong, but worth clarifying).",
                    recommendation="Ask for preferred DIRECT paths (if available) and which resellers are required vs legacy.",
                    evidence=Evidence(line_no=None, line=f"RESELLER share ≈ {round(reseller_share, 2)}"),
                )
            )

    # Scoring: aggregate by rule with diminishing returns
    rule_counts: Dict[str, int] = {}
    rule_severity: Dict[str, str] = {}
    order = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1, "LOW": 0}

    for f in findings:
        rule_counts[f.rule_id] = rule_counts.get(f.rule_id, 0) + 1
        if f.rule_id not in rule_severity:
            rule_severity[f.rule_id] = f.severity
        else:
            if order.get(f.severity, 0) > order.get(rule_severity[f.rule_id], 0):
                rule_severity[f.rule_id] = f.severity

    penalty = 0.0
    for rid, cnt in rule_counts.items():
        sev = rule_severity.get(rid, "LOW")

        # IMPORTANT: MISSING_CAID is informational; barely affect score.
        if rid == "MISSING_CAID":
            penalty += 0.15 * math.log1p(cnt)
            continue

        penalty += _severity_weight(sev) * math.log1p(cnt)

    score = int(round(100 - (penalty * 6)))
    score = _clamp(score)

    # Buyer-friendly highlights
    highlights: List[str] = []
    if rule_counts.get("MALFORMED_LINE"):
        highlights.append(f"{rule_counts['MALFORMED_LINE']} malformed line(s) to fix.")
    if rule_counts.get("INVALID_RELATIONSHIP"):
        highlights.append("Some lines use invalid relationship values (should be DIRECT/RESELLER).")
    if rule_counts.get("RELATIONSHIP_AMBIGUITY"):
        highlights.append("Some seller accounts appear as both DIRECT and RESELLER (ask which path is preferred).")
    if rule_counts.get("RESELLER_HEAVY"):
        highlights.append("File is reseller-heavy (worth asking for more DIRECT paths where possible).")
    if not highlights:
        highlights.append("No obvious structural red flags detected from ads.txt formatting rules.")

    return {
        "meta": {
            "generated_at": _now_iso(),
            "source_label": source_label,
            "version": "0.4",
            "include_optional_checks": include_optional_checks,
        },
        "summary": {
            "risk_score": score,
            "risk_level": _risk_level(score),
            "finding_count": len(findings),
            "entry_count": entry_count,
            "direct_count": direct_count,
            "reseller_count": reseller_count,
            "rule_counts": rule_counts,
            "highlights": highlights,
        },
        "findings": [asdict(f) for f in findings],
    }


def report_to_json_bytes(report: Dict) -> bytes:
    return json.dumps(report, indent=2, ensure_ascii=False).encode("utf-8")


def report_to_txt_bytes(report: Dict) -> bytes:
    s = StringIO()
    sm = report.get("summary", {})
    meta = report.get("meta", {})
    s.write("AdChainAudit report\n")
    s.write(f"Source: {meta.get('source_label','ads.txt')}\n")
    s.write(f"Generated: {meta.get('generated_at','')}\n\n")
    s.write(f"Risk score: {sm.get('risk_score')} ({sm.get('risk_level')})\n")
    s.write(f"Entries: {sm.get('entry_count')} | Findings: {sm.get('finding_count')}\n")
    s.write(f"DIRECT: {sm.get('direct_count')} | RESELLER: {sm.get('reseller_count')}\n\n")

    highlights = sm.get("highlights") or []
    if highlights:
        s.write("Highlights:\n")
        for h in highlights:
            s.write(f"- {h}\n")
        s.write("\n")

    rc = sm.get("rule_counts", {})
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
        else:
            if ev.get("line"):
                s.write(f"   Evidence: {ev.get('line')}\n")
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
