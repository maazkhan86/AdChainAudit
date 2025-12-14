# analyzer.py
from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from io import StringIO
from typing import Dict, List, Optional, Tuple
import csv
import json


ALLOWED_RELATIONSHIPS = {"DIRECT", "RESELLER"}


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


def _clean_line(line: str) -> str:
    return line.strip()


def _is_comment_or_blank(line: str) -> bool:
    s = line.strip()
    return (not s) or s.startswith("#")


def _split_fields(line: str) -> List[str]:
    # ads.txt uses comma-separated fields. We keep it simple and tolerant.
    return [p.strip() for p in line.split(",")]


def _risk_level(score: int) -> str:
    if score >= 80:
        return "LOW"
    if score >= 55:
        return "MEDIUM"
    return "HIGH"


def _severity_weight(sev: str) -> int:
    return {"CRITICAL": 15, "HIGH": 10, "MEDIUM": 6, "LOW": 3}.get(sev, 3)


def analyze_ads_txt(text: str, source_label: str = "ads.txt") -> Dict:
    lines = text.splitlines()

    entry_rows: List[Tuple[int, str, List[str]]] = []
    for idx, raw in enumerate(lines, start=1):
        line = _clean_line(raw)
        if _is_comment_or_blank(line):
            continue
        fields = _split_fields(line)
        entry_rows.append((idx, line, fields))

    findings: List[Finding] = []

    # Rule: malformed lines (wrong number of fields)
    for line_no, line, fields in entry_rows:
        if len(fields) not in (3, 4):
            findings.append(
                Finding(
                    rule_id="MALFORMED_LINE",
                    severity="HIGH",
                    title="Malformed ads.txt line (unexpected number of fields)",
                    why_buyer_cares="Malformed lines can break automated checks and create ambiguity around who is actually authorized to sell inventory.",
                    recommendation="Ask the publisher to fix formatting. Buyers should prefer clean, machine-parseable ads.txt.",
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
                        why_buyer_cares="If relationship is not clearly declared, it becomes harder to validate the path and enforce preferred routes.",
                        recommendation="Ask the publisher to correct relationship values to DIRECT or RESELLER only.",
                        evidence=Evidence(line_no=line_no, line=line),
                    )
                )

    # Rule: missing certification authority ID (CAID) (4th field)
    for line_no, line, fields in entry_rows:
        if len(fields) == 3:
            findings.append(
                Finding(
                    rule_id="MISSING_CAID",
                    severity="MEDIUM",
                    title="Missing Certification Authority ID (CAID) field",
                    why_buyer_cares="CAID can help buyers validate and match seller identities across systems. Missing IDs reduce verifiability.",
                    recommendation="Ask the publisher or seller to include the CAID where applicable (4th field).",
                    evidence=Evidence(line_no=line_no, line=line),
                )
            )

    # Rule: relationship ambiguity (same seller listed as both DIRECT and RESELLER)
    seen: Dict[Tuple[str, str], set] = {}
    for line_no, line, fields in entry_rows:
        if len(fields) >= 3:
            ad_system = fields[0].lower()
            seller_id = fields[1]
            rel = fields[2].upper()
            key = (ad_system, seller_id)
            seen.setdefault(key, set()).add(rel)

    ambiguous_keys = {k for k, rels in seen.items() if ("DIRECT" in rels and "RESELLER" in rels)}
    if ambiguous_keys:
        for line_no, line, fields in entry_rows:
            if len(fields) >= 3:
                key = (fields[0].lower(), fields[1])
                if key in ambiguous_keys:
                    findings.append(
                        Finding(
                            rule_id="RELATIONSHIP_AMBIGUITY",
                            severity="MEDIUM",
                            title="Relationship ambiguity (seller appears as DIRECT and RESELLER)",
                            why_buyer_cares="Ambiguity makes it harder to enforce preferred paths and can hide extra intermediaries or unclear selling relationships.",
                            recommendation="Ask the publisher which is the preferred route and whether a DIRECT relationship is available.",
                            evidence=Evidence(line_no=line_no, line=line),
                        )
                    )

    # Simple metrics
    entry_count = len(entry_rows)
    direct_count = sum(1 for _, _, f in entry_rows if len(f) >= 3 and f[2].upper() == "DIRECT")
    reseller_count = sum(1 for _, _, f in entry_rows if len(f) >= 3 and f[2].upper() == "RESELLER")

    # Risk score (start at 100, subtract weighted findings)
    score = 100
    for f in findings:
        score -= _severity_weight(f.severity)
    score = max(0, min(100, score))

    report = {
        "meta": {
            "generated_at": _now_iso(),
            "source_label": source_label,
            "version": "0.1",
        },
        "summary": {
            "risk_score": score,
            "risk_level": _risk_level(score),
            "finding_count": len(findings),
            "entry_count": entry_count,
            "direct_count": direct_count,
            "reseller_count": reseller_count,
        },
        "findings": [asdict(f) for f in findings],
    }
    return report


def report_to_json_bytes(report: Dict) -> bytes:
    return json.dumps(report, indent=2, ensure_ascii=False).encode("utf-8")


def report_to_txt_bytes(report: Dict) -> bytes:
    s = StringIO()
    sm = report.get("summary", {})
    meta = report.get("meta", {})
    s.write(f"AdChainAudit report\n")
    s.write(f"Source: {meta.get('source_label','ads.txt')}\n")
    s.write(f"Generated: {meta.get('generated_at','')}\n\n")
    s.write(f"Risk score: {sm.get('risk_score')} ({sm.get('risk_level')})\n")
    s.write(f"Entries: {sm.get('entry_count')} | Findings: {sm.get('finding_count')}\n")
    s.write(f"DIRECT: {sm.get('direct_count')} | RESELLER: {sm.get('reseller_count')}\n\n")

    findings = report.get("findings", [])
    if not findings:
        s.write("No findings.\n")
    else:
        for i, f in enumerate(findings, start=1):
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
