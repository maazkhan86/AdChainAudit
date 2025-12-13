from __future__ import annotations

import json
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, asdict
from typing import Any, Dict, List, Optional, Tuple


# Simple FQDN-ish check (not perfect, but useful)
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9-]+\.)+[a-z]{2,63}$", re.IGNORECASE)

VALID_RELATIONSHIPS = {"DIRECT", "RESELLER"}


@dataclass
class AdsTxtRecord:
    line_no: int
    raw: str
    domain: str = ""
    account_id: str = ""
    relationship: str = ""
    caid: str = ""  # Certification Authority ID (optional)
    field_count: int = 0
    record_type: str = "entry"  # "entry" or "meta"
    meta_key: str = ""
    meta_value: str = ""


def _strip_inline_comment(line: str) -> str:
    # Remove inline comment fragments after '#'
    if "#" in line:
        line = line.split("#", 1)[0]
    return line.strip()


def parse_ads_txt(text: str) -> List[AdsTxtRecord]:
    """
    Parses ads.txt content into records.

    Supports:
    - Standard ads.txt entries: <ad_system_domain>, <publisher_id>, <DIRECT|RESELLER>, [cert_authority_id]
    - Simple meta/variable lines like: OWNERDOMAIN=example.com (kept as record_type="meta")
    """
    records: List[AdsTxtRecord] = []

    for i, raw in enumerate(text.splitlines(), start=1):
        stripped = _strip_inline_comment(raw)
        if not stripped:
            continue

        # Handle meta lines (e.g., OWNERDOMAIN=..., contact=..., etc.)
        if "=" in stripped and "," not in stripped:
            key, val = stripped.split("=", 1)
            rec = AdsTxtRecord(
                line_no=i,
                raw=raw,
                record_type="meta",
                meta_key=key.strip(),
                meta_value=val.strip(),
            )
            records.append(rec)
            continue

        # Standard entry lines
        parts = [p.strip() for p in stripped.split(",")]

        # Remove empty trailing fields if someone ended with comma(s)
        while parts and parts[-1] == "":
            parts.pop()

        domain = parts[0] if len(parts) > 0 else ""
        account_id = parts[1] if len(parts) > 1 else ""
        relationship = parts[2].upper() if len(parts) > 2 else ""
        caid = parts[3] if len(parts) > 3 else ""

        rec = AdsTxtRecord(
            line_no=i,
            raw=raw,
            domain=domain,
            account_id=account_id,
            relationship=relationship,
            caid=caid,
            field_count=len(parts),
            record_type="entry",
        )
        records.append(rec)

    return records


def _issue(severity: str, title: str, detail: str, examples: List[AdsTxtRecord]) -> Dict[str, Any]:
    return {
        "severity": severity,
        "title": title,
        "detail": detail,
        "examples": [asdict(e) for e in examples],
    }


def analyze(records: List[AdsTxtRecord]) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    """
    Returns:
      summary: dict
      issues: list[dict] (each includes severity/title/detail/examples)
    """
    issues: List[Dict[str, Any]] = []

    entry_records = [r for r in records if r.record_type == "entry"]
    meta_records = [r for r in records if r.record_type == "meta"]

    total_entries = len(entry_records)
    total_meta = len(meta_records)

    # --- Critical structure checks ---
    malformed = [r for r in entry_records if r.field_count not in (3, 4)]
    if malformed:
        issues.append(_issue(
            "CRITICAL",
            "Malformed lines (wrong number of fields)",
            "Each ads.txt entry should have 3 or 4 comma-separated fields (domain, account, relationship, optional CAID).",
            malformed[:12],
        ))

    invalid_relationship = [r for r in entry_records if r.relationship not in VALID_RELATIONSHIPS]
    if invalid_relationship:
        issues.append(_issue(
            "CRITICAL",
            "Invalid relationship value",
            "Relationship (field #3) should be DIRECT or RESELLER.",
            invalid_relationship[:12],
        ))

    missing_domain = [r for r in entry_records if not (r.domain or "").strip()]
    if missing_domain:
        issues.append(_issue(
            "CRITICAL",
            "Missing ad system domain",
            "The ad system domain (field #1) is required for a valid entry.",
            missing_domain[:12],
        ))

    missing_account = [r for r in entry_records if not (r.account_id or "").strip()]
    if missing_account:
        issues.append(_issue(
            "CRITICAL",
            "Missing publisher account ID",
            "The publisher account ID (field #2) is required for a valid entry.",
            missing_account[:12],
        ))

    # --- Buyer-relevant risk signals ---
    suspicious_domains = [r for r in entry_records if r.domain and not DOMAIN_RE.match(r.domain)]
    if suspicious_domains:
        issues.append(_issue(
            "HIGH",
            "Suspicious ad system domains",
            "Some domains don't look like standard fully-qualified domains. This can indicate typos or configuration mistakes.",
            suspicious_domains[:12],
        ))

    missing_caid = [r for r in entry_records if r.field_count == 3]
    if missing_caid and total_entries > 0:
        issues.append(_issue(
            "MEDIUM",
            "Missing Certification Authority ID on some entries",
            "CAID (field #4) is optional, but its absence can reduce certain verification/traceability coverage depending on partners.",
            missing_caid[:12],
        ))

    # Relationship ambiguity: same (domain, account_id) appears as both DIRECT and RESELLER
    rels: Dict[Tuple[str, str], set] = defaultdict(set)
    rel_examples: Dict[Tuple[str, str], List[AdsTxtRecord]] = defaultdict(list)

    for r in entry_records:
        key = (r.domain.lower(), r.account_id.strip())
        if not key[0] or not key[1]:
            continue
        if r.relationship:
            rels[key].add(r.relationship)
        if len(rel_examples[key]) < 6:
            rel_examples[key].append(r)

    ambiguous_keys = [k for k, v in rels.items() if ("DIRECT" in v and "RESELLER" in v)]
    if ambiguous_keys:
        ex: List[AdsTxtRecord] = []
        for k in ambiguous_keys[:6]:
            ex.extend(rel_examples[k][:4])
        issues.append(_issue(
            "HIGH",
            "Relationship ambiguity (DIRECT and RESELLER for same seller)",
            "The same seller (domain + account) is declared with both DIRECT and RESELLER. This can create uncertainty for buyers.",
            ex[:12],
        ))

    # --- Summary stats ---
    rel_counter = Counter(r.relationship for r in entry_records if r.relationship)
    field_counter = Counter(r.field_count for r in entry_records)

    summary: Dict[str, Any] = {
        "totals": {
            "entries": total_entries,
            "meta_lines": total_meta,
            "all_records": len(records),
        },
        "relationships": dict(rel_counter),
        "field_counts": dict(field_counter),
        "missing_caid_entries": len(missing_caid),
        "relationship_ambiguity_pairs": len(ambiguous_keys),
        "meta_keys": dict(Counter(m.meta_key for m in meta_records if m.meta_key)),
    }

    # Simple risk score (0–100): prioritize CRITICAL/HIGH
    score = 0
    if malformed or invalid_relationship or missing_domain or missing_account:
        score += 60
    if ambiguous_keys:
        score += 25
    if suspicious_domains:
        score += 10
    if total_entries > 0:
        # Up to 15 points based on % missing CAID
        score += min(15, int((len(missing_caid) / total_entries) * 15))
    summary["risk_score_0_100"] = min(100, score)

    return summary, issues


def to_report_json(summary: Dict[str, Any], issues: List[Dict[str, Any]]) -> str:
    return json.dumps({"summary": summary, "issues": issues}, indent=2)
