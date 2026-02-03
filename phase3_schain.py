# phase3_schain.py
from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _norm_domain(d: str) -> str:
    d = (d or "").strip().lower()
    d = re.sub(r"^https?://", "", d)
    d = d.strip("/").strip()
    return d


@dataclass
class SchainFinding:
    rule_id: str
    severity: str  # HIGH/MEDIUM/LOW
    title: str
    why_buyer_cares: str
    recommendation: str
    evidence: Dict[str, Any]


def _safe_int(x: Any) -> Optional[int]:
    try:
        return int(x)
    except Exception:
        return None


def extract_schain_obj(any_json: Any) -> Optional[Dict[str, Any]]:
    """
    Accepts any of:
      - a direct schain object: {"ver":"1.0","complete":0/1,"nodes":[...]}
      - an OpenRTB bidrequest-ish wrapper with: source.ext.schain or source.ext.schain in ext
      - a wrapper where schain may be a string-serialized JSON
    """
    if isinstance(any_json, dict):
        # direct schain
        if "nodes" in any_json and "complete" in any_json:
            return any_json

        # OpenRTB-ish: source.ext.schain
        src = any_json.get("source")
        if isinstance(src, dict):
            ext = src.get("ext", {})
            if isinstance(ext, dict) and "schain" in ext:
                sch = ext.get("schain")
                if isinstance(sch, str):
                    try:
                        sch = json.loads(sch)
                    except Exception:
                        sch = None
                if isinstance(sch, dict):
                    return sch

        # sometimes ext.schain at top-level
        ext2 = any_json.get("ext")
        if isinstance(ext2, dict) and "schain" in ext2:
            sch = ext2.get("schain")
            if isinstance(sch, str):
                try:
                    sch = json.loads(sch)
                except Exception:
                    sch = None
            if isinstance(sch, dict):
                return sch

    return None


def parse_schain_text(s: str) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """
    Returns (schain_obj, error)
    """
    if not (s or "").strip():
        return None, "Empty input"

    try:
        obj = json.loads(s)
    except Exception as e:
        return None, f"Invalid JSON: {e}"

    sch = extract_schain_obj(obj)
    if not sch:
        return None, "Could not find schain object. Expected schain JSON or an OpenRTB wrapper containing source.ext.schain."
    return sch, None


def analyze_schain(
    schain_obj: Dict[str, Any],
    *,
    source_label: str = "schain",
    ads_txt_text: Optional[str] = None,
) -> Dict[str, Any]:
    findings: List[SchainFinding] = []

    ver = str(schain_obj.get("ver", "")).strip()
    complete = _safe_int(schain_obj.get("complete"))
    nodes = schain_obj.get("nodes", [])

    if complete not in (0, 1):
        findings.append(
            SchainFinding(
                rule_id="SCHAIN_MISSING_COMPLETE",
                severity="HIGH",
                title="schain is missing a valid 'complete' flag",
                why_buyer_cares="Without 'complete', it’s harder to interpret whether the seller claims the chain is fully declared.",
                recommendation="Ask the seller/SSP to provide a valid schain object (complete must be 0 or 1).",
                evidence={"complete": schain_obj.get("complete")},
            )
        )

    if not isinstance(nodes, list) or len(nodes) == 0:
        findings.append(
            SchainFinding(
                rule_id="SCHAIN_NO_NODES",
                severity="HIGH",
                title="schain has no nodes",
                why_buyer_cares="No nodes means no supply path disclosure at the schain layer.",
                recommendation="Ask for schain in bid requests/logs (or from your DSP’s transparency export).",
                evidence={"nodes_type": str(type(nodes))},
            )
        )
        nodes = []

    # Optional cross-check: which ad systems appear in ads.txt
    ads_domains: Optional[set] = None
    if ads_txt_text:
        ads_domains = set()
        for raw in ads_txt_text.splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if "#" in line:
                line = line.split("#", 1)[0].strip()
            parts = [p.strip() for p in line.split(",")]
            if parts:
                ads_domains.add(_norm_domain(parts[0]))

    # Validate node fields + compute summary
    hop_count = 0
    reseller_hops = 0
    direct_hops = 0
    unknown_nodes = 0
    duplicates = 0
    seen = set()

    normalized_nodes: List[Dict[str, Any]] = []

    for i, n in enumerate(nodes, start=1):
        if not isinstance(n, dict):
            unknown_nodes += 1
            continue

        asi = _norm_domain(str(n.get("asi", "")).strip())
        sid = str(n.get("sid", "")).strip()
        hp = _safe_int(n.get("hp"))

        hop_count += 1
        if hp == 1:
            direct_hops += 1
        elif hp == 0:
            reseller_hops += 1

        if not asi or not sid or hp not in (0, 1):
            unknown_nodes += 1
            findings.append(
                SchainFinding(
                    rule_id="SCHAIN_NODE_MISSING_FIELDS",
                    severity="HIGH",
                    title="One or more schain nodes are missing required fields (asi/sid/hp)",
                    why_buyer_cares="Missing required fields reduces supply-path transparency and makes hops hard to validate.",
                    recommendation="Ask the seller/SSP to provide a compliant schain node with asi, sid, and hp.",
                    evidence={"node_index": i, "asi": asi, "sid": sid, "hp": n.get("hp")},
                )
            )

        key = (asi, sid, hp)
        if key in seen:
            duplicates += 1
        else:
            seen.add(key)

        if ads_domains is not None and asi and asi not in ads_domains:
            findings.append(
                SchainFinding(
                    rule_id="SCHAIN_ASI_NOT_IN_ADS_TXT",
                    severity="LOW",
                    title="schain includes an ad system (asi) not present in ads.txt",
                    why_buyer_cares="If an ad system appears in schain but not in ads.txt, it may indicate a path that isn’t clearly authorized at the publisher’s ads.txt layer.",
                    recommendation="Verify whether this hop is expected and whether the publisher has authorized it (ads.txt / sellers.json / contract route).",
                    evidence={"node_index": i, "asi": asi},
                )
            )

        normalized_nodes.append(
            {
                "index": i,
                "asi": asi,
                "sid": sid,
                "hp": hp,
                "rid": n.get("rid"),
                "name": n.get("name"),
                "domain": n.get("domain"),
            }
        )

    if duplicates > 0:
        findings.append(
            SchainFinding(
                rule_id="SCHAIN_DUPLICATE_NODES",
                severity="MEDIUM",
                title="Duplicate nodes detected in schain",
                why_buyer_cares="Duplicates can indicate messy path declaration or repeated hops.",
                recommendation="Ask for clarification on the intended hop sequence and whether the chain is normalized correctly.",
                evidence={"duplicate_count": duplicates},
            )
        )

    if complete == 0:
        findings.append(
            SchainFinding(
                rule_id="SCHAIN_INCOMPLETE",
                severity="MEDIUM",
                title="SupplyChain marked as incomplete (complete=0)",
                why_buyer_cares="An incomplete schain means the seller is not asserting the full chain is declared.",
                recommendation="Treat as a transparency gap. Ask for a complete schain (complete=1) for this route where possible.",
                evidence={"complete": complete, "ver": ver},
            )
        )

    if hop_count >= 4:
        findings.append(
            SchainFinding(
                rule_id="SCHAIN_MANY_HOPS",
                severity="MEDIUM",
                title="Many hops in schain",
                why_buyer_cares="More hops often means more intermediaries and potentially more fees/opacity.",
                recommendation="Ask for the preferred/cleanest path and whether fewer hops are available (SPO).",
                evidence={"hop_count": hop_count},
            )
        )

    if reseller_hops > 0:
        findings.append(
            SchainFinding(
                rule_id="SCHAIN_RESELLER_HOPS_PRESENT",
                severity="LOW",
                title="Reseller hops present (hp=0)",
                why_buyer_cares="Reseller hops can be legitimate, but they reduce directness and can add fees.",
                recommendation="Confirm why reselling is needed and whether DIRECT paths exist for key publishers.",
                evidence={"reseller_hops": reseller_hops},
            )
        )

    # Graphviz DOT for simple visualization in Streamlit
    dot = build_graphviz_dot(normalized_nodes, complete=complete)

    return {
        "meta": {"generated_at": _now_iso(), "source_label": source_label, "version": "0.1-phase3-quickview"},
        "summary": {
            "ver": ver,
            "complete": complete,
            "hops": hop_count,
            "direct_hops": direct_hops,
            "reseller_hops": reseller_hops,
            "unknown_nodes": unknown_nodes,
            "duplicate_nodes": duplicates,
            "finding_count": len(findings),
        },
        "nodes": normalized_nodes,
        "graphviz_dot": dot,
        "findings": [asdict(f) for f in findings],
    }


def build_graphviz_dot(nodes: List[Dict[str, Any]], *, complete: Optional[int]) -> str:
    """
    Returns a DOT graph for st.graphviz_chart.
    """
    rankdir = "LR"
    lines = [f'digraph schain {{ rankdir={rankdir}; labelloc="t";']

    label = "SupplyChain (schain)"
    if complete in (0, 1):
        label += f" — complete={complete}"
    lines.append(f'label="{label}";')

    # nodes
    for n in nodes:
        i = n.get("index")
        asi = n.get("asi") or "—"
        sid = n.get("sid") or "—"
        hp = n.get("hp")
        hp_s = "DIRECT" if hp == 1 else ("RESELLER" if hp == 0 else "—")
        node_id = f"n{i}"
        node_label = f"{i}. {asi}\\nSID: {sid}\\n{hp_s}"
        lines.append(f'{node_id} [shape=box, style="rounded", label="{node_label}"];')

    # edges
    for i in range(1, len(nodes)):
        lines.append(f"n{i} -> n{i+1};")

    lines.append("}")
    return "\n".join(lines)
