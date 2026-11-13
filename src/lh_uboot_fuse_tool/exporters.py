"""Multi-Format Exporters for Hardware Fuse Audit Reports and Key Tables."""

from __future__ import annotations

import json
from typing import Any

from lh_uboot_fuse_tool.auditor import AuditReport, Severity

# ANSI Color Codes
CLR_RESET = "\033[0m"
CLR_BOLD = "\033[1m"
CLR_RED = "\033[31m"
CLR_GREEN = "\033[32m"
CLR_YELLOW = "\033[33m"
CLR_BLUE = "\033[34m"
CLR_MAGENTA = "\033[35m"
CLR_CYAN = "\033[36m"


def render_audit_table(report: AuditReport) -> str:
    """Format an AuditReport into an ANSI colorized terminal table."""
    score_clr = CLR_RED
    if report.score == 100:
        score_clr = CLR_GREEN
    elif report.score >= 85:
        score_clr = CLR_YELLOW

    lines = [
        "",
        f"{CLR_BOLD}================================================================================{CLR_RESET}",
        f"{CLR_BOLD}{CLR_CYAN}   LOGIHERTZ SECURE BOOT HARDWARE FUSE POSTURE AUDIT REPORT{CLR_RESET}",
        f"{CLR_BOLD}================================================================================{CLR_RESET}",
        f" Policy Name  : {CLR_BOLD}{report.policy_name}{CLR_RESET}",
        f" Posture Score: {CLR_BOLD}{score_clr}{report.score} / 100 [{report.status}]{CLR_RESET}",
        f" Rules Checked: {report.total_rules} Total | {CLR_GREEN}{report.passed_rules} Passed{CLR_RESET} | {CLR_RED}{report.failed_rules} Failed{CLR_RESET}",
        f" Audited At   : {report.audited_at}",
        "--------------------------------------------------------------------------------",
    ]

    if not report.findings:
        lines.append(f"\n {CLR_GREEN}{CLR_BOLD}✓ ZERO POSTURE DEFECTS DETECTED. HARDWARE ROOT-OF-TRUST SECURED.{CLR_RESET}\n")
        return "\n".join(lines)

    lines.append(f"\n{CLR_BOLD}{CLR_RED}IDENTIFIED HARDWARE ROOT-OF-TRUST DEFECTS & FINDINGS:{CLR_RESET}\n")
    for i, f in enumerate(report.findings, start=1):
        sev_clr = CLR_RED
        if f.severity == Severity.HIGH:
            sev_clr = CLR_MAGENTA
        elif f.severity == Severity.MEDIUM:
            sev_clr = CLR_YELLOW
        elif f.severity == Severity.LOW:
            sev_clr = CLR_BLUE

        lines.append(f" {i}. {sev_clr}{CLR_BOLD}[{f.severity.value}]{CLR_RESET} {CLR_BOLD}{f.title}{CLR_RESET} (Deduction: -{f.weight} pts)")
        lines.append(f"    Rule ID    : {f.rule_id}")
        lines.append(f"    CWE        : {f.cwe}")
        lines.append(f"    Description: {f.description}")
        lines.append(f"    Remediation: {CLR_CYAN}{f.remediation}{CLR_RESET}\n")

    return "\n".join(lines)


def render_srk_table(
    composite_hex: str,
    words: list[int],
    hamming: int,
    per_word_hamming: list[int],
    endianness: str,
) -> str:
    """Format SRK table hash and packed fuse words into an ANSI summary table."""
    lines = [
        "",
        f"{CLR_BOLD}================================================================================{CLR_RESET}",
        f"{CLR_BOLD}{CLR_CYAN}   SUPER ROOT KEY (SRK/PKC) HARDWARE FUSE PACKING SUMMARY{CLR_RESET}",
        f"{CLR_BOLD}================================================================================{CLR_RESET}",
        f" Composite Hash : {CLR_BOLD}{composite_hex}{CLR_RESET}",
        f" Digest Size    : {len(composite_hex) * 4} bits ({len(composite_hex) // 2} bytes)",
        f" Word Packing   : {endianness.upper()}-ENDIAN (32-bit OTP words)",
        f" Total Popcount : {CLR_BOLD}{CLR_GREEN}{hamming} bits blown{CLR_RESET} ({hamming} / {len(words)*32})",
        "--------------------------------------------------------------------------------",
        f" {'Word':<6} | {'Hex Value':<12} | {'Dec Value':<12} | {'Popcount':<8} | {'Binary Representation'}",
        "--------+--------------+--------------+----------+----------------------------------",
    ]

    for i, (w, pop) in enumerate(zip(words, per_word_hamming)):
        w_32 = w & 0xFFFFFFFF
        bin_str = f"{w_32:032b}"
        lines.append(f" W{i:<5} | 0x{w_32:08X}   | {w_32:<12} | {pop:<8} | {bin_str}")

    lines.append("--------------------------------------------------------------------------------\n")
    return "\n".join(lines)


def to_json(data: Any) -> str:
    """Serialize any dataclass, dict, or object to deterministic indented JSON."""
    def default_serializer(o: Any) -> Any:
        if hasattr(o, "__dataclass_fields__"):
            return {k: getattr(o, k) for k in o.__dataclass_fields__}
        if hasattr(o, "value"):
            return o.value
        raise TypeError(f"Object of type {o.__class__.__name__} is not JSON serializable")

    return json.dumps(data, default=default_serializer, indent=2)


def to_sarif(report: AuditReport) -> str:
    """Convert an AuditReport into an OASIS SARIF v2.1.0 JSON document."""
    rules_dict: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []

    for f in report.findings:
        level = "error"
        if f.severity == Severity.MEDIUM:
            level = "warning"
        elif f.severity == Severity.LOW:
            level = "note"

        if f.rule_id not in rules_dict:
            rules_dict[f.rule_id] = {
                "id": f.rule_id,
                "name": f.title,
                "shortDescription": {"text": f.title},
                "fullDescription": {"text": f.description},
                "defaultConfiguration": {"level": level},
                "help": {"text": f.remediation},
                "properties": {
                    "cwe": f.cwe,
                    "weight": f.weight,
                },
            }

        results.append({
            "ruleId": f.rule_id,
            "level": level,
            "message": {"text": f"{f.title}: {f.description}"},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": report.policy_name,
                        }
                    }
                }
            ],
        })

    sarif_doc = {
        "version": "2.1.0",
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "lh-fuse",
                        "version": "0.1.0",
                        "informationUri": "https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-uboot-fuse-tool",
                        "rules": list(rules_dict.values()),
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(sarif_doc, indent=2)
