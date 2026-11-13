"""10-Rule Deterministic Hardware Root-of-Trust (RoT) OTP Fuse Posture Auditor."""

from __future__ import annotations

import time
from dataclasses import dataclass
from enum import Enum
from typing import Any, Mapping


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: Severity
    weight: int
    cwe: str
    description: str
    remediation: str


@dataclass
class AuditReport:
    policy_name: str
    score: int
    status: str
    total_rules: int
    passed_rules: int
    failed_rules: int
    findings: list[Finding]
    audited_at: str


def audit_fuse_policy(policy: Mapping[str, Any]) -> AuditReport:
    """Audit an OTP hardware fuse policy against the 10 Logihertz RoT security rules."""
    policy_name = str(policy.get("name", "Unnamed Hardware Fuse Policy"))
    findings: list[Finding] = []
    deductions = 0

    # Rule 1: LH-FUSE-001 (CRITICAL, 25 pts, CWE-347)
    sec_enforced = bool(policy.get("secure_boot_enforced", False))
    lifecycle = str(policy.get("lifecycle_state", "")).upper()
    if not sec_enforced or lifecycle != "CLOSED_PRODUCTION":
        findings.append(Finding(
            rule_id="LH-FUSE-001",
            title="Hardware Secure Boot Enforcement Fuse Left Open",
            severity=Severity.CRITICAL,
            weight=25,
            cwe="CWE-347: Improper Verification of Cryptographic Signature",
            description="Hardware Secure Boot enforcement fuse (SEC_CONFIG_CLOSED / PKC_DISABLE / SecurityMode) is not blown or lifecycle state is not set to CLOSED_PRODUCTION. The BootROM will execute unsigned, unverified bootloaders.",
            remediation="Set 'secure_boot_enforced: true' and 'lifecycle_state: \"CLOSED_PRODUCTION\"' to commit the hardware root-of-trust enforcement fuse.",
        ))
        deductions += 25

    # Rule 2: LH-FUSE-002 (CRITICAL, 25 pts, CWE-326)
    srk_hash = str(policy.get("srk_hash_hex", "")).replace("0x", "").strip().lower()
    is_all_zero = not srk_hash or set(srk_hash) == {"0"}
    is_too_short = len(srk_hash) < 64
    key_algo = str(policy.get("key_algorithm", "")).upper()
    valid_algos = {"RSA-3072", "RSA-4096", "ECDSA-P384", "ED25519"}
    if is_all_zero or is_too_short or key_algo not in valid_algos:
        findings.append(Finding(
            rule_id="LH-FUSE-002",
            title="All-Zero, Test/Dummy, or Weak Public Key Hash",
            severity=Severity.CRITICAL,
            weight=25,
            cwe="CWE-326: Inadequate Encryption Strength",
            description="Public key hash is all zeros, shorter than 64 hex characters (256 bits), or uses an insecure/unapproved key algorithm. This allows signature bypass or brute-force key collision.",
            remediation="Provision a cryptographically strong 256-bit or 384-bit SRK hash using RSA-3072, RSA-4096, ECDSA-P384, or Ed25519.",
        ))
        deductions += 25

    # Rule 3: LH-FUSE-003 (CRITICAL, 25 pts, CWE-1191)
    jtag_mode = str(policy.get("jtag_debug_mode", "")).upper()
    allowed_jtag = {"DISABLED", "AUTHENTICATED_CHALLENGE_ONLY"}
    if jtag_mode not in allowed_jtag:
        findings.append(Finding(
            rule_id="LH-FUSE-003",
            title="Hardware JTAG / SWD Debug Interface Left Open in Production",
            severity=Severity.CRITICAL,
            weight=25,
            cwe="CWE-1191: On-Chip Debug and Test Interface With Insufficient Access Control",
            description="Hardware JTAG, Serial Wire Debug (SWD), or Secure JTAG Debug Controller (SJDC) is left permanently enabled in production. Physical attackers can halt BootROM execution and dump SRAM secrets.",
            remediation="Blow JTAG disable fuses or restrict debug access strictly to 'DISABLED' or 'AUTHENTICATED_CHALLENGE_ONLY'.",
        ))
        deductions += 25

    # Rule 4: LH-FUSE-004 (HIGH, 10 pts, CWE-276)
    if not bool(policy.get("lock_srk_fuse_bank", False)):
        findings.append(Finding(
            rule_id="LH-FUSE-004",
            title="OTP SRK/PKC Hash Bank Write-Lock Fuse Not Blown",
            severity=Severity.HIGH,
            weight=10,
            cwe="CWE-276: Incorrect Default Permissions",
            description="The OTP write-protect / lock fuse for the SRK/PKC hash bank has not been blown. Attackers with kernel/bare-metal code execution can burn unblown bits to overwrite the Root-of-Trust hash.",
            remediation="Enable 'lock_srk_fuse_bank: true' to blow the hardware write-protect fuse on the public key hash register bank.",
        ))
        deductions += 10

    # Rule 5: LH-FUSE-005 (HIGH, 10 pts, CWE-306)
    disable_serial = bool(policy.get("disable_unauthenticated_serial_boot", False))
    enforce_rcm = bool(policy.get("enforce_signed_rcm_payloads", False))
    if not disable_serial or not enforce_rcm:
        findings.append(Finding(
            rule_id="LH-FUSE-005",
            title="BootROM Serial Download Recovery Mode Unauthenticated",
            severity=Severity.HIGH,
            weight=10,
            cwe="CWE-306: Missing Authentication for Critical Function",
            description="USB/UART BootROM recovery download protocols (e.g. NXP SDP or NVIDIA RCM) permit arbitrary unsigned payload injection directly into internal IRAM.",
            remediation="Enable 'disable_unauthenticated_serial_boot: true' and 'enforce_signed_rcm_payloads: true' to cryptographically gate or disable recovery download protocols.",
        ))
        deductions += 10

    # Rule 6: LH-FUSE-006 (HIGH, 10 pts, CWE-693)
    svn_enabled = bool(policy.get("anti_rollback_svn_enabled", False))
    try:
        svn_val = int(policy.get("monotonic_svn_counter", 0))
    except (ValueError, TypeError):
        svn_val = 0
    if not svn_enabled or svn_val < 1:
        findings.append(Finding(
            rule_id="LH-FUSE-006",
            title="Hardware Anti-Rollback SVN Fuse Ratchet Disabled or Zeroed",
            severity=Severity.HIGH,
            weight=10,
            cwe="CWE-693: Protection Mechanism Failure",
            description="Monotonic anti-rollback Security Version Number (SVN) hardware fuse ratchet is disabled or set to 0, exposing the device to firmware downgrade attacks.",
            remediation="Enable 'anti_rollback_svn_enabled: true' and increment 'monotonic_svn_counter' to >= 1 to burn the anti-rollback thermometer bits.",
        ))
        deductions += 10

    # Rule 7: LH-FUSE-007 (HIGH, 10 pts, CWE-320)
    try:
        srk_slots = int(policy.get("srk_total_key_slots", 0))
    except (ValueError, TypeError):
        srk_slots = 0
    srk_rev_guard = bool(policy.get("srk_revocation_lock_guard", False))
    if srk_slots < 2 or not srk_rev_guard:
        findings.append(Finding(
            rule_id="LH-FUSE-007",
            title="Missing Backup Super Root Key Slots or Unlocked Revocation Guard",
            severity=Severity.HIGH,
            weight=10,
            cwe="CWE-320: Key Management Errors",
            description="Fewer than 2 Super Root Key slots are provisioned or SRK key revocation locks are unguarded, leaving no key rotation path if the primary signing key is compromised.",
            remediation="Configure 'srk_total_key_slots' >= 2 and enable 'srk_revocation_lock_guard: true' to protect key revocation fuses.",
        ))
        deductions += 10

    # Rule 8: LH-FUSE-008 (MEDIUM, 4 pts, CWE-693)
    bootdelay = policy.get("uboot_bootdelay")
    disable_fuse_cmd = bool(policy.get("disable_runtime_uboot_fuse_cmd", False))
    env_writable = bool(policy.get("uboot_env_writeable", False))
    if bootdelay != -2 or not disable_fuse_cmd or env_writable:
        findings.append(Finding(
            rule_id="LH-FUSE-008",
            title="U-Boot Interactive CLI or Runtime Fuse Command Enabled",
            severity=Severity.MEDIUM,
            weight=4,
            cwe="CWE-693: Protection Mechanism Failure",
            description="U-Boot interactive console delay is not disabled (bootdelay != -2), runtime 'fuse prog' command is left compiled into the production binary, or U-Boot environment is writable.",
            remediation="Set 'uboot_bootdelay: -2', 'disable_runtime_uboot_fuse_cmd: true', and 'uboot_env_writeable: false' in production bootloader configs.",
        ))
        deductions += 4

    # Rule 9: LH-FUSE-009 (MEDIUM, 4 pts, CWE-754)
    verify_readback = bool(policy.get("verify_readback_before_lock", False))
    vpp_check = bool(policy.get("vpp_voltage_rail_check", False))
    if not verify_readback or not vpp_check:
        findings.append(Finding(
            rule_id="LH-FUSE-009",
            title="Missing Pre-Burn Sense Check or Post-Burn Readback Verification",
            severity=Severity.MEDIUM,
            weight=4,
            cwe="CWE-754: Improper Check for Unusual or Exceptional Conditions",
            description="Automated provisioning does not verify fuse readback (fuse cmp) before committing the permanent lock fuse, or omits programming voltage (V_PP) rail validation.",
            remediation="Configure 'verify_readback_before_lock: true' and 'vpp_voltage_rail_check: true' in factory burning pipelines.",
        ))
        deductions += 4

    # Rule 10: LH-FUSE-010 (LOW, 1 pt, CWE-778)
    hsm_logged = bool(policy.get("hsm_ceremony_audit_logged", False))
    uid_bound = bool(policy.get("bind_fuse_receipt_to_soc_uid", False))
    if not hsm_logged or not uid_bound:
        findings.append(Finding(
            rule_id="LH-FUSE-010",
            title="Missing HSM Signing Ceremony Audit Log or Per-Device UID Binding",
            severity=Severity.LOW,
            weight=1,
            cwe="CWE-778: Insufficient Logging",
            description="Hardware Security Module (HSM) key generation ceremony is not cryptographically logged, or fuse burning receipts are not uniquely bound to the silicon UID (ECID/BR_CID).",
            remediation="Enable 'hsm_ceremony_audit_logged: true' and 'bind_fuse_receipt_to_soc_uid: true' for complete supply chain traceability.",
        ))
        deductions += 1

    failed_count = len(findings)
    passed_count = 10 - failed_count
    score = max(0, 100 - deductions)

    if score == 100:
        status = "HARDENED"
    elif score >= 85:
        status = "ADEQUATE"
    elif score >= 60:
        status = "ELEVATED_RISK"
    else:
        status = "CRITICAL_RISK"

    return AuditReport(
        policy_name=policy_name,
        score=score,
        status=status,
        total_rules=10,
        passed_rules=passed_count,
        failed_rules=failed_count,
        findings=findings,
        audited_at=time.strftime("%Y-%m-%d %H:%M:%SZ", time.gmtime()),
    )
