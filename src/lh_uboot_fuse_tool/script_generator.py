"""U-Boot & NVIDIA Tegra234 Orin Hardware Fuse Script Synthesizer.

Generates atomic U-Boot `fuse prog` / `fuse cmp` provisioning scripts with
pre-flight dry-run checks and NVIDIA Tegra234 Orin `generic_odmfuse` XML manifests.
"""

from __future__ import annotations

import hashlib
import time
from typing import Sequence


def generate_uboot_fuse_script(
    bank: int,
    start_word: int,
    words: Sequence[int],
    lock_bank: int | None = None,
    lock_word: int | None = None,
    lock_val: int | None = None,
    verify_readback: bool = True,
    vpp_check: bool = True,
    title: str = "Logihertz Secure Boot SRK Provisioning Script",
) -> str:
    """Generate a hardened, deterministic U-Boot fuse programming script.

    Enforces pre-flight dry-run sensing, atomic program-and-compare pairs with
    instant failure abort (`exit 1`), and optional hardware bank write-locking.
    """
    lines: list[str] = [
        "#!/bin/sh",
        f"# {title}",
        f"# Generated: {time.strftime('%Y-%m-%d %H:%M:%SZ', time.gmtime())}",
        "#",
        "# CRITICAL WARNING: Silicon eFuse burning is physically permanent and IRREVERSIBLE.",
        "# Ensure programming voltage rail (V_PP) is stabilized prior to execution.",
        "#",
        "echo '=== [LOGIHERTZ] Initiating Hardware OTP Fuse Burning Ceremony ==='",
    ]

    if vpp_check:
        lines.extend([
            "echo '-> Verifying programming voltage rail (V_PP)...'",
            "test -n \"${vpp_rail_ok}\" || { echo '[ERROR] V_PP rail unverified. Aborting.'; exit 1; }",
        ])

    lines.append("")
    lines.append(f"# Pre-flight Dry-Run: Sense target bank {bank} words")
    for i in range(len(words)):
        w_idx = start_word + i
        lines.append(f"fuse sense {bank} {w_idx} || {{ echo '[ERROR] Dry-run sense failed at word {w_idx}'; exit 1; }}")

    lines.append("")
    lines.append(f"# Primary Fuse Programming Loop: Bank {bank}, Start Word {start_word}")
    for i, val in enumerate(words):
        w_idx = start_word + i
        val_32 = val & 0xFFFFFFFF
        val_hex = f"0x{val_32:08X}"
        lines.append(f"# Word {w_idx} (Index {i})")
        lines.append(f"echo '-> Burning Bank {bank} Word {w_idx} = {val_hex}'")
        lines.append(f"fuse prog -y {bank} {w_idx} {val_hex} || {{ echo '[FATAL] Programming failed at Word {w_idx}'; exit 1; }}")
        if verify_readback:
            lines.append(f"fuse cmp {bank} {w_idx} {val_hex} || {{ echo '[FATAL] Readback mismatch at Word {w_idx}'; exit 1; }}")

    if lock_bank is not None and lock_word is not None and lock_val is not None:
        l_hex = f"0x{(lock_val & 0xFFFFFFFF):08X}"
        lines.append("")
        lines.append(f"# Final Security Lock: Bank {lock_bank} Word {lock_word} = {l_hex}")
        lines.append(f"echo '-> Sealing Hardware Fuse Bank Lock ({lock_bank}:{lock_word})'")
        lines.append(f"fuse prog -y {lock_bank} {lock_word} {l_hex} || {{ echo '[FATAL] Lock programming failed'; exit 1; }}")
        if verify_readback:
            lines.append(f"fuse cmp {lock_bank} {lock_word} {l_hex} || {{ echo '[FATAL] Lock readback mismatch'; exit 1; }}")

    lines.extend([
        "",
        "echo '=== [LOGIHERTZ] Hardware OTP Fuse Burning Succeeded Deterministically ==='",
        "exit 0",
    ])

    script_body = "\n".join(lines) + "\n"
    script_hash = hashlib.sha256(script_body.encode("utf-8")).hexdigest()
    return script_body + f"# Script Integrity SHA-256: {script_hash}\n"


def generate_tegra234_odmfuse_xml(
    public_key_hash_hex: str,
    boot_security_info: int = 0x00000001,
    security_mode: int = 0x00000001,
    reserved_odm0: int = 0x00000000,
    reserved_odm1: int = 0x00000000,
) -> str:
    """Generate an NVIDIA Jetson Orin (Tegra234) generic_odmfuse XML manifest."""
    clean_hash = public_key_hash_hex.strip().replace("0x", "").lower()
    hash_len_bytes = len(clean_hash) // 2
    if hash_len_bytes not in (32, 48):
        raise ValueError(f"Tegra234 Public Key Hash must be 32 bytes (SHA-256) or 48 bytes (SHA-384), got {hash_len_bytes}")

    bsi_hex = f"0x{(boot_security_info & 0xFFFFFFFF):08x}"
    sec_hex = f"0x{(security_mode & 0xFFFFFFFF):08x}"
    odm0_hex = f"0x{(reserved_odm0 & 0xFFFFFFFF):08x}"
    odm1_hex = f"0x{(reserved_odm1 & 0xFFFFFFFF):08x}"

    xml_lines = [
        '<genericfuse MagicId="0x45535546" version="1.0.0">',
        f'    <fuse name="PublicKeyHash" size="{hash_len_bytes}" value="0x{clean_hash}"/>',
        f'    <fuse name="BootSecurityInfo" size="4" value="{bsi_hex}"/>',
        f'    <fuse name="SecurityMode" size="4" value="{sec_hex}"/>',
        f'    <fuse name="ReservedOdm0" size="4" value="{odm0_hex}"/>',
        f'    <fuse name="ReservedOdm1" size="4" value="{odm1_hex}"/>',
        '</genericfuse>',
        "",
    ]
    return "\n".join(xml_lines)
