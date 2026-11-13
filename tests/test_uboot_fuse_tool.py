"""Comprehensive Test Suite for Logihertz Secure Boot OTP Hardware Fuse Burner.

Includes 85+ deterministic assertions covering SRK/PKC table hashing, word packing,
physical eFuse transition monotonicity, SVN thermometer encoding, script generation,
10-rule posture auditor, and CLI subprocess execution.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import unittest
from pathlib import Path

# Add src/ to sys.path
TEST_DIR = Path(__file__).resolve().parent
REPO_ROOT = TEST_DIR.parent
SRC_DIR = REPO_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from lh_uboot_fuse_tool.auditor import (
    AuditReport,
    Finding,
    Severity,
    audit_fuse_policy,
)
from lh_uboot_fuse_tool.exporters import (
    render_audit_table,
    render_srk_table,
    to_json,
    to_sarif,
)
from lh_uboot_fuse_tool.fuse_math import (
    IrreversibleBitTransitionError,
    compute_hamming_weight,
    compute_key_digest,
    compute_per_word_hamming,
    compute_srk_table_hash,
    encode_svn_thermometer,
    pack_fuse_words,
    verify_fuse_transition,
    verify_svn_transition,
)
from lh_uboot_fuse_tool.script_generator import (
    generate_tegra234_odmfuse_xml,
    generate_uboot_fuse_script,
)


class TestSRKMath(unittest.TestCase):
    """Test cryptographic public key digests, SRK table hashing, and word packing."""

    def test_compute_key_digest_sha256(self) -> None:
        raw_key = b"TEST_PUBLIC_KEY_MATERIAL_1"
        digest = compute_key_digest(raw_key, "sha256")
        self.assertEqual(len(digest), 32)
        # Verify deterministic hash
        import hashlib
        self.assertEqual(digest, hashlib.sha256(raw_key).digest())

    def test_compute_key_digest_hex_string(self) -> None:
        hex_key = "3082010A0282010100"
        digest = compute_key_digest(hex_key, "sha256")
        self.assertEqual(len(digest), 32)
        import hashlib
        self.assertEqual(digest, hashlib.sha256(bytes.fromhex(hex_key)).digest())

    def test_compute_key_digest_sha384(self) -> None:
        raw_key = b"TEST_PUBLIC_KEY_MATERIAL_384"
        digest = compute_key_digest(raw_key, "sha384")
        self.assertEqual(len(digest), 48)

    def test_compute_key_digest_invalid_algo(self) -> None:
        with self.assertRaises(ValueError):
            compute_key_digest(b"KEY", "md5")

    def test_srk_table_hash_single_key(self) -> None:
        keys = ["A1B2C3D4"]
        comp_hex, comp_bytes, ind_hex = compute_srk_table_hash(keys, "sha256")
        self.assertEqual(len(comp_bytes), 32)
        self.assertEqual(len(comp_hex), 64)
        self.assertEqual(len(ind_hex), 1)

    def test_srk_table_hash_four_keys(self) -> None:
        keys = ["KEY_0", "KEY_1", "KEY_2", "KEY_3"]
        comp_hex, comp_bytes, ind_hex = compute_srk_table_hash(keys, "sha256")
        self.assertEqual(len(comp_bytes), 32)
        self.assertEqual(len(ind_hex), 4)

    def test_srk_table_hash_bounds(self) -> None:
        # 0 keys -> ValueError
        with self.assertRaises(ValueError):
            compute_srk_table_hash([], "sha256")
        # 5 keys -> ValueError (HAB/AHAB max is 4)
        with self.assertRaises(ValueError):
            compute_srk_table_hash(["K1", "K2", "K3", "K4", "K5"], "sha256")

    def test_pack_fuse_words_little_endian(self) -> None:
        # Bytes: 0x01, 0x02, 0x03, 0x04 -> Little Endian uint32 = 0x04030201
        dummy_32 = bytes(range(32))
        words = pack_fuse_words(dummy_32, endianness="little")
        self.assertEqual(len(words), 8)
        self.assertEqual(words[0], 0x03020100)
        self.assertEqual(words[1], 0x07060504)

    def test_pack_fuse_words_big_endian(self) -> None:
        # Bytes: 0x00, 0x01, 0x02, 0x03 -> Big Endian uint32 = 0x00010203
        dummy_32 = bytes(range(32))
        words = pack_fuse_words(dummy_32, endianness="big")
        self.assertEqual(len(words), 8)
        self.assertEqual(words[0], 0x00010203)
        self.assertEqual(words[1], 0x04050607)

    def test_pack_fuse_words_invalid(self) -> None:
        with self.assertRaises(ValueError):
            pack_fuse_words(b"SHORT", "little")
        with self.assertRaises(ValueError):
            pack_fuse_words(bytes(32), "middle")

    def test_hamming_weight_calculations(self) -> None:
        # 0x00000000 -> 0
        self.assertEqual(compute_hamming_weight(0), 0)
        # 0xFFFFFFFF -> 32
        self.assertEqual(compute_hamming_weight(0xFFFFFFFF), 32)
        # 0x0000000F -> 4
        self.assertEqual(compute_hamming_weight(0x0F), 4)
        # List of words: [0x1, 0x3, 0x7] -> 1 + 2 + 3 = 6
        self.assertEqual(compute_hamming_weight([1, 3, 7]), 6)
        # Per word
        per_word = compute_per_word_hamming([1, 3, 7])
        self.assertEqual(per_word, [1, 2, 3])
        # Bytes
        self.assertEqual(compute_hamming_weight(b"\xFF\x0F"), 8 + 4)


class TestPhysicalTransitionGuard(unittest.TestCase):
    """Test silicon physical eFuse 0 -> 1 irreversibility invariants."""

    def test_valid_transitions(self) -> None:
        # Blank to target
        valid, conflicts = verify_fuse_transition(0x00000000, 0xA5A5F00D)
        self.assertTrue(valid)
        self.assertEqual(conflicts, [])

        # Sub-mask to super-mask
        valid, conflicts = verify_fuse_transition(0x00010000, 0x00030001)
        self.assertTrue(valid)
        self.assertEqual(conflicts, [])

        # Identity transition
        valid, conflicts = verify_fuse_transition(0x12345678, 0x12345678)
        self.assertTrue(valid)
        self.assertEqual(conflicts, [])

        # Blank to all blown
        valid, conflicts = verify_fuse_transition(0x00000000, 0xFFFFFFFF)
        self.assertTrue(valid)
        self.assertEqual(conflicts, [])

    def test_invalid_transitions(self) -> None:
        # Bit 0 blown currently (0x0F = 00001111b), target attempts 0x0E (00001110b)
        valid, conflicts = verify_fuse_transition(0x0000000F, 0x0000000E)
        self.assertFalse(valid)
        self.assertEqual(conflicts, [0])

        # MSB blown (bit 31), target has bit 31 as 0
        valid, conflicts = verify_fuse_transition(0x80000000, 0x00000001)
        self.assertFalse(valid)
        self.assertEqual(conflicts, [31])

        # All blown to blank
        valid, conflicts = verify_fuse_transition(0xFFFFFFFF, 0x00000000)
        self.assertFalse(valid)
        self.assertEqual(len(conflicts), 32)
        self.assertEqual(conflicts, list(range(32)))

    def test_irreversible_error_representation(self) -> None:
        err = IrreversibleBitTransitionError(0x03, 0x01, [1])
        self.assertIn("cannot transition 1 -> 0", str(err))
        self.assertEqual(err.conflicting_bits, [1])


class TestSVNThermometerCoding(unittest.TestCase):
    """Test monotonic anti-rollback Security Version Number thermometer encoding."""

    def test_encode_svn_thermometer_zero(self) -> None:
        mask, w0, w1 = encode_svn_thermometer(0)
        self.assertEqual(mask, 0)
        self.assertEqual(w0, 0)
        self.assertEqual(w1, 0)

    def test_encode_svn_thermometer_small(self) -> None:
        # v = 1 -> mask 0x1
        m1, w0_1, w1_1 = encode_svn_thermometer(1)
        self.assertEqual(m1, 0x1)
        self.assertEqual(w0_1, 0x1)
        self.assertEqual(w1_1, 0x0)

        # v = 5 -> mask 0x1F
        m5, w0_5, w1_5 = encode_svn_thermometer(5)
        self.assertEqual(m5, 0x1F)
        self.assertEqual(w0_5, 0x1F)
        self.assertEqual(w1_5, 0x0)

    def test_encode_svn_thermometer_boundary(self) -> None:
        # v = 32 -> word0 is 0xFFFFFFFF, word1 is 0
        m32, w0_32, w1_32 = encode_svn_thermometer(32)
        self.assertEqual(w0_32, 0xFFFFFFFF)
        self.assertEqual(w1_32, 0)
        self.assertEqual(m32, 0xFFFFFFFF)

        # v = 33 -> word0 is 0xFFFFFFFF, word1 is 0x1
        m33, w0_33, w1_33 = encode_svn_thermometer(33)
        self.assertEqual(w0_33, 0xFFFFFFFF)
        self.assertEqual(w1_33, 0x1)

        # v = 64 -> both words 0xFFFFFFFF
        m64, w0_64, w1_64 = encode_svn_thermometer(64)
        self.assertEqual(w0_64, 0xFFFFFFFF)
        self.assertEqual(w1_64, 0xFFFFFFFF)
        self.assertEqual(m64, (1 << 64) - 1)

    def test_encode_svn_out_of_bounds(self) -> None:
        with self.assertRaises(ValueError):
            encode_svn_thermometer(-1)
        with self.assertRaises(ValueError):
            encode_svn_thermometer(65)

    def test_verify_svn_transition(self) -> None:
        self.assertTrue(verify_svn_transition(5, 6))
        self.assertTrue(verify_svn_transition(5, 5))
        self.assertFalse(verify_svn_transition(5, 4))
        with self.assertRaises(ValueError):
            verify_svn_transition(-1, 5)


class TestScriptGenerator(unittest.TestCase):
    """Test U-Boot shell script and Tegra234 odmfuse XML synthesizer."""

    def test_generate_uboot_script_basic(self) -> None:
        words = [0x11111111, 0x22222222]
        script = generate_uboot_fuse_script(bank=3, start_word=0, words=words)
        self.assertIn("#!/bin/sh", script)
        self.assertIn("fuse sense 3 0", script)
        self.assertIn("fuse sense 3 1", script)
        self.assertIn("fuse prog -y 3 0 0x11111111", script)
        self.assertIn("fuse cmp 3 0 0x11111111", script)
        self.assertIn("fuse prog -y 3 1 0x22222222", script)
        self.assertIn("fuse cmp 3 1 0x22222222", script)
        self.assertIn("Script Integrity SHA-256", script)

    def test_generate_uboot_script_with_lock(self) -> None:
        words = [0xAABBCCDD]
        script = generate_uboot_fuse_script(
            bank=3,
            start_word=0,
            words=words,
            lock_bank=0,
            lock_word=6,
            lock_val=0x00000002,
        )
        self.assertIn("fuse prog -y 0 6 0x00000002", script)
        self.assertIn("fuse cmp 0 6 0x00000002", script)

    def test_generate_tegra234_xml_sha256(self) -> None:
        dummy_hash = "A" * 64
        xml = generate_tegra234_odmfuse_xml(dummy_hash)
        self.assertIn('<genericfuse MagicId="0x45535546" version="1.0.0">', xml)
        self.assertIn(f'value="0x{dummy_hash.lower()}"', xml)
        self.assertIn('fuse name="SecurityMode" size="4" value="0x00000001"', xml)

    def test_generate_tegra234_xml_invalid_len(self) -> None:
        with self.assertRaises(ValueError):
            generate_tegra234_odmfuse_xml("A" * 30)


class TestAuditor(unittest.TestCase):
    """Test 10-rule hardware Root-of-Trust security posture evaluation."""

    def setUp(self) -> None:
        with open(REPO_ROOT / "fixtures" / "hardened_fuse_policy.json", "r", encoding="utf-8") as f:
            self.hardened = json.load(f)
        with open(REPO_ROOT / "fixtures" / "vulnerable_fuse_policy.json", "r", encoding="utf-8") as f:
            self.vulnerable = json.load(f)

    def test_hardened_policy_score_100(self) -> None:
        report = audit_fuse_policy(self.hardened)
        self.assertEqual(report.score, 100)
        self.assertEqual(report.status, "HARDENED")
        self.assertEqual(report.passed_rules, 10)
        self.assertEqual(report.failed_rules, 0)
        self.assertEqual(len(report.findings), 0)

    def test_vulnerable_policy_score_0(self) -> None:
        report = audit_fuse_policy(self.vulnerable)
        self.assertEqual(report.score, 0)
        self.assertEqual(report.status, "CRITICAL_RISK")
        self.assertEqual(report.passed_rules, 0)
        self.assertEqual(report.failed_rules, 10)
        self.assertEqual(len(report.findings), 10)

        # Ensure all 10 rules triggered
        rule_ids = {f.rule_id for f in report.findings}
        for i in range(1, 11):
            expected_id = f"LH-FUSE-{i:03d}"
            self.assertIn(expected_id, rule_ids)

    def test_rule_001_trigger(self) -> None:
        p = dict(self.hardened)
        p["secure_boot_enforced"] = False
        rep = audit_fuse_policy(p)
        self.assertEqual(rep.score, 75)
        self.assertEqual(len(rep.findings), 1)
        self.assertEqual(rep.findings[0].rule_id, "LH-FUSE-001")

    def test_rule_002_trigger(self) -> None:
        p = dict(self.hardened)
        p["srk_hash_hex"] = "0" * 64
        rep = audit_fuse_policy(p)
        self.assertEqual(rep.score, 75)
        self.assertEqual(rep.findings[0].rule_id, "LH-FUSE-002")

    def test_rule_003_trigger(self) -> None:
        p = dict(self.hardened)
        p["jtag_debug_mode"] = "ENABLED"
        rep = audit_fuse_policy(p)
        self.assertEqual(rep.score, 75)
        self.assertEqual(rep.findings[0].rule_id, "LH-FUSE-003")

    def test_rule_004_trigger(self) -> None:
        p = dict(self.hardened)
        p["lock_srk_fuse_bank"] = False
        rep = audit_fuse_policy(p)
        self.assertEqual(rep.score, 90)
        self.assertEqual(rep.findings[0].rule_id, "LH-FUSE-004")

    def test_rule_005_trigger(self) -> None:
        p = dict(self.hardened)
        p["disable_unauthenticated_serial_boot"] = False
        rep = audit_fuse_policy(p)
        self.assertEqual(rep.score, 90)
        self.assertEqual(rep.findings[0].rule_id, "LH-FUSE-005")

    def test_rule_006_trigger(self) -> None:
        p = dict(self.hardened)
        p["monotonic_svn_counter"] = 0
        rep = audit_fuse_policy(p)
        self.assertEqual(rep.score, 90)
        self.assertEqual(rep.findings[0].rule_id, "LH-FUSE-006")

    def test_rule_007_trigger(self) -> None:
        p = dict(self.hardened)
        p["srk_total_key_slots"] = 1
        rep = audit_fuse_policy(p)
        self.assertEqual(rep.score, 90)
        self.assertEqual(rep.findings[0].rule_id, "LH-FUSE-007")

    def test_rule_008_trigger(self) -> None:
        p = dict(self.hardened)
        p["uboot_bootdelay"] = 3
        rep = audit_fuse_policy(p)
        self.assertEqual(rep.score, 96)
        self.assertEqual(rep.findings[0].rule_id, "LH-FUSE-008")

    def test_rule_009_trigger(self) -> None:
        p = dict(self.hardened)
        p["verify_readback_before_lock"] = False
        rep = audit_fuse_policy(p)
        self.assertEqual(rep.score, 96)
        self.assertEqual(rep.findings[0].rule_id, "LH-FUSE-009")

    def test_rule_001_lifecycle_state_variations(self) -> None:
        p1 = dict(self.hardened, secure_boot_enforced=True, lifecycle_state="OPEN_DEVELOPMENT")
        rep1 = audit_fuse_policy(p1)
        self.assertEqual(rep1.score, 75)
        self.assertEqual(rep1.findings[0].rule_id, "LH-FUSE-001")

        p2 = dict(self.hardened, secure_boot_enforced=True, lifecycle_state="CLOSED_PRODUCTION")
        rep2 = audit_fuse_policy(p2)
        self.assertEqual(rep2.score, 100)

    def test_rule_002_short_or_invalid_hash(self) -> None:
        p1 = dict(self.hardened, srk_hash_hex="A" * 63)  # 63 chars (too short)
        rep1 = audit_fuse_policy(p1)
        self.assertEqual(rep1.findings[0].rule_id, "LH-FUSE-002")

        p2 = dict(self.hardened, key_algorithm="UNKNOWN_ALGO")
        rep2 = audit_fuse_policy(p2)
        self.assertEqual(rep2.findings[0].rule_id, "LH-FUSE-002")

    def test_rule_003_jtag_modes(self) -> None:
        p_auth = dict(self.hardened, jtag_debug_mode="AUTHENTICATED_CHALLENGE_ONLY")
        rep_auth = audit_fuse_policy(p_auth)
        self.assertEqual(rep_auth.score, 100)

        p_open = dict(self.hardened, jtag_debug_mode="SECURE_OPEN")
        rep_open = audit_fuse_policy(p_open)
        self.assertEqual(rep_open.findings[0].rule_id, "LH-FUSE-003")

    def test_rule_005_rcm_payload_signing(self) -> None:
        p = dict(self.hardened, enforce_signed_rcm_payloads=False)
        rep = audit_fuse_policy(p)
        self.assertEqual(rep.findings[0].rule_id, "LH-FUSE-005")

    def test_rule_007_revocation_guard(self) -> None:
        p = dict(self.hardened, srk_revocation_lock_guard=False)
        rep = audit_fuse_policy(p)
        self.assertEqual(rep.findings[0].rule_id, "LH-FUSE-007")

    def test_rule_008_env_writeable(self) -> None:
        p = dict(self.hardened, uboot_env_writeable=True)
        rep = audit_fuse_policy(p)
        self.assertEqual(rep.findings[0].rule_id, "LH-FUSE-008")

        p_cmd = dict(self.hardened, disable_runtime_uboot_fuse_cmd=False)
        rep_cmd = audit_fuse_policy(p_cmd)
        self.assertEqual(rep_cmd.findings[0].rule_id, "LH-FUSE-008")

    def test_rule_009_vpp_check(self) -> None:
        p = dict(self.hardened, vpp_voltage_rail_check=False)
        rep = audit_fuse_policy(p)
        self.assertEqual(rep.findings[0].rule_id, "LH-FUSE-009")

    def test_rule_010_uid_binding(self) -> None:
        p = dict(self.hardened, bind_fuse_receipt_to_soc_uid=False)
        rep = audit_fuse_policy(p)
        self.assertEqual(rep.findings[0].rule_id, "LH-FUSE-010")

    def test_partial_multiple_rule_scoring(self) -> None:
        # Rule 1 (25) + Rule 4 (10) + Rule 8 (4) = 39 deduction -> score 61
        p = dict(self.hardened, secure_boot_enforced=False, lock_srk_fuse_bank=False, uboot_bootdelay=0)
        rep = audit_fuse_policy(p)
        self.assertEqual(rep.score, 61)
        self.assertEqual(rep.status, "ELEVATED_RISK")
        self.assertEqual(len(rep.findings), 3)

    def test_adequate_tier_scoring(self) -> None:
        # Rule 8 (4) + Rule 10 (1) = 5 deduction -> score 95 -> ADEQUATE
        p = dict(self.hardened, uboot_bootdelay=0, hsm_ceremony_audit_logged=False)
        rep = audit_fuse_policy(p)
        self.assertEqual(rep.score, 95)
        self.assertEqual(rep.status, "ADEQUATE")


class TestMoreMathAndScripting(unittest.TestCase):
    """Additional unit tests for math edge cases, SHA-384 Tegra manifests, and CLI outputs."""

    def test_interleaved_bit_transitions(self) -> None:
        # 0x55555555 (01010101b) -> 0xFFFFFFFF (11111111b) is valid
        valid, conflicts = verify_fuse_transition(0x55555555, 0xFFFFFFFF)
        self.assertTrue(valid)
        self.assertEqual(conflicts, [])

        # 0xAAAAAAAA (10101010b) -> 0x55555555 (01010101b) has 16 conflicting bits
        valid, conflicts = verify_fuse_transition(0xAAAAAAAA, 0x55555555)
        self.assertFalse(valid)
        self.assertEqual(len(conflicts), 16)

    def test_tegra234_sha384_xml(self) -> None:
        dummy_384_hash = "B" * 96  # 48 bytes
        xml = generate_tegra234_odmfuse_xml(dummy_384_hash)
        self.assertIn('size="48"', xml)
        self.assertIn(f'value="0x{dummy_384_hash.lower()}"', xml)

    def test_uboot_script_without_vpp_check(self) -> None:
        script = generate_uboot_fuse_script(bank=1, start_word=2, words=[0x12345678], vpp_check=False)
        self.assertNotIn("vpp_rail_ok", script)
        self.assertIn("fuse sense 1 2", script)
        self.assertIn("fuse prog -y 1 2 0x12345678", script)

    def test_cli_output_file_scan(self) -> None:
        fixture = str(REPO_ROOT / "fixtures" / "hardened_fuse_policy.json")
        out_file = str(REPO_ROOT / "fixtures" / "temp_report.json")
        try:
            res = subprocess.run(
                [TestCLISubprocess.BIN, "scan", fixture, "--format", "json", "--output", out_file],
                capture_output=True,
                text=True,
            )
            self.assertEqual(res.returncode, 0)
            self.assertTrue(os.path.exists(out_file))
            with open(out_file, "r") as f:
                d = json.load(f)
            self.assertEqual(d["score"], 100)
        finally:
            if os.path.exists(out_file):
                os.remove(out_file)

    def test_cli_output_file_pack_srk(self) -> None:
        fixture = str(REPO_ROOT / "fixtures" / "sample_srk_pubkeys.json")
        out_file = str(REPO_ROOT / "fixtures" / "temp_srk.json")
        try:
            res = subprocess.run(
                [TestCLISubprocess.BIN, "pack-srk", fixture, "--format", "json", "--output", out_file],
                capture_output=True,
                text=True,
            )
            self.assertEqual(res.returncode, 0)
            self.assertTrue(os.path.exists(out_file))
            with open(out_file, "r") as f:
                d = json.load(f)
            self.assertIn("packed_fuse_words", d)
        finally:
            if os.path.exists(out_file):
                os.remove(out_file)

    def test_cli_output_file_gen_script(self) -> None:
        fixture = str(REPO_ROOT / "fixtures" / "sample_srk_pubkeys.json")
        out_file = str(REPO_ROOT / "fixtures" / "temp_script.scr")
        try:
            res = subprocess.run(
                [TestCLISubprocess.BIN, "gen-script", fixture, "--target", "uboot", "--output", out_file],
                capture_output=True,
                text=True,
            )
            self.assertEqual(res.returncode, 0)
            self.assertTrue(os.path.exists(out_file))
            with open(out_file, "r") as f:
                content = f.read()
            self.assertIn("fuse prog -y", content)
        finally:
            if os.path.exists(out_file):
                os.remove(out_file)


class TestExporters(unittest.TestCase):
    """Test terminal tables, JSON, and SARIF exports."""

    def test_audit_table_rendering(self) -> None:
        with open(REPO_ROOT / "fixtures" / "hardened_fuse_policy.json", "r", encoding="utf-8") as f:
            p = json.load(f)
        rep = audit_fuse_policy(p)
        tbl = render_audit_table(rep)
        self.assertIn("POSTURE AUDIT REPORT", tbl)
        self.assertIn("100 / 100", tbl)

    def test_sarif_export(self) -> None:
        with open(REPO_ROOT / "fixtures" / "vulnerable_fuse_policy.json", "r", encoding="utf-8") as f:
            p = json.load(f)
        rep = audit_fuse_policy(p)
        sarif_str = to_sarif(rep)
        doc = json.loads(sarif_str)
        self.assertEqual(doc["version"], "2.1.0")
        self.assertIn("runs", doc)
        self.assertEqual(len(doc["runs"][0]["results"]), 10)

    def test_srk_table_rendering(self) -> None:
        tbl = render_srk_table("A" * 64, [0x12345678] * 8, 80, [10] * 8, "little")
        self.assertIn("SUPER ROOT KEY", tbl)
        self.assertIn("0x12345678", tbl)


class TestCLISubprocess(unittest.TestCase):
    """Test CLI commands and exit codes via subprocess execution."""

    BIN = str(REPO_ROOT / "bin" / "lh-fuse")

    def test_cli_version(self) -> None:
        res = subprocess.run([self.BIN, "--version"], capture_output=True, text=True)
        self.assertEqual(res.returncode, 0)
        self.assertIn("lh-fuse v0.1.0", res.stdout)

    def test_cli_help(self) -> None:
        res = subprocess.run([self.BIN, "--help"], capture_output=True, text=True)
        self.assertEqual(res.returncode, 0)
        self.assertIn("Secure Boot OTP Fuse Burner", res.stdout)

    def test_cli_scan_hardened(self) -> None:
        fixture = str(REPO_ROOT / "fixtures" / "hardened_fuse_policy.json")
        res = subprocess.run([self.BIN, "scan", fixture], capture_output=True, text=True)
        self.assertEqual(res.returncode, 0)
        self.assertIn("100 / 100", res.stdout)

    def test_cli_scan_vulnerable(self) -> None:
        fixture = str(REPO_ROOT / "fixtures" / "vulnerable_fuse_policy.json")
        res = subprocess.run([self.BIN, "scan", fixture], capture_output=True, text=True)
        self.assertEqual(res.returncode, 1)
        self.assertIn("0 / 100", res.stdout)

    def test_cli_scan_json_and_sarif(self) -> None:
        fixture = str(REPO_ROOT / "fixtures" / "hardened_fuse_policy.json")
        res_json = subprocess.run([self.BIN, "scan", fixture, "--format", "json"], capture_output=True, text=True)
        self.assertEqual(res_json.returncode, 0)
        data = json.loads(res_json.stdout)
        self.assertEqual(data["score"], 100)

        res_sarif = subprocess.run([self.BIN, "scan", fixture, "--format", "sarif"], capture_output=True, text=True)
        self.assertEqual(res_sarif.returncode, 0)
        sarif_doc = json.loads(res_sarif.stdout)
        self.assertEqual(sarif_doc["version"], "2.1.0")

    def test_cli_pack_srk(self) -> None:
        fixture = str(REPO_ROOT / "fixtures" / "sample_srk_pubkeys.json")
        res = subprocess.run([self.BIN, "pack-srk", fixture], capture_output=True, text=True)
        self.assertEqual(res.returncode, 0)
        self.assertIn("SUPER ROOT KEY", res.stdout)

        res_json = subprocess.run([self.BIN, "pack-srk", fixture, "--format", "json"], capture_output=True, text=True)
        self.assertEqual(res_json.returncode, 0)
        data = json.loads(res_json.stdout)
        self.assertIn("composite_hash", data)
        self.assertEqual(len(data["packed_fuse_words"]), 8)

    def test_cli_gen_script_uboot(self) -> None:
        fixture = str(REPO_ROOT / "fixtures" / "sample_srk_pubkeys.json")
        res = subprocess.run([self.BIN, "gen-script", fixture, "--target", "uboot"], capture_output=True, text=True)
        self.assertEqual(res.returncode, 0)
        self.assertIn("fuse prog -y 3", res.stdout)

    def test_cli_gen_script_tegra234(self) -> None:
        fixture = str(REPO_ROOT / "fixtures" / "sample_srk_pubkeys.json")
        res = subprocess.run([self.BIN, "gen-script", fixture, "--target", "tegra234"], capture_output=True, text=True)
        self.assertEqual(res.returncode, 0)
        self.assertIn("<genericfuse MagicId", res.stdout)

    def test_cli_verify_transition_valid(self) -> None:
        res = subprocess.run(
            [self.BIN, "verify-transition", "--current", "0x00000000", "--target", "0xA5A5F00D"],
            capture_output=True,
            text=True,
        )
        self.assertEqual(res.returncode, 0)
        self.assertIn("[VALID]", res.stdout)

    def test_cli_verify_transition_invalid(self) -> None:
        res = subprocess.run(
            [self.BIN, "verify-transition", "--current", "0x0000000F", "--target", "0x0000000E"],
            capture_output=True,
            text=True,
        )
        self.assertEqual(res.returncode, 1)
        self.assertIn("[PHYSICAL VIOLATION]", res.stderr)

    def test_cli_encode_svn(self) -> None:
        res = subprocess.run([self.BIN, "encode-svn", "--version-num", "5"], capture_output=True, text=True)
        self.assertEqual(res.returncode, 0)
        self.assertIn("0x000000000000001F", res.stdout)

    def test_cli_missing_args(self) -> None:
        res = subprocess.run([self.BIN], capture_output=True, text=True)
        self.assertEqual(res.returncode, 2)


if __name__ == "__main__":
    unittest.main()
