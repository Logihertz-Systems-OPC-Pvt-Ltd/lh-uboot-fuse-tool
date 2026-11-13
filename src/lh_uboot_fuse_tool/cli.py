"""Command-Line Interface (CLI) for Logihertz Secure Boot OTP Hardware Fuse Burner."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Sequence

from lh_uboot_fuse_tool import __version__
from lh_uboot_fuse_tool.auditor import audit_fuse_policy
from lh_uboot_fuse_tool.exporters import (
    render_audit_table,
    render_srk_table,
    to_json,
    to_sarif,
)
from lh_uboot_fuse_tool.fuse_math import (
    compute_hamming_weight,
    compute_per_word_hamming,
    compute_srk_table_hash,
    encode_svn_thermometer,
    pack_fuse_words,
    verify_fuse_transition,
)
from lh_uboot_fuse_tool.script_generator import (
    generate_tegra234_odmfuse_xml,
    generate_uboot_fuse_script,
)

TOOL_NAME = "lh-fuse"
ORG_NAME = "Logihertz Systems (OPC) Private Limited"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description=f"{TOOL_NAME} v{__version__} - Secure Boot OTP Fuse Burner & RoT Auditor ({ORG_NAME})",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exit Codes:
  0  Success / Compliant Posture (Score 100/100) / Valid Monotonic Transition
  1  Policy Violation (Score < 100) / Impossible 1 -> 0 Bit Transition Error
  2  Command-line Syntax Error / Missing File / JSON Parse Error
""",
    )
    parser.add_argument("-v", "--version", action="version", version=f"{TOOL_NAME} v{__version__} ({ORG_NAME})")

    subparsers = parser.add_subparsers(dest="subcommand", help="Available subcommands")

    # 1. scan
    p_scan = subparsers.add_parser("scan", help="Audit hardware fuse policy against 10 RoT rules")
    p_scan.add_argument("policy_file", type=str, help="Path to hardware fuse policy JSON manifest")
    p_scan.add_argument("--format", choices=["table", "json", "sarif"], default="table", help="Output format")
    p_scan.add_argument("--output", "-o", type=str, help="Optional output file destination")

    # 2. pack-srk
    p_pack = subparsers.add_parser("pack-srk", help="Compute SRK/PKC table hash and pack into 32-bit OTP words")
    p_pack.add_argument("manifest_file", type=str, help="Path to SRK public key manifest JSON")
    p_pack.add_argument("--endian", choices=["little", "big"], default="little", help="Word byte order")
    p_pack.add_argument("--format", choices=["table", "json"], default="table", help="Output format")
    p_pack.add_argument("--output", "-o", type=str, help="Optional output file destination")

    # 3. gen-script
    p_gen = subparsers.add_parser("gen-script", help="Synthesize U-Boot fuse script or Tegra234 odmfuse XML")
    p_gen.add_argument("manifest_file", type=str, help="Path to SRK public key manifest JSON")
    p_gen.add_argument("--target", choices=["uboot", "tegra234"], default="uboot", help="Target hardware platform")
    p_gen.add_argument("--bank", type=int, default=3, help="U-Boot target fuse bank index (default: 3)")
    p_gen.add_argument("--word-offset", type=int, default=0, help="U-Boot starting word offset (default: 0)")
    p_gen.add_argument("--lock-bank", type=int, default=None, help="Optional bank index to lock")
    p_gen.add_argument("--lock-word", type=int, default=None, help="Optional word offset to lock")
    p_gen.add_argument("--lock-val", type=lambda x: int(x, 0), default=None, help="Optional lock word value (e.g. 0x00000002)")
    p_gen.add_argument("--output", "-o", type=str, help="Optional output script/XML file destination")

    # 4. verify-transition
    p_trans = subparsers.add_parser("verify-transition", help="Verify physical eFuse 0 -> 1 bit transition monotonicity")
    p_trans.add_argument("--current", type=lambda x: int(x, 0), required=True, help="Current 32-bit hardware fuse register word (e.g. 0x00000000)")
    p_trans.add_argument("--target", type=lambda x: int(x, 0), required=True, help="Target 32-bit hardware fuse register word (e.g. 0xA5A5F00D)")

    # 5. encode-svn
    p_svn = subparsers.add_parser("encode-svn", help="Encode anti-rollback SVN into unary thermometer bitmask")
    p_svn.add_argument("--version-num", type=int, required=True, help="Security Version Number [0..64]")
    p_svn.add_argument("--format", choices=["table", "json"], default="table", help="Output format")
    p_svn.add_argument("--output", "-o", type=str, help="Optional output destination")

    return parser


def handle_scan(args: argparse.Namespace) -> int:
    path = Path(args.policy_file)
    if not path.is_file():
        sys.stderr.write(f"Error: Policy file not found: {args.policy_file}\n")
        return 2

    try:
        with open(path, "r", encoding="utf-8") as f:
            policy_data = json.load(f)
    except Exception as e:
        sys.stderr.write(f"Error: Failed to parse policy JSON: {e}\n")
        return 2

    if "name" not in policy_data:
        policy_data["name"] = path.name

    report = audit_fuse_policy(policy_data)

    if args.format == "table":
        out = render_audit_table(report) + "\n"
    elif args.format == "json":
        out = to_json(report) + "\n"
    elif args.format == "sarif":
        out = to_sarif(report) + "\n"
    else:
        sys.stderr.write(f"Error: Unsupported format: {args.format}\n")
        return 2

    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(out)
        except Exception as e:
            sys.stderr.write(f"Error: Failed to write output file: {e}\n")
            return 2
    else:
        sys.stdout.write(out)

    return 0 if report.score == 100 else 1


def handle_pack_srk(args: argparse.Namespace) -> int:
    path = Path(args.manifest_file)
    if not path.is_file():
        sys.stderr.write(f"Error: Manifest file not found: {args.manifest_file}\n")
        return 2

    try:
        with open(path, "r", encoding="utf-8") as f:
            manifest = json.load(f)
    except Exception as e:
        sys.stderr.write(f"Error: Failed to parse manifest JSON: {e}\n")
        return 2

    keys = manifest.get("public_keys", [])
    if not keys:
        sys.stderr.write("Error: Manifest must contain non-empty 'public_keys' array\n")
        return 2

    algo = manifest.get("hash_algorithm", "sha256")
    try:
        comp_hex, comp_bytes, ind_digests = compute_srk_table_hash(keys, algo)
        words = pack_fuse_words(comp_bytes, endianness=args.endian)
        hamming = compute_hamming_weight(words)
        per_word_hamming = compute_per_word_hamming(words)
    except Exception as e:
        sys.stderr.write(f"Error: SRK packing failed: {e}\n")
        return 2

    if args.format == "table":
        out = render_srk_table(comp_hex, words, hamming, per_word_hamming, args.endian)
    else:
        out_dict = {
            "composite_hash": comp_hex,
            "hash_algorithm": algo,
            "endianness": args.endian,
            "total_hamming_weight": hamming,
            "individual_key_digests": ind_digests,
            "packed_fuse_words": [f"0x{(w & 0xFFFFFFFF):08X}" for w in words],
            "packed_fuse_words_int": words,
            "per_word_hamming": per_word_hamming,
        }
        out = to_json(out_dict) + "\n"

    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(out)
        except Exception as e:
            sys.stderr.write(f"Error: Failed to write output file: {e}\n")
            return 2
    else:
        sys.stdout.write(out)

    return 0


def handle_gen_script(args: argparse.Namespace) -> int:
    path = Path(args.manifest_file)
    if not path.is_file():
        sys.stderr.write(f"Error: Manifest file not found: {args.manifest_file}\n")
        return 2

    try:
        with open(path, "r", encoding="utf-8") as f:
            manifest = json.load(f)
    except Exception as e:
        sys.stderr.write(f"Error: Failed to parse manifest JSON: {e}\n")
        return 2

    keys = manifest.get("public_keys", [])
    if not keys:
        sys.stderr.write("Error: Manifest must contain non-empty 'public_keys' array\n")
        return 2

    algo = manifest.get("hash_algorithm", "sha256")
    try:
        comp_hex, comp_bytes, _ = compute_srk_table_hash(keys, algo)
        words = pack_fuse_words(comp_bytes, endianness="little")
    except Exception as e:
        sys.stderr.write(f"Error: Failed computing SRK table hash: {e}\n")
        return 2

    if args.target == "uboot":
        script = generate_uboot_fuse_script(
            bank=args.bank,
            start_word=args.word_offset,
            words=words,
            lock_bank=args.lock_bank,
            lock_word=args.lock_word,
            lock_val=args.lock_val,
        )
    elif args.target == "tegra234":
        script = generate_tegra234_odmfuse_xml(
            public_key_hash_hex=comp_hex,
            boot_security_info=manifest.get("boot_security_info", 0x00000001),
            security_mode=manifest.get("security_mode", 0x00000001),
            reserved_odm0=manifest.get("reserved_odm0", 0x00000000),
            reserved_odm1=manifest.get("reserved_odm1", 0x00000000),
        )
    else:
        sys.stderr.write(f"Error: Unsupported target: {args.target}\n")
        return 2

    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(script)
        except Exception as e:
            sys.stderr.write(f"Error: Failed writing script output: {e}\n")
            return 2
    else:
        sys.stdout.write(script)

    return 0


def handle_verify_transition(args: argparse.Namespace) -> int:
    curr = args.current & 0xFFFFFFFF
    targ = args.target & 0xFFFFFFFF
    valid, conflicting_bits = verify_fuse_transition(curr, targ)

    if valid:
        sys.stdout.write(
            f"[VALID] Monotonic eFuse transition verified: 0x{curr:08X} -> 0x{targ:08X} "
            f"(Blown delta bits: {((targ ^ curr) & 0xFFFFFFFF).bit_count()})\n"
        )
        return 0

    bits_str = ", ".join(str(b) for b in conflicting_bits)
    sys.stderr.write(
        f"[PHYSICAL VIOLATION] Impossible 1 -> 0 eFuse transition: 0x{curr:08X} -> 0x{targ:08X}\n"
        f"Conflicting bit indices (cannot revert 1 to 0): [{bits_str}]\n"
    )
    return 1


def handle_encode_svn(args: argparse.Namespace) -> int:
    v = args.version_num
    if not (0 <= v <= 64):
        sys.stderr.write(f"Error: Version number must be in range [0..64], got {v}\n")
        return 2

    total_mask, word0, word1 = encode_svn_thermometer(v)
    if args.format == "table":
        lines = [
            f"SVN Counter Value : {v} / 64",
            f"Thermometer Mask  : 0x{total_mask:016X}",
            f"Word 0 (Bits 0..31): 0x{word0:08X} (Popcount: {word0.bit_count()})",
            f"Word 1 (Bits 32.63): 0x{word1:08X} (Popcount: {word1.bit_count()})",
            f"Total Bits Blown  : {total_mask.bit_count()}",
        ]
        out = "\n".join(lines) + "\n"
    else:
        out_dict = {
            "svn_version": v,
            "total_mask_hex": f"0x{total_mask:016X}",
            "word0_hex": f"0x{word0:08X}",
            "word1_hex": f"0x{word1:08X}",
            "total_bits_blown": total_mask.bit_count(),
        }
        out = to_json(out_dict) + "\n"

    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(out)
        except Exception as e:
            sys.stderr.write(f"Error: Failed writing SVN output: {e}\n")
            return 2
    else:
        sys.stdout.write(out)

    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    if argv is None:
        argv = sys.argv[1:]

    if not argv:
        parser.print_help()
        return 2

    args = parser.parse_args(argv)

    if args.subcommand == "scan":
        return handle_scan(args)
    if args.subcommand == "pack-srk":
        return handle_pack_srk(args)
    if args.subcommand == "gen-script":
        return handle_gen_script(args)
    if args.subcommand == "verify-transition":
        return handle_verify_transition(args)
    if args.subcommand == "encode-svn":
        return handle_encode_svn(args)

    parser.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
