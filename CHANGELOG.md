# Changelog

All notable changes to `lh-uboot-fuse-tool` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.1.0] - 2026-11-13

### Added
- **Core OTP Hardware Fuse Math (`fuse_math.py`)**:
  - Hierarchical Super Root Key (SRK) and Public Key Cryptography (PKC) table hashing conforming to NXP HAB/AHAB and NVIDIA Tegra234 specifications.
  - Multi-slot public key digest concatenation ($D_{\text{SRK}} = \text{SHA-256}(d_0 \parallel d_1 \dots \parallel d_{K-1})$).
  - 32-bit unsigned little-endian and big-endian OTP fuse word packing ($W_0 \dots W_7$).
  - Exact bit-level Hamming weight / popcount calculation across all 8 fuse words and per-word.
  - Silicon eFuse irreversibility transition guard verifying $(F_{\text{curr}} \ \& \ \sim F_{\text{target}}) == 0$ with conflicting bit identification.
  - Monotonic anti-rollback Security Version Number (SVN) unary thermometer bitmask encoder ($M_{\text{SVN}}(v) = (1 \ll v) - 1$) and downgrade transition blocker.
- **Provisioning Script & Manifest Synthesizer (`script_generator.py`)**:
  - Deterministic U-Boot provisioning script generator with pre-flight dry-run `fuse sense`, atomic `fuse prog -y`, and post-burn `fuse cmp` verification pairs with exit guards.
  - NVIDIA Jetson Orin (`tegra234`) `generic_odmfuse` XML manifest generator specifying `PublicKeyHash`, `BootSecurityInfo`, `SecurityMode`, and anti-rollback ratchet words.
  - Script SHA-256 integrity verification footer.
- **10-Rule Hardware Root-of-Trust Posture Auditor (`auditor.py`)**:
  - `LH-FUSE-001`: Hardware Secure Boot enforcement fuse open (Critical, 25 pts, CWE-347).
  - `LH-FUSE-002`: All-zero or weak Public Key Hash (Critical, 25 pts, CWE-326).
  - `LH-FUSE-003`: Hardware JTAG/SWD debug interface open in production (Critical, 25 pts, CWE-1191).
  - `LH-FUSE-004`: OTP SRK/PKC hash bank write-lock fuse not blown (High, 10 pts, CWE-276).
  - `LH-FUSE-005`: BootROM serial download recovery mode unauthenticated (High, 10 pts, CWE-306).
  - `LH-FUSE-006`: Hardware anti-rollback SVN fuse ratchet disabled or zeroed (High, 10 pts, CWE-693).
  - `LH-FUSE-007`: Missing backup Super Root Key slots or unlocked revocation (High, 10 pts, CWE-320).
  - `LH-FUSE-008`: U-Boot interactive CLI or runtime fuse programming command enabled (Medium, 4 pts, CWE-693).
  - `LH-FUSE-009`: Missing pre-burn sense check or post-burn readback verification (Medium, 4 pts, CWE-754).
  - `LH-FUSE-010`: Missing HSM signing ceremony audit log or UID binding (Low, 1 pt, CWE-778).
- **Multi-Format Exporters & CLI (`exporters.py`, `cli.py`, `bin/lh-fuse`)**:
  - Colorized ANSI terminal tables with posture score banners.
  - Canonical deterministic JSON exporter.
  - OASIS SARIF v2.1.0 exporter for industrial DevSecOps pipelines.
  - Subcommands: `scan`, `pack-srk`, `gen-script`, `verify-transition`, `encode-svn`, `--version`, `--help`.
- **Zero-Dependency Architecture**:
  - Implemented entirely with Python 3.11+ Standard Library.
