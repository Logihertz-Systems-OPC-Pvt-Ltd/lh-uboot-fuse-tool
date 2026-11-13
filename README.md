# Logihertz Secure Boot OTP Hardware Fuse Burner (`lh-uboot-fuse-tool`)

[![CI](https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-uboot-fuse-tool/actions/workflows/ci.yml/badge.svg)](https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-uboot-fuse-tool/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13-blue.svg)](pyproject.toml)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Zero External Dependencies](https://img.shields.io/badge/dependencies-0%20(stdlib%20only)-success.svg)](pyproject.toml)

**`lh-uboot-fuse-tool`** (`bin/lh-fuse`) is a zero-dependency, production-grade **Secure Boot One-Time Programmable (OTP) Hardware Fuse Burner, SRK/PKC Public Key Hash Synthesizer, Irreversible Bit-Transition Verifier, and 10-Rule Hardware Root-of-Trust (RoT) Posture Auditor** implemented entirely in standard Python 3.11+.

Engineered by **Logihertz Systems (OPC) Private Limited** for high-assurance embedded systems, industrial IoT gateways, automotive compute units, and sovereign edge AI appliances (including NXP i.MX / Layerscape, NVIDIA Jetson Orin `tegra234`, and ARM TrustZone SoCs).

---

## Core Capabilities

- **Zero External Runtime Dependencies**: 100% Python Standard Library (`json`, `hashlib`, `struct`, `argparse`, `pathlib`, `dataclasses`, `typing`). Eliminates supply chain risks in air-gapped factory provisioning environments.
- **Hierarchical Super Root Key (SRK/PKC) Table Hashing**:
  - Computes standard NXP HAB/AHAB and NVIDIA Tegra234 Orin public key table digests across up to 4 root keys ($K \in \{1, 2, 3, 4\}$).
  - Packs 256-bit / 384-bit digests into consecutive 32-bit unsigned little-endian or big-endian OTP words.
  - Computes exact bit-level Hamming weight ($\text{popcount}$) across all words and per word.
- **Silicon eFuse Irreversibility Invariant Guard**:
  - Enforces physical silicon electromigration constraints ($0 \to 1$ only; $1 \to 0$ impossible).
  - Evaluates bitwise monotonicity $(F_{\text{curr}} \ \& \ \sim F_{\text{target}}) == 0$ prior to synthesis, identifying exact conflicting bit positions to prevent bricked SoCs.
- **Monotonic Anti-Rollback SVN Thermometer Bitmask Encoder**:
  - Encodes Security Version Numbers ($v \in [0, 64]$) into unary thermometer bitmasks $M_{\text{SVN}}(v) = (1 \ll v) - 1$.
  - Enforces strict monotonic progression ($v_{\text{new}} \ge v_{\text{old}}$) to prevent firmware downgrade attacks.
- **Automated Provisioning Script & Manifest Synthesizer**:
  - Emits hardened U-Boot provisioning scripts featuring pre-flight dry-run `fuse sense`, atomic `fuse prog -y`, and immediate `fuse cmp` readback verification pairs with abort-on-error gates.
  - Synthesizes compliant NVIDIA Jetson Orin (`tegra234`) `generic_odmfuse` XML manifests.
- **10-Rule Hardware Root-of-Trust Posture Auditor**:
  - Deterministic evaluation of factory fuse policies against industrial RoT standards, mapping misconfigurations directly to CWEs.
  - Multi-format reporting: Colorized ANSI terminal tables, Canonical JSON, and OASIS SARIF v2.1.0 for factory DevSecOps pipelines.

---

## Architecture & Silicon Physics

```
       FACTORY KEY CEREMONY / HSM MANIFEST
       ┌────────────────────────────────────────────────────────┐
       │ Public Key Manifest {P_0, P_1, P_2, P_3} (RSA / ECDSA) │
       └───────────────────────────┬────────────────────────────┘
                                   │
                                   ▼
       ┌────────────────────────────────────────────────────────┐
       │                lh-uboot-fuse-tool                      │
       │                                                        │
       │ 1. Individual Key Digests:   d_i = SHA-256(P_i)        │
       │ 2. Composite SRK Digest:     D_SRK = SHA-256(d_0..d_3) │
       │ 3. 32-bit Word Packing:      W_k = unpack_le(D_SRK[k]) │
       │ 4. Silicon Transition Check: (F_curr & ~F_target) == 0 │
       │ 5. SVN Thermometer Mask:     M_SVN = (1 << v) - 1      │
       └───────────────────────────┬────────────────────────────┘
                                   │
                  ┌────────────────┴────────────────┐
                  ▼                                 ▼
       ┌───────────────────────┐         ┌───────────────────────┐
       │ U-Boot Provisioning   │         │ NVIDIA Tegra234 Orin  │
       │ Shell Script (.scr)   │         │ odmfuse XML Manifest  │
       ├───────────────────────┤         ├───────────────────────┤
       │ • fuse sense dry-runs │         │ • PublicKeyHash       │
       │ • fuse prog -y words  │         │ • BootSecurityInfo    │
       │ • fuse cmp readback   │         │ • SecurityMode = 0x1  │
       │ • fuse prog lock bank │         │ • ReservedOdm ratchet │
       └──────────┬────────────┘         └──────────┬────────────┘
                  │                                 │
                  ▼                                 ▼
       ┌────────────────────────────────────────────────────────┐
       │             TARGET EMBEDDED SYSTEM-ON-CHIP             │
       │          One-Time Programmable (OTP) eFuses            │
       │        (Physical Silicon Polysilicon Rupture)          │
       └────────────────────────────────────────────────────────┘
```

---

## Mathematical Formulations

### 1. Composite Super Root Key Table Hash
Given $K \in \{1, 2, 3, 4\}$ public keys $\{P_0, \dots, P_{K-1}\}$:
$$d_i = \text{SHA-256}(P_i) \quad \text{for } i \in \{0, \dots, K-1\}$$
$$D_{\text{SRK}} = \text{SHA-256}\left(d_0 \parallel d_1 \parallel \dots \parallel d_{K-1}\right)$$
For a 256-bit digest, $D_{\text{SRK}}$ is packed into 8 consecutive 32-bit OTP fuse words $W_0, \dots, W_7$:
$$W_k = \text{uint32\_le}\left(D_{\text{SRK}}[4k : 4k+4]\right) \quad \text{for } k \in \{0, \dots, 7\}$$

### 2. Hamming Weight (Popcount)
The total number of physically blown bits in the silicon fuse array is given by:
$$\text{popcount}(D_{\text{SRK}}) = \sum_{k=0}^{7} \sum_{b=0}^{31} \left(\frac{W_k}{2^b} \bmod 2\right)$$

### 3. Physical eFuse Monotonicity Invariant
Silicon eFuses rupture irreversibly through thermal electromigration ($0 \to 1$). Reversing a blown bit back to $0$ is physically impossible. Given current hardware register value $F_{\text{curr}}$ and target value $F_{\text{target}}$:
$$\left(F_{\text{curr}} \ \& \ \sim F_{\text{target}}\right) == 0 \iff \left(F_{\text{curr}} \mid F_{\text{target}}\right) == F_{\text{target}}$$
If $(F_{\text{curr}} \ \& \ \sim F_{\text{target}}) \ne 0$, an `IrreversibleBitTransitionError` is flagged with the exact set of conflicting bit indices:
$$\mathcal{B}_{\text{conflict}} = \left\{i \in \{0, \dots, 31\} \mid (F_{\text{curr}} \gg i) \ \& \ 1 = 1 \ \land \ (F_{\text{target}} \gg i) \ \& \ 1 = 0\right\}$$

### 4. Anti-Rollback Unary Thermometer Encoding
Anti-rollback security version $v \in [0, 64]$ is represented as a monotonic unary thermometer bitmask across two 32-bit fuse words:
$$M_{\text{SVN}}(v) = (1 \ll v) - 1$$
$$W_0 = M_{\text{SVN}}(v) \ \& \ \mathtt{0xFFFFFFFF}, \quad W_1 = (M_{\text{SVN}}(v) \gg 32) \ \& \ \mathtt{0xFFFFFFFF}$$

### 5. Security Posture Scoring
$$S_{\text{posture}} = \max\left(0, \; 100 - \left(25 \cdot c_{\text{CRITICAL}} + 10 \cdot c_{\text{HIGH}} + 4 \cdot c_{\text{MEDIUM}} + 1 \cdot c_{\text{LOW}}\right)\right)$$

---

## 10-Rule Hardware RoT Posture Matrix

| Rule ID | Severity | Weight | CWE | Title | Enforcement Objective |
|---|---|---|---|---|---|
| **`LH-FUSE-001`** | **CRITICAL** | 25 | CWE-347 | Hardware Secure Boot Enforcement Fuse Left Open | Enforces `SEC_CONFIG_CLOSED` / `CLOSED_PRODUCTION` |
| **`LH-FUSE-002`** | **CRITICAL** | 25 | CWE-326 | All-Zero, Test/Dummy, or Weak Public Key Hash | Rejects zeroed hashes & enforces RSA-3072+/ECDSA/Ed25519 |
| **`LH-FUSE-003`** | **CRITICAL** | 25 | CWE-1191 | Hardware JTAG / SWD Debug Interface Open in Production | Enforces `DISABLED` or `AUTHENTICATED_CHALLENGE_ONLY` |
| **`LH-FUSE-004`** | **HIGH** | 10 | CWE-276 | OTP SRK/PKC Hash Bank Write-Lock Fuse Not Blown | Ensures SRK write-lock fuse is blown post-burn |
| **`LH-FUSE-005`** | **HIGH** | 10 | CWE-306 | BootROM Serial Download Recovery Mode Unauthenticated | Restricts unauthenticated USB/UART recovery (SDP/RCM) |
| **`LH-FUSE-006`** | **HIGH** | 10 | CWE-693 | Hardware Anti-Rollback SVN Fuse Ratchet Disabled/Zeroed | Enforces active monotonic SVN fuse counter ($\ge 1$) |
| **`LH-FUSE-007`** | **HIGH** | 10 | CWE-320 | Missing Backup SRK Slots or Unlocked Revocation Guard | Requires $\ge 2$ SRK slots and key revocation lock |
| **`LH-FUSE-008`** | **MEDIUM** | 4 | CWE-693 | U-Boot Interactive CLI or Runtime Fuse Command Enabled | Enforces `bootdelay: -2`, read-only env & no runtime prog |
| **`LH-FUSE-009`** | **MEDIUM** | 4 | CWE-754 | Missing Pre-Burn Sense Check or Readback Verification | Requires atomic dry-run sense, prog, and `fuse cmp` pairs |
| **`LH-FUSE-010`** | **LOW** | 1 | CWE-778 | Missing HSM Ceremony Audit Log or UID Binding | Enforces cryptographic HSM log and SoC UID binding |

---

## Installation & CLI Usage

### Standalone Executable
```bash
git clone https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-uboot-fuse-tool.git
cd lh-uboot-fuse-tool
chmod +x bin/lh-fuse
```

### 1. Audit Factory Hardware Fuse Policy (`scan`)
```bash
# ANSI terminal table output
./bin/lh-fuse scan fixtures/hardened_fuse_policy.json

# Canonical JSON export
./bin/lh-fuse scan --format json fixtures/hardened_fuse_policy.json

# OASIS SARIF v2.1.0 report for CI/CD DevSecOps
./bin/lh-fuse scan --format sarif --output report.sarif fixtures/vulnerable_fuse_policy.json
```

### 2. Pack SRK Public Keys into 32-Bit Fuse Words (`pack-srk`)
```bash
# Terminal table output showing popcounts and word packing
./bin/lh-fuse pack-srk fixtures/sample_srk_pubkeys.json --endian little

# Machine-readable JSON output
./bin/lh-fuse pack-srk fixtures/sample_srk_pubkeys.json --endian big --format json
```

### 3. Generate Hardware Provisioning Scripts (`gen-script`)
```bash
# Synthesize hardened U-Boot fuse programming shell script
./bin/lh-fuse gen-script fixtures/sample_srk_pubkeys.json --target uboot --bank 3 --word-offset 0 --output provision.scr

# Synthesize NVIDIA Jetson Orin (Tegra234) generic_odmfuse XML manifest
./bin/lh-fuse gen-script fixtures/sample_srk_pubkeys.json --target tegra234 --output odmfuse.xml
```

### 4. Verify Physical eFuse Transition Monotonicity (`verify-transition`)
```bash
# Valid 0 -> 1 transition (Exits 0)
./bin/lh-fuse verify-transition --current 0x00000000 --target 0xA5A5F00D

# Invalid 1 -> 0 transition attempt (Exits 1 with conflicting bits)
./bin/lh-fuse verify-transition --current 0x0000000F --target 0x0000000E
```

### 5. Encode Anti-Rollback SVN Thermometer (`encode-svn`)
```bash
# Encode version 5 into unary thermometer bitmask
./bin/lh-fuse encode-svn --version-num 5

# Output in JSON format
./bin/lh-fuse encode-svn --version-num 32 --format json
```

---

## Exit Codes

| Exit Code | Classification | Description |
|---|---|---|
| `0` | **COMPLIANT / VALID** | Posture score 100/100, valid monotonic bit transition, or successful synthesis. |
| `1` | **FINDING / ERROR** | Posture score $< 100$, or impossible physical $1 \to 0$ eFuse transition detected. |
| `2` | **USAGE / I/O ERROR** | Command syntax error, missing argument, or file I/O parse error. |

---

## License & Attribution

Licensed under the **Apache License, Version 2.0**. See [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE) for details.

Developed by **Sameer Tawade**, Creator, Founder, Director & Sole Developer at **Logihertz Systems (OPC) Private Limited** (<https://logihertz.com/>).
