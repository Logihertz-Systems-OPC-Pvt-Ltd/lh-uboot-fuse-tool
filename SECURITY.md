# Security Policy

## Supported Versions

Logihertz Systems (OPC) Private Limited maintains security updates and patch releases for the following versions of `lh-uboot-fuse-tool`:

| Version | Supported          | Security Maintenance Status |
|---------|--------------------|-----------------------------|
| 0.1.x   | :white_check_mark: | Active Current Release      |
| < 0.1.0 | :x:                | Unsupported Initial Dev     |

---

## Threat Model & Hardware Root-of-Trust (RoT) Security

One-Time Programmable (OTP) hardware eFuses constitute the immutable foundation of modern embedded Root-of-Trust architectures (including NXP High Assurance Boot / AHAB, NVIDIA Tegra234 Orin PKC/SBK, and ARM TrustZone).

Hardware fuse manipulation involves irreversible physical silicon state transitions:
- **Permanent Physical Electromigration**: eFuses function via microscopic polysilicon or metal link rupture triggered by high programming voltages ($V_{\text{PP}}$). Silicon physics permits exclusively $0 \to 1$ transitions; reversing a blown fuse back to $0$ is physically impossible. Accidental or malformed writes permanently brick SoCs.
- **Root Key Hash Substitution**: If the SRK / PKC fuse bank is left unlocked (`lock_srk_fuse_bank: false`), an attacker with local root execution can overwrite unblown bits, hijacking the Root-of-Trust verification chain.
- **JTAG / SWD Silicon Probing**: Unfused or open JTAG/SWD interfaces allow debuggers to halt BootROM execution, bypass signature checks, and dump internal SRAM secrets.
- **Unauthenticated Serial Recovery Exploit**: Open USB/UART serial download protocols (such as NXP SDP or NVIDIA RCM) permit arbitrary unsigned payload injection into internal IRAM unless cryptographically gated or disabled.
- **Firmware Rollback Exploits**: Without monotonic anti-rollback Security Version Number (SVN) thermometer fuses, attackers can downgrade signed firmware to historical vulnerable releases.

`lh-uboot-fuse-tool` provides formal deterministic validation to eliminate these failure modes before production factory burning:
1. **Mathematical $0 \to 1$ Transition Invariant Verification**: Bitwise state transition checking guaranteeing $(F_{\text{curr}} \ \& \ \sim F_{\text{target}}) == 0$ before provisioning scripts are synthesized.
2. **Pre-flight & Post-burn Verification Pairs**: Enforces atomic `fuse sense` dry runs, `fuse prog -y`, and `fuse cmp` readback verification halting execution immediately upon bit discrepancy.
3. **10-Rule Hardware Security Posture Auditor**: Audits fuse configurations against CWE and industrial benchmarks to ensure zero open security gates prior to silicon closure.

---

## Reporting a Vulnerability

If you discover a vulnerability in `lh-uboot-fuse-tool`, please report it promptly through coordinated disclosure:

- **Primary Contact**: Sameer Tawade <ops@logihertz.com>
- **Security Contact**: <security@logihertz.com>
- **Subject**: `[SECURITY VULNERABILITY] lh-uboot-fuse-tool - <Component>`
- **Response Commitment**: Initial acknowledgment within 24 hours, triage within 48 hours, and patch verification within 14 business days.
