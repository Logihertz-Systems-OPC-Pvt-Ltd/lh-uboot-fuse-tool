# Contributing to Logihertz Secure Boot OTP Hardware Fuse Burner (`lh-uboot-fuse-tool`)

Thank you for contributing to `lh-uboot-fuse-tool`. This tool provides mission-critical hardware root-of-trust verification and provisioning script synthesis for high-assurance embedded systems.

---

## Architectural & Governance Principles

1. **Zero External Runtime Dependencies**:
   - The entire codebase must execute using Python 3.11+ standard library modules exclusively (`json`, `hashlib`, `hmac`, `struct`, `argparse`, `pathlib`, `dataclasses`, `typing`).
   - Third-party packages (e.g. `requests`, `pydantic`, `cryptography`, `click`) are strictly prohibited in `pyproject.toml` runtime dependencies.
2. **Silicon Safety & Irreversibility Invariants**:
   - All fuse generation operations must adhere to silicon physics: eFuses only transition $0 \to 1$.
   - The bitwise transition check `(current & ~target) == 0` must always be enforced to prevent bricked SoCs.
   - Any script generator must include pre-flight dry runs and readback comparison commands (`fuse cmp`) before issuing lock commands.
3. **Deterministic Cryptographic Math**:
   - Super Root Key (SRK) and Public Key Cryptography (PKC) table hashing must strictly follow NXP HAB/AHAB and NVIDIA Tegra specifications.
   - Anti-rollback Security Version Numbers (SVN) must follow monotonic unary thermometer encoding $M_{\text{SVN}}(v) = (1 \ll v) - 1$.
4. **Clean Code & Universal Version Support**:
   - Support Python 3.11, 3.12, and 3.13 without deprecation warnings.
   - Clean type annotations with `typing`.

---

## Development Workflow

### Prerequisites
- Python 3.11 or later.

### Verification & Testing
```bash
# Verify syntax across all modules
python3 -m py_compile src/lh_uboot_fuse_tool/*.py tests/test_uboot_fuse_tool.py

# Run the comprehensive test suite
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

### CLI Verification
```bash
PYTHONPATH=src python3 -m lh_uboot_fuse_tool.cli --help
PYTHONPATH=src python3 -m lh_uboot_fuse_tool.cli scan fixtures/hardened_fuse_policy.json
```

---

## Pull Request Guidelines

1. **Zero Regressions**: All 85+ unit tests must pass cleanly.
2. **Targeted Commits**: Keep commits focused and provide clear explanations of hardware fuse mappings or architectural rationale.
3. **License Agreement**: All contributions are licensed under the Apache License 2.0.
