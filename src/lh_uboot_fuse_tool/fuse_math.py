"""Silicon OTP Hardware Fuse Mathematics & Root-of-Trust Synthesizer.

Implements SRK/PKC hierarchical public key table hashing, 32-bit OTP fuse word
packing, physical eFuse irreversibility transition validation, and monotonic
anti-rollback SVN unary thermometer bitmask encoding.
"""

from __future__ import annotations

import hashlib
import struct
from typing import Sequence


class IrreversibleBitTransitionError(ValueError):
    """Raised when an eFuse word transition attempts an impossible 1 -> 0 bit change."""

    def __init__(self, current: int, target: int, conflicting_bits: list[int]) -> None:
        self.current = current & 0xFFFFFFFF
        self.target = target & 0xFFFFFFFF
        self.conflicting_bits = conflicting_bits
        bits_str = ", ".join(str(b) for b in conflicting_bits)
        super().__init__(
            f"Physical eFuse violation: cannot transition 1 -> 0 from 0x{self.current:08X} "
            f"to 0x{self.target:08X}. Conflicting bit indices: [{bits_str}]"
        )


def verify_fuse_transition(current: int, target: int) -> tuple[bool, list[int]]:
    """Verify that a 32-bit fuse transition satisfies silicon monotonicity (0 -> 1 only).

    Silicon eFuses physically rupture through thermal electromigration and can never
    revert from blown (1) to unblown (0).

    Condition:
        (current & ~target) == 0  <=>  (current | target) == target

    Returns:
        (is_valid, conflicting_bit_indices)
    """
    curr_32 = current & 0xFFFFFFFF
    targ_32 = target & 0xFFFFFFFF

    impossible_mask = curr_32 & (~targ_32) & 0xFFFFFFFF
    if impossible_mask == 0:
        return True, []

    conflicting_bits = [i for i in range(32) if (impossible_mask & (1 << i)) != 0]
    return False, conflicting_bits


def compute_key_digest(key_data: str | bytes, algorithm: str = "sha256") -> bytes:
    """Compute the cryptographic digest for an individual public key entry."""
    algo = algorithm.lower().replace("-", "")
    if algo not in ("sha256", "sha384", "sha512"):
        raise ValueError(f"Unsupported public key digest algorithm: {algorithm}")

    hasher = getattr(hashlib, algo)()
    if isinstance(key_data, str):
        clean_str = key_data.strip().replace(" ", "").replace("\n", "").replace("\r", "")
        # If valid hex string of even length, decode binary bytes; otherwise treat as utf-8
        try:
            if len(clean_str) % 2 == 0:
                raw_bytes = bytes.fromhex(clean_str)
            else:
                raw_bytes = clean_str.encode("utf-8")
        except ValueError:
            raw_bytes = clean_str.encode("utf-8")
    else:
        raw_bytes = bytes(key_data)

    hasher.update(raw_bytes)
    return hasher.digest()


def compute_srk_table_hash(
    public_keys: Sequence[str | bytes],
    hash_algorithm: str = "sha256",
) -> tuple[str, bytes, list[str]]:
    """Compute the hierarchical Super Root Key (SRK/PKC) table hash.

    Follows NXP High Assurance Boot (HAB/AHAB) and NVIDIA Tegra234 PKC standards:
      1. For K public keys (K in 1..4), compute individual digests d_0 .. d_{K-1}.
      2. Concatenate individual digests: T = d_0 || d_1 || ... || d_{K-1}.
      3. Compute composite Root-of-Trust hash: D_SRK = H(T).

    Returns:
        (composite_hash_hex, composite_hash_bytes, individual_digests_hex)
    """
    if not (1 <= len(public_keys) <= 4):
        raise ValueError(f"SRK table must contain between 1 and 4 public keys, got {len(public_keys)}")

    individual_digests = [compute_key_digest(k, hash_algorithm) for k in public_keys]
    concatenated = b"".join(individual_digests)

    algo = hash_algorithm.lower().replace("-", "")
    hasher = getattr(hashlib, algo)()
    hasher.update(concatenated)
    composite_bytes = hasher.digest()

    composite_hex = composite_bytes.hex().upper()
    individual_hex = [d.hex().upper() for d in individual_digests]
    return composite_hex, composite_bytes, individual_hex


def pack_fuse_words(digest_bytes: bytes, endianness: str = "little") -> list[int]:
    """Pack a cryptographic digest into consecutive 32-bit unsigned OTP fuse words.

    For a 256-bit (32-byte) digest, produces 8 words (W0..W7).
    """
    if len(digest_bytes) < 32:
        raise ValueError(f"Digest length must be at least 32 bytes (got {len(digest_bytes)})")

    endian = endianness.lower()
    if endian not in ("little", "big"):
        raise ValueError(f"Endianness must be 'little' or 'big', got: {endianness}")

    fmt_char = "<" if endian == "little" else ">"
    word_count = len(digest_bytes) // 4
    words: list[int] = []

    for i in range(word_count):
        chunk = digest_bytes[i * 4 : (i + 1) * 4]
        word = struct.unpack(f"{fmt_char}I", chunk)[0]
        words.append(word)

    return words


def compute_hamming_weight(data: Sequence[int] | bytes | int) -> int:
    """Calculate the total Hamming weight (popcount / number of blown 1-bits)."""
    if isinstance(data, int):
        return data.bit_count()
    if isinstance(data, (bytes, bytearray)):
        return sum(b.bit_count() for b in data)
    return sum((w & 0xFFFFFFFF).bit_count() for w in data)


def compute_per_word_hamming(words: Sequence[int]) -> list[int]:
    """Calculate Hamming weight for each individual 32-bit word."""
    return [(w & 0xFFFFFFFF).bit_count() for w in words]


def encode_svn_thermometer(version: int) -> tuple[int, int, int]:
    """Encode an anti-rollback Security Version Number (SVN) into unary thermometer mask.

    For version v in [0..64]:
      M_SVN(v) = (1 << v) - 1

    Returns:
      (total_mask_64bit, word0_32bit, word1_32bit)
    """
    if not (0 <= version <= 64):
        raise ValueError(f"Anti-rollback SVN must be between 0 and 64, got {version}")

    if version == 64:
        total_mask = (1 << 64) - 1
    else:
        total_mask = (1 << version) - 1

    word0 = total_mask & 0xFFFFFFFF
    word1 = (total_mask >> 32) & 0xFFFFFFFF
    return total_mask, word0, word1


def verify_svn_transition(current_version: int, target_version: int) -> bool:
    """Verify that an anti-rollback SVN update is monotonic (target >= current)."""
    if not (0 <= current_version <= 64) or not (0 <= target_version <= 64):
        raise ValueError("SVN values must be in range [0..64]")
    return target_version >= current_version
