"""
PA#5 — Message Authentication Codes (MACs)

Implements:
  - Mac_PRF / Vrfy_PRF:  PRF-based MAC for fixed-length messages
  - Mac_CBC / Vrfy_CBC:  CBC-MAC for variable-length messages
  - hmac_stub:           Raises NotImplemented until PA#10

Bidirectional reductions:
  - Forward:  PRF → MAC (Mac_PRF is a secure MAC if F is a PRF)
  - Backward: MAC → PRF (use Mac_PRF as a PRF — demo via distinguishing test)

Depends on: PA#2 (PRFFromAES), PA#3 (for comparison)
No external crypto libraries.
"""

from __future__ import annotations
from src.pa02_prf.ggm_prf import PRFFromAES
from src.foundations.aes_impl import aes_encrypt_block
from src.common.randomness import random_bytes
from src.common.bytes_utils import xor_bytes
from src.common.padding import iso7816_pad
from src.common.timing import secure_compare

BLOCK_SIZE = 16  # AES block size


# ─────────────────────────────────────────────────────────────
#  PRF-based MAC (fixed-length messages)
# ─────────────────────────────────────────────────────────────

class MacPRF:
    """PRF-based MAC: Mac(k, m) = F_k(m).

    Secure for fixed-length messages (|m| = one block = 16 bytes).
    For variable-length, use MacCBC.

    Interface:
        Mac(k, m) -> tag
        Vrfy(k, m, t) -> bool
    """

    def __init__(self, prf: PRFFromAES | None = None):
        self.prf = prf or PRFFromAES()

    def Mac(self, k: bytes, m: bytes) -> bytes:
        """Compute MAC tag: t = F_k(m).

        m must be exactly 16 bytes for the fixed-length variant.
        For longer messages, use Mac_variable.
        """
        if len(k) != BLOCK_SIZE:
            raise ValueError("MacPRF.Mac: key must be 16 bytes")
        if len(m) != BLOCK_SIZE:
            raise ValueError(
                "MacPRF.Mac: message must be 16 bytes. Use Mac_variable for longer messages."
            )
        return self.prf.F(k, m)

    def Vrfy(self, k: bytes, m: bytes, t: bytes) -> bool:
        """Verify MAC tag using constant-time comparison."""
        expected = self.Mac(k, m)
        return secure_compare(expected, t)

    def Mac_variable(self, k: bytes, m: bytes) -> bytes:
        """Extend to variable-length using chain of PRF applications.

        This is CBC-MAC style applied with the PRF directly.
        For proper CBC-MAC, use MacCBC below.
        """
        padded = iso7816_pad(m, BLOCK_SIZE)
        state = b"\x00" * BLOCK_SIZE
        for i in range(0, len(padded), BLOCK_SIZE):
            block = padded[i : i + BLOCK_SIZE]
            state = self.prf.F(k, xor_bytes(state, block))
        return state


# ─────────────────────────────────────────────────────────────
#  CBC-MAC (variable-length messages)
# ─────────────────────────────────────────────────────────────

class MacCBC:
    """CBC-MAC for variable-length messages.

    Mac_CBC(k, M):
        Pad M with ISO/IEC 7816-4 padding to multiple of block_size.
        CBC-encrypt with IV=0: C_i = AES_k(M_i ⊕ C_{i-1}), C_0 = 0.
        Tag = C_last.

    Note: naive CBC-MAC is only secure for fixed-length messages.
    For variable-length, an additional final encryption step (EMAC/CMAC) is needed.
    We implement the standard variant with length-prepending for variable-length security.
    """

    def Mac(self, k: bytes, M: bytes) -> bytes:
        """Compute CBC-MAC tag.

        Uses length-prepending: prepend 8-byte big-endian length to the message.
        This makes it secure for variable-length messages.
        """
        if len(k) != BLOCK_SIZE:
            raise ValueError("MacCBC.Mac: key must be 16 bytes")
        # Prepend 8-byte big-endian message length
        import struct
        M_len_prefixed = struct.pack(">Q", len(M)) + M
        padded = iso7816_pad(M_len_prefixed, BLOCK_SIZE)
        state = b"\x00" * BLOCK_SIZE
        for i in range(0, len(padded), BLOCK_SIZE):
            block = padded[i : i + BLOCK_SIZE]
            state = aes_encrypt_block(k, xor_bytes(state, block))
        return state

    def Vrfy(self, k: bytes, M: bytes, t: bytes) -> bool:
        """Verify CBC-MAC tag."""
        expected = self.Mac(k, M)
        return secure_compare(expected, t)


# ─────────────────────────────────────────────────────────────
#  HMAC Stub (PA#10 will implement)
# ─────────────────────────────────────────────────────────────

def hmac_stub(k: bytes, m: bytes) -> bytes:
    """HMAC stub — not yet implemented.

    Will be replaced by PA#10 implementation using the PA#8 DLP hash.
    Raises NotImplementedError to make dependency explicit.
    """
    raise NotImplementedError(
        "HMAC is not yet implemented. See PA#10 (pa10_hmac_eth/hmac_eth.py). "
        "This stub exists to make the dependency explicit."
    )


# ─────────────────────────────────────────────────────────────
#  EUF-CMA Game Simulation
# ─────────────────────────────────────────────────────────────

def euf_cma_game(
    mac: MacPRF | MacCBC | None = None,
    k: bytes | None = None,
    num_queries: int = 50,
) -> dict:
    """Simulate EUF-CMA (Existential Unforgeability under Chosen Message Attack) game.

    Adversary gets access to a signing oracle for num_queries messages.
    Then tries to forge a valid tag on a *new* message never queried.
    A secure MAC should always reject the forgery.

    Returns game transcript and forgery attempt result.
    """
    if mac is None:
        mac = MacPRF()
    if k is None:
        k = random_bytes(BLOCK_SIZE)

    # Oracle: collect (message, tag) pairs
    queried = {}
    for _ in range(num_queries):
        m = random_bytes(BLOCK_SIZE)
        t = mac.Mac(k, m) if isinstance(mac, MacPRF) else mac.Mac(k, m)
        queried[m] = t

    # Adversary attempts to forge on a fresh message
    fresh = random_bytes(BLOCK_SIZE)
    while fresh in queried:
        fresh = random_bytes(BLOCK_SIZE)

    # Simple forgery attempt: use a known tag from a different message
    if queried:
        stolen_tag = next(iter(queried.values()))
    else:
        stolen_tag = random_bytes(BLOCK_SIZE)

    forgery_accepted = mac.Vrfy(k, fresh, stolen_tag) if isinstance(mac, MacPRF) else mac.Vrfy(k, fresh, stolen_tag)

    return {
        "num_oracle_queries": num_queries,
        "fresh_message": fresh.hex(),
        "forgery_tag": stolen_tag.hex(),
        "forgery_accepted": forgery_accepted,
        "security_holds": not forgery_accepted,
        "note": "A secure MAC always rejects forgeries on fresh messages.",
    }


# ─────────────────────────────────────────────────────────────
#  Length-Extension Attack Demo on Naive H(k ∥ m) MAC
# ─────────────────────────────────────────────────────────────

def naive_mac(k: bytes, m: bytes) -> bytes:
    """INSECURE naive MAC: H(k ∥ m) using a toy hash (XOR-fold for demo).

    This is vulnerable to length-extension attacks because the internal
    state after processing k ∥ m can be used to continue hashing.
    """
    # Toy hash: XOR all 16-byte blocks (demonstrative only)
    combined = k + m
    # Pad to multiple of 16
    padded = iso7816_pad(combined, BLOCK_SIZE)
    state = b"\x00" * BLOCK_SIZE
    for i in range(0, len(padded), BLOCK_SIZE):
        block = padded[i : i + BLOCK_SIZE]
        state = xor_bytes(state, block)
    return state


def length_extension_attack_demo(k: bytes, m: bytes) -> dict:
    """Demonstrate length-extension attack on naive H(k ∥ m) MAC.

    Given H(k ∥ m) and knowledge of |k|, an attacker can compute
    H(k ∥ m ∥ padding ∥ extension) without knowing k.

    This attack does NOT work on HMAC (PA#10).
    """
    tag = naive_mac(k, m)

    # Attacker knows: tag = H(k ∥ m), |k|, m
    # Attacker extends: m' = m ∥ padding ∥ extension
    extension = b"FORGED_EXTENSION"

    # Simulate: attacker rebuilds internal state from tag and continues
    # Since our toy hash is XOR-fold, attacker can compute H(k ∥ m ∥ ext)
    # by XOR-ing their extension with the known tag
    padded_ext = iso7816_pad(extension, BLOCK_SIZE)
    state = tag
    for i in range(0, len(padded_ext), BLOCK_SIZE):
        block = padded_ext[i : i + BLOCK_SIZE]
        state = xor_bytes(state, block)
    forged_tag = state

    # Build the actual extended message to verify
    # m' = m ∥ iso7816_pad(k+m) tail ∥ extension  (simplified)
    m_prime = m + iso7816_pad(b"", BLOCK_SIZE) + extension
    actual_tag = naive_mac(k, m_prime)

    # The attack succeeds if forged_tag == actual_tag
    # (This depends on hash structure; XOR-fold makes it exact)
    return {
        "attack": "Length Extension",
        "original_message": m.hex(),
        "extension": extension.hex(),
        "original_tag": tag.hex(),
        "forged_tag_without_key": forged_tag.hex(),
        "actual_extended_tag": actual_tag.hex(),
        "attack_note": (
            "For naive H(k ∥ m), attacker can extend without knowing k. "
            "HMAC uses nested construction H(k ⊕ opad ∥ H(k ⊕ ipad ∥ m)) "
            "which is immune to length extension."
        ),
    }
