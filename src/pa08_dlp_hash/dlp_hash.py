"""
PA#8 — DLP-Based Collision-Resistant Hash Function (CRHF)

Compression function: h(x, y) = g^x * ĥ^y mod p
  - g, ĥ are generators of a prime-order-q subgroup of Z_p*
  - x, y are integers derived from the input blocks
  - α = log_g(ĥ) is discarded after key generation — its existence proves hardness

Security: Finding a collision (x1, y1) ≠ (x2, y2) with h(x1,y1) = h(x2,y2)
          implies solving DLP: α = (x1-x2)/(y2-y1) mod q.

Full hash: DLPHash(message) = MD(message) using PA#7 Merkle-Damgård framework
           with this DLP compression function.

Depends on: PA#7 (Merkle-Damgård), src/foundations/dlp_group.py
No external crypto libraries.
"""

from __future__ import annotations
from dataclasses import dataclass
from src.foundations.dlp_group import GroupParams, DEMO_PARAMS, MEDIUM_DEMO_PARAMS
from src.pa07_merkle_damgard.merkle_damgard import MerkleDamgard
from src.common.math_utils import modexp, mod_inverse
from src.common.randomness import random_element_zq
from src.common.bytes_utils import bytes_to_int, int_to_bytes


# ─────────────────────────────────────────────────────────────
#  DLP Hash Group Setup
# ─────────────────────────────────────────────────────────────

@dataclass
class DLPHashParams:
    """Parameters for the DLP-based hash function.

    g:   first generator of order-q subgroup of Z_p*
    h_hat: second generator ĥ = g^α mod p  (α is the trapdoor, discarded)
    p, q: group parameters
    alpha_trapdoor: the discrete log α (kept only for collision demo; in practice discarded)
    """
    g: int
    h_hat: int
    p: int
    q: int
    alpha_trapdoor: int  # TRAPDOOR — in practice this is discarded!


def gen_dlp_hash_params(group: GroupParams | None = None) -> DLPHashParams:
    """Generate DLP hash parameters.

    Picks random α ∈ Z_q, computes ĥ = g^α mod p, then discards α.
    In a real deployment, α would be immediately zeroed. Here we keep it
    only for the collision demonstration.
    """
    if group is None:
        group = DEMO_PARAMS
    alpha = random_element_zq(group.q)
    h_hat = modexp(group.g, alpha, group.p)
    return DLPHashParams(
        g=group.g,
        h_hat=h_hat,
        p=group.p,
        q=group.q,
        alpha_trapdoor=alpha,
    )


# ─────────────────────────────────────────────────────────────
#  DLP Compression Function
# ─────────────────────────────────────────────────────────────

class DLPCompress:
    """DLP-based compression function: h(x, y) = g^x * ĥ^y mod p.

    Accepts chaining_value (bytes) and block (bytes) and returns
    a new chaining value (group element serialized to bytes).

    The chaining value encodes x (as the integer value of the group element mod q).
    The block encodes y (the block interpreted as an integer mod q).
    """

    def __init__(self, params: DLPHashParams):
        self.params = params
        self.p = params.p
        self.q = params.q
        self.g = params.g
        self.h_hat = params.h_hat
        self.elem_bytes = (self.p.bit_length() + 7) // 8

    def compress(self, chaining: bytes, block: bytes) -> bytes:
        """Compute h(chaining, block) = g^x * ĥ^y mod p.

        x = bytes_to_int(chaining) mod q   (chaining value as exponent)
        y = bytes_to_int(block) mod q       (block as exponent)
        """
        x = bytes_to_int(chaining) % self.q
        y = bytes_to_int(block) % self.q
        result = (modexp(self.g, x, self.p) * modexp(self.h_hat, y, self.p)) % self.p
        return int_to_bytes(result, self.elem_bytes)


# ─────────────────────────────────────────────────────────────
#  Full DLP Hash (Merkle-Damgård over DLP compression)
# ─────────────────────────────────────────────────────────────

class DLPHash:
    """Full collision-resistant hash function using DLP compression in Merkle-Damgård.

    Interface: DLPHash(message) -> bytes (group element)
    """

    def __init__(self, params: DLPHashParams | None = None, block_size: int = 64):
        if params is None:
            params = gen_dlp_hash_params()
        self.params = params
        self.block_size = block_size
        self._compress_fn = DLPCompress(params)
        elem_bytes = (params.p.bit_length() + 7) // 8
        # IV = g^1 * ĥ^0 mod p = g mod p
        iv_int = params.g
        iv = int_to_bytes(iv_int, elem_bytes)
        self._md = MerkleDamgard(
            compress=self._compress_fn.compress,
            iv=iv,
            block_size=block_size,
        )

    def hash(self, message: bytes) -> bytes:
        """Hash *message* using DLP-based Merkle-Damgård construction."""
        return self._md.hash(message)

    def __call__(self, message: bytes) -> bytes:
        return self.hash(message)

    def truncate(self, message: bytes, output_bits: int) -> int:
        """Return truncated hash as an integer (for birthday attack experiments)."""
        h = self.hash(message)
        full_int = bytes_to_int(h)
        mask = (1 << output_bits) - 1
        return full_int & mask


# ─────────────────────────────────────────────────────────────
#  Collision → DLP Reduction (Algebraic Demo)
# ─────────────────────────────────────────────────────────────

def collision_to_dlp(
    params: DLPHashParams,
    x1: int, y1: int,   # first pre-image: h(x1,y1) = h(x2,y2)
    x2: int, y2: int,   # second pre-image
) -> dict:
    """Show algebraically that a compression collision gives log_g(ĥ).

    If h(x1, y1) = h(x2, y2):
      g^x1 * ĥ^y1 = g^x2 * ĥ^y2 (mod p)
      g^(x1-x2) = ĥ^(y2-y1) (mod p)
      Since ĥ = g^α:
      g^(x1-x2) = g^(α*(y2-y1)) (mod p)
      α = (x1-x2) * (y2-y1)^{-1} (mod q)

    Returns the recovered α and verifies against trapdoor.
    """
    p, q = params.p, params.q
    compress = DLPCompress(params)
    # Verify collision
    cv = int_to_bytes(0, (p.bit_length() + 7) // 8)
    h1 = (modexp(params.g, x1, p) * modexp(params.h_hat, y1, p)) % p
    h2 = (modexp(params.g, x2, p) * modexp(params.h_hat, y2, p)) % p
    is_collision = h1 == h2 and (x1 != x2 or y1 != y2)

    if not is_collision:
        return {"error": "Not a valid collision — h(x1,y1) ≠ h(x2,y2) or x1=x2, y1=y2"}

    # Recover α
    dy = (y2 - y1) % q
    dx = (x1 - x2) % q
    try:
        dy_inv = mod_inverse(dy, q)
        alpha_recovered = (dx * dy_inv) % q
    except ValueError:
        return {"error": "Cannot compute modular inverse — dy = 0 (trivial collision)"}

    return {
        "collision": {"x1": x1, "y1": y1, "x2": x2, "y2": y2},
        "h_value": h1,
        "alpha_trapdoor": params.alpha_trapdoor,
        "alpha_recovered": alpha_recovered,
        "recovery_correct": alpha_recovered == params.alpha_trapdoor % q,
        "formula": "α = (x1 - x2) * (y2 - y1)^{-1} mod q",
        "conclusion": "Finding a collision in h() gives the discrete log α = log_g(ĥ).",
    }


def demo_find_collision_brute_force(params: DLPHashParams) -> dict:
    """Find a collision in the DLP compression function by brute force.

    Only feasible for tiny group parameters (q ≈ 2^16 → birthday bound ≈ 2^8).
    Demonstrates birthday-bound behavior.
    """
    compress = DLPCompress(params)
    elem_bytes = (params.p.bit_length() + 7) // 8
    cv = int_to_bytes(params.g, elem_bytes)  # initial chaining value

    seen = {}  # hash_value → (x, y)
    evaluations = 0

    # Search over pairs (x, y) ∈ Z_q × Z_q
    for x in range(min(params.q, 500)):
        for y in range(min(params.q, 500)):
            val = (modexp(params.g, x, params.p) * modexp(params.h_hat, y, params.p)) % params.p
            evaluations += 1
            if val in seen:
                x0, y0 = seen[val]
                if (x0 != x or y0 != y):
                    # Collision found!
                    dlp_result = collision_to_dlp(params, x0, y0, x, y)
                    return {
                        "collision_found": True,
                        "evaluations": evaluations,
                        "birthday_bound": int(params.q ** 0.5),
                        "pair_1": (x0, y0),
                        "pair_2": (x, y),
                        "hash_value": val,
                        "dlp_recovery": dlp_result,
                    }
            seen[val] = (x, y)

    return {
        "collision_found": False,
        "evaluations": evaluations,
        "note": "No collision found in search range. Try larger search or smaller q.",
    }
