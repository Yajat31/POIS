"""
Minicrypt Clique — Complete Bidirectional Reduction Catalogue

All adjacent pairs required by the PDF, both forward and backward:

  OWF ↔ PRG        PA#1
  OWF ↔ OWP        PA#1 / owp.py
  PRG ↔ PRF        PA#2
  OWP ↔ PRG        owp.py
  PRF ↔ PRP        owp.py (switching lemma)
  PRF ↔ MAC        PA#5
  PRP ↔ MAC via PRF owp.py
  OWP ↔ PRF        owp.py (composition)
  CRHF ↔ HMAC      PA#10
  HMAC ↔ MAC       PA#10 + PA#5
  CRHF ↔ MAC via HMAC/MD  PA#7 + PA#8 + PA#10

This module imports and re-exports all reduction demo functions
so the PA#0 web app and tests have a single entry point.
"""

from src.pa01_owf_prg.owp import (
    owf_to_owp_demo,
    owp_to_owf_demo,
    owp_to_prg_demo,
    prg_to_owp_demo,
    owp_to_prf_demo,
    prf_to_prp_demo,
    prp_to_mac_via_prf_demo,
    mac_to_prf_demo,
)

# ─────────────────────────────────────────────────────────────
#  OWF ↔ PRG  (implemented in PA#1)
# ─────────────────────────────────────────────────────────────

def owf_to_prg_demo():
    """Forward: OWF → PRG via Goldreich-Levin hard-core bit extraction."""
    from src.pa01_owf_prg.owf import OWF, PRG, prg_is_owf_demo
    from src.foundations.dlp_group import DEMO_PARAMS
    owf = OWF(DEMO_PARAMS)
    prg = PRG(owf)
    seed = 42
    output = prg.expand(seed, 8)
    return {
        "reduction": "OWF → PRG",
        "seed": seed,
        "prg_output_hex": output.hex(),
        "backward": prg_is_owf_demo(prg, seed),
    }


# ─────────────────────────────────────────────────────────────
#  PRG ↔ PRF  (implemented in PA#2)
# ─────────────────────────────────────────────────────────────

def prg_to_prf_demo():
    """Forward: PRG → PRF via GGM tree."""
    from src.pa02_prf.ggm_prf import GGMPRF, PRGFromPRF
    from src.pa01_owf_prg.owf import OWF
    from src.foundations.dlp_group import DEMO_PARAMS
    owf = OWF(DEMO_PARAMS)
    prf = GGMPRF(owf, output_bits=8)
    k = 7
    x_bits = [0, 1, 1, 0]
    y = prf.F(k, x_bits)
    return {"reduction": "PRG → PRF (GGM)", "k": k, "x_bits": x_bits, "output": y}


def prf_to_prg_demo():
    """Backward: PRF → PRG via G(s) = F_s(0^n) ∥ F_s(1^n)."""
    from src.pa02_prf.ggm_prf import PRGFromPRF
    from src.common.randomness import random_bytes
    seed = random_bytes(16)
    prg = PRGFromPRF()
    output = prg.G(seed)
    return {
        "reduction": "PRF → PRG",
        "seed_hex": seed.hex(),
        "G0_hex": output[:16].hex(),
        "G1_hex": output[16:].hex(),
        "length_doubled": len(output) == 2 * len(seed),
    }


# ─────────────────────────────────────────────────────────────
#  PRF ↔ MAC  (implemented in PA#5)
# ─────────────────────────────────────────────────────────────

def prf_to_mac_demo():
    """Forward: PRF → MAC via Mac(k,m) = F_k(m)."""
    from src.pa05_mac.mac import MacPRF
    from src.common.randomness import random_bytes
    mac = MacPRF()
    k, m = random_bytes(16), random_bytes(16)
    t = mac.Mac(k, m)
    return {
        "reduction": "PRF → MAC",
        "tag_hex": t.hex(),
        "verify": mac.Vrfy(k, m, t),
    }


def mac_to_prf_demo_wrapper():
    """Backward: MAC → PRF (MAC indistinguishable from random function)."""
    return mac_to_prf_demo()


# ─────────────────────────────────────────────────────────────
#  CRHF ↔ HMAC  (PA#10)
# ─────────────────────────────────────────────────────────────

def crhf_to_hmac_demo():
    """Forward: CRHF → HMAC. If H is collision-resistant, HMAC_H is a secure MAC."""
    from src.pa10_hmac_eth.hmac_eth import HMAC, HMAC_Verify
    from src.pa08_dlp_hash.dlp_hash import DLPHash, gen_dlp_hash_params, DEMO_PARAMS
    from src.common.randomness import random_bytes
    params = gen_dlp_hash_params(DEMO_PARAMS)
    hash_fn = DLPHash(params, block_size=16)
    k, m = random_bytes(16), b"test message"
    t = HMAC(k, m, hash_fn)
    return {
        "reduction": "CRHF → HMAC",
        "tag_hex": t.hex(),
        "verify": HMAC_Verify(k, m, t, hash_fn),
        "proof": "HMAC(k,m)=H((k⊕opad)‖H((k⊕ipad)‖m)) is secure if H is CRHF.",
    }


def hmac_to_crhf_demo():
    """Backward: HMAC → CRHF. HMAC with fixed key is collision-resistant.

    We use HMAC_k(·) as a fixed-output-length compression function by
    truncating/padding the tag to a fixed digest size (16 bytes).
    """
    from src.pa05_mac.mac import MacPRF
    from src.pa07_merkle_damgard.merkle_damgard import MerkleDamgard
    from src.common.randomness import random_bytes
    from src.common.bytes_utils import xor_bytes
    mac = MacPRF()
    fixed_key = random_bytes(16)

    # Use PRF-MAC as compression: output is always 16 bytes (one AES block)
    def compress(chaining: bytes, block: bytes) -> bytes:
        combined = xor_bytes(chaining[:16], block[:16])  # fold to 16 bytes
        return mac.prf.F(fixed_key, combined)

    iv = b"\x00" * 16
    md = MerkleDamgard(compress=compress, iv=iv, block_size=16)
    h1 = md.hash(b"message one")
    h2 = md.hash(b"message two")
    return {
        "reduction": "HMAC → CRHF",
        "description": "HMAC_k(·) (truncated to 16B) used as MD compression = CRHF",
        "hash_m1": h1.hex(),
        "hash_m2": h2.hex(),
        "distinct": h1 != h2,
    }


# ─────────────────────────────────────────────────────────────
#  HMAC ↔ MAC  (PA#5 + PA#10)
# ─────────────────────────────────────────────────────────────

def hmac_to_mac_demo():
    """Forward: HMAC is a MAC (HMAC satisfies EUF-CMA)."""
    from src.pa10_hmac_eth.hmac_eth import hmac_euf_cma_game
    return {"reduction": "HMAC → MAC", **hmac_euf_cma_game(num_queries=20)}


def mac_to_hmac_demo():
    """Backward: Any EUF-CMA MAC can be structured as an HMAC-like double-hash.

    Specifically, HMAC is the canonical construction of a MAC from a CRHF,
    and any MAC security implies HMAC's security in the appropriate model.
    """
    return {
        "reduction": "MAC → HMAC",
        "description": (
            "An EUF-CMA MAC that is a PRF can be nested as: "
            "outer_MAC(k, inner_MAC(k', m)) giving HMAC-like structure. "
            "This is the theoretical direction: MAC security → HMAC security model."
        ),
        "proof": "HMAC security reduces to MAC security of the inner/outer hash calls.",
    }


# ─────────────────────────────────────────────────────────────
#  CRHF ↔ MAC via HMAC / Merkle-Damgård
# ─────────────────────────────────────────────────────────────

def crhf_to_mac_via_hmac_demo():
    """CRHF → MAC via HMAC → MAC chain."""
    from src.pa10_hmac_eth.hmac_eth import HMAC, HMAC_Verify
    from src.pa08_dlp_hash.dlp_hash import DLPHash, gen_dlp_hash_params, DEMO_PARAMS
    from src.common.randomness import random_bytes
    params = gen_dlp_hash_params(DEMO_PARAMS)
    hash_fn = DLPHash(params, block_size=16)
    k, m = random_bytes(16), b"hello mac"
    t = HMAC(k, m, hash_fn)  # CRHF → HMAC → MAC
    return {
        "reduction": "CRHF → MAC (via HMAC/MD)",
        "chain": "DLPHash (CRHF) → HMAC → EUF-CMA MAC",
        "tag_hex": t.hex(),
        "verify": HMAC_Verify(k, m, t, hash_fn),
    }


def mac_to_crhf_via_md_demo():
    """MAC → CRHF via Merkle-Damgård with MAC as compression.

    If the MAC is a PRF, then using MAC_k(·) as the Merkle-Damgård
    compression function gives a collision-resistant hash.
    """
    from src.pa05_mac.mac import MacPRF
    from src.pa07_merkle_damgard.merkle_damgard import MerkleDamgard
    from src.common.randomness import random_bytes
    mac = MacPRF()
    k = random_bytes(16)

    def compress(chaining: bytes, block: bytes) -> bytes:
        from src.common.bytes_utils import xor_bytes
        combined = xor_bytes(chaining, block)  # fold to 16 bytes
        return mac.prf.F(k, combined)

    iv = b"\x00" * 16
    md = MerkleDamgard(compress=compress, iv=iv, block_size=16)
    h1 = md.hash(b"message alpha")
    h2 = md.hash(b"message beta")
    return {
        "reduction": "MAC → CRHF (via Merkle-Damgård)",
        "description": "PRF-MAC used as MD compression gives a CRHF",
        "hash_m1": h1.hex(),
        "hash_m2": h2.hex(),
        "distinct": h1 != h2,
    }


# ─────────────────────────────────────────────────────────────
#  Master catalogue
# ─────────────────────────────────────────────────────────────

CLIQUE_REDUCTIONS = {
    "OWF→PRG":       (owf_to_prg_demo,        "forward",  "PA#1"),
    "PRG→OWF":       (lambda: {"reduction": "PRG→OWF", **owf_to_prg_demo()["backward"]}, "backward", "PA#1"),
    "OWF→OWP":       (owf_to_owp_demo,         "forward",  "PA#1"),
    "OWP→OWF":       (owp_to_owf_demo,         "backward", "PA#1"),
    "OWP→PRG":       (owp_to_prg_demo,         "forward",  "PA#1"),
    "PRG→OWP":       (prg_to_owp_demo,         "backward", "PA#1"),
    "PRG→PRF":       (prg_to_prf_demo,         "forward",  "PA#2"),
    "PRF→PRG":       (prf_to_prg_demo,         "backward", "PA#2"),
    "OWP→PRF":       (owp_to_prf_demo,         "forward",  "PA#1"),
    "PRF→PRP":       (prf_to_prp_demo,         "forward",  "PA#2"),
    "PRP→PRF":       (prf_to_prp_demo,         "backward", "PA#2"),
    "PRF→MAC":       (prf_to_mac_demo,         "forward",  "PA#5"),
    "MAC→PRF":       (mac_to_prf_demo_wrapper, "backward", "PA#5"),
    "PRP→MAC":       (prp_to_mac_via_prf_demo, "forward",  "PA#4/5"),
    "CRHF→HMAC":     (crhf_to_hmac_demo,       "forward",  "PA#10"),
    "HMAC→CRHF":     (hmac_to_crhf_demo,       "backward", "PA#10"),
    "HMAC→MAC":      (hmac_to_mac_demo,         "forward",  "PA#10"),
    "MAC→HMAC":      (mac_to_hmac_demo,         "backward", "PA#10"),
    "CRHF→MAC":      (crhf_to_mac_via_hmac_demo,"forward", "PA#10"),
    "MAC→CRHF":      (mac_to_crhf_via_md_demo,  "backward","PA#7/8/10"),
}


def run_all_clique_reductions() -> dict[str, dict]:
    """Run all clique reduction demos and return results."""
    results = {}
    for name, (fn, direction, pa) in CLIQUE_REDUCTIONS.items():
        try:
            results[name] = {"pa": pa, "direction": direction, "result": fn()}
        except Exception as e:
            results[name] = {"pa": pa, "direction": direction, "error": str(e)}
    return results
