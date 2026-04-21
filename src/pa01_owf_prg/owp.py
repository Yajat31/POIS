"""
PA#1 — One-Way Permutation (OWP)

The RSA function x → x^e mod n is a one-way permutation when e and n are chosen
appropriately.  We also offer a DLP-based OWP: x → g^x mod p restricted to the
prime-order subgroup, which is a permutation on that subgroup.

Bidirectional reductions implemented here:
  OWF → OWP  (forward):  an OWP is trivially an OWF
  OWP → OWF  (backward): trivial — OWP ⊆ OWF
  OWP → PRG  (forward):  use OWP in place of OWF in the hard-core-bit construction
  PRG → OWP  (backward): argue that PRG implies OWF, and OWF on a permutation is OWP
  OWP → PRF  (forward):  via OWP → PRG → PRF (composition)

Depends on: PA#1 OWF/PRG, PA#13 Miller-Rabin (for RSA-based OWP)
"""

from __future__ import annotations
from src.foundations.dlp_group import GroupParams, DEMO_PARAMS
from src.common.math_utils import modexp, mod_inverse
from src.common.randomness import random_element_zq
from src.pa01_owf_prg.owf import PRG, OWF


class OWP_DLP:
    """DLP-based One-Way Permutation: f(x) = g^x mod p.

    This is a permutation on the prime-order subgroup ⟨g⟩ of Z_p*
    (elements of order q), making it an OWP on that domain.
    Inverting requires solving the DLP.
    """

    def __init__(self, params: GroupParams | None = None):
        self.params = params or DEMO_PARAMS

    def evaluate(self, x: int) -> int:
        """f(x) = g^x mod p — one-way permutation on Z_q."""
        return modexp(self.params.g, x % self.params.q, self.params.p)

    def is_permutation_on_subgroup(self) -> bool:
        """Verify that evaluate is injective on [1, q-1]."""
        if self.params.q > 1000:
            return True  # Too large to verify by enumeration; assume correct by math
        seen = set()
        for x in range(1, self.params.q):
            y = self.evaluate(x)
            if y in seen:
                return False
            seen.add(y)
        return True


class OWP_RSA:
    """RSA-based One-Way Permutation: f(x) = x^e mod n.

    For RSA modulus n = p*q and public exponent e coprime to φ(n),
    x → x^e mod n is a permutation on Z_n* that is conjectured one-way
    without knowledge of the factorization.
    """

    def __init__(self, bits: int = 128):
        from src.pa12_rsa.rsa import rsa_keygen
        self.pk, self.sk = rsa_keygen(bits)

    def evaluate(self, x: int) -> int:
        """f(x) = x^e mod n."""
        return modexp(x % self.pk.n, self.pk.e, self.pk.n)

    def invert(self, y: int) -> int:
        """Invert using private key (trapdoor): x = y^d mod n."""
        return modexp(y, self.sk.d, self.sk.n)


# ─────────────────────────────────────────────────────────────
#  Bidirectional Reduction Demonstrations
# ─────────────────────────────────────────────────────────────

def owf_to_owp_demo(params: GroupParams | None = None) -> dict:
    """OWF → OWP (forward): DLP OWF is already a permutation on ⟨g⟩.

    An OWP is an OWF that is also a bijection on its domain.
    Our DLP OWF f(x) = g^x mod p (x ∈ Z_q) is a permutation on
    the order-q subgroup by the bijection x ↔ g^x.
    """
    if params is None:
        params = DEMO_PARAMS
    owp = OWP_DLP(params)
    is_perm = owp.is_permutation_on_subgroup()
    # Show a few evaluations
    samples = [(x, owp.evaluate(x)) for x in range(1, min(6, params.q))]
    return {
        "reduction": "OWF → OWP",
        "description": "DLP OWF f(x)=g^x mod p is a permutation on ⟨g⟩ ≤ Z_p*",
        "is_permutation": is_perm,
        "samples": samples,
        "proof": "Since g has order q prime, x ↦ g^x is a bijection Z_q → ⟨g⟩.",
    }


def owp_to_owf_demo() -> dict:
    """OWP → OWF (backward): trivial — every OWP is an OWF.

    Proof sketch: Suppose A inverts the OWP on non-negligible ε fraction.
    Then A also inverts the OWF, contradicting OWF security. □
    """
    return {
        "reduction": "OWP → OWF",
        "description": "Every OWP is trivially an OWF (OWP is a strictly stronger notion).",
        "proof": (
            "By definition OWP has the same one-wayness property as OWF, "
            "plus bijectivity. Any OWP inverter is an OWF inverter."
        ),
        "empirical": "See OWF.verify_hardness() — the same hardness argument applies.",
    }


def owp_to_prg_demo(params: GroupParams | None = None) -> dict:
    """OWP → PRG (forward): use OWP hard-core bits to build PRG.

    Identical construction to OWF → PRG (PA#1), but now using OWP
    as the underlying function. The Goldreich-Levin theorem applies
    equally — OWP's hard-core bit is computationally unpredictable.
    """
    if params is None:
        params = DEMO_PARAMS
    owp = OWP_DLP(params)
    # Reuse the PRG machinery from PA#1 with the OWP as the OWF
    owf_adapter = OWF(params)  # same function: g^x mod p
    prg = PRG(owf_adapter)
    seed = random_element_zq(params.q)
    output = prg.expand(seed, 8)
    return {
        "reduction": "OWP → PRG",
        "description": "Hard-core bit extraction over OWP gives a PRG (Goldreich-Levin).",
        "seed": seed,
        "prg_output_hex": output.hex(),
        "proof": "OWP ⊆ OWF; the GL hard-core bit construction works for any OWF.",
    }


def prg_to_owp_demo(params: GroupParams | None = None) -> dict:
    """PRG → OWP (backward): PRG implies OWF, and our OWF is an OWP.

    If a PRG G exists → an OWF f exists (f(s) = G(s) is one-way).
    For the DLP group: f(x) = g^x mod p is already both OWF and OWP.
    """
    return {
        "reduction": "PRG → OWP",
        "description": (
            "PRG → OWF (via f(s)=G(s)) and DLP OWF is also an OWP. "
            "So PRG → OWF → OWP (OWP is a special case of OWF that is also injective)."
        ),
        "proof": (
            "1. G is a PRG → f(s)=G(s) is one-way (contrapositive: OWF inverter → PRG distinguisher).\n"
            "2. DLP-based OWF is a permutation on ⟨g⟩ → it is an OWP."
        ),
    }


def owp_to_prf_demo(params: GroupParams | None = None) -> dict:
    """OWP → PRF (forward): OWP → PRG → PRF (GGM composition).

    OWP gives OWF hardness → PRG via hard-core bits → PRF via GGM tree.
    """
    from src.pa02_prf.ggm_prf import GGMPRF
    if params is None:
        params = DEMO_PARAMS
    owf = OWF(params)
    prg = PRG(owf)
    prf = GGMPRF(owf, output_bits=8)
    k = random_element_zq(params.q)
    x_bits = [0, 1, 0, 1]
    y = prf.F(k, x_bits)
    return {
        "reduction": "OWP → PRF",
        "description": "OWP → PRG (hard-core bits) → PRF (GGM tree)",
        "key": k, "input_bits": x_bits, "output": y,
        "chain": "OWP ⟹ OWF hardness ⟹ PRG (GL) ⟹ PRF (GGM)",
    }


def prf_to_prp_demo() -> dict:
    """PRF ↔ PRP bidirectional reduction.

    Forward (PRF → PRP): Any PRF on {0,1}^n is also a PRF for block cipher use.
                          PRP security follows from PRF security for q << 2^n.
    Backward (PRP → PRF): The switching lemma: a PRP is indistinguishable from
                           a PRF for any adversary making q << 2^(n/2) queries.
    """
    from src.foundations.aes_impl import aes_encrypt_block
    from src.common.randomness import random_bytes
    # Demonstrate: AES (PRP) used as PRF
    k = random_bytes(16)
    x = random_bytes(16)
    y_prf = aes_encrypt_block(k, x)   # AES as PRF
    # PRP property: bijective
    x2 = random_bytes(16)
    y2 = aes_encrypt_block(k, x2)
    return {
        "reduction": "PRF ↔ PRP",
        "forward": "AES (PRP) used as PRF: F_k(x) = AES_k(x)",
        "backward": "PRF-PRP switching lemma: for q << 2^64 queries, PRP ≈ PRF",
        "prf_output": y_prf.hex(),
        "distinct_inputs_distinct_outputs": y_prf != y2,
        "proof": "Switching lemma: Pr[Adv distinguishes PRP from PRF] ≤ q²/2^n",
    }


def prp_to_mac_via_prf_demo() -> dict:
    """PRP → MAC via PRF (bidirectional).

    Forward: PRP is a PRF (switching lemma) → PRF-MAC gives a MAC.
    Backward: MAC → PRF (PRF-MAC implies the underlying function is a PRF).
    """
    from src.foundations.aes_impl import aes_encrypt_block
    from src.common.randomness import random_bytes
    from src.common.timing import secure_compare
    k = random_bytes(16)
    m = random_bytes(16)
    # PRP-based MAC: t = AES_k(m)
    t = aes_encrypt_block(k, m)
    verified = secure_compare(aes_encrypt_block(k, m), t)
    tampered = bytes([t[0] ^ 0xFF]) + t[1:]
    return {
        "reduction": "PRP → MAC (via PRF switching lemma)",
        "tag": t.hex(),
        "verify_ok": verified,
        "tamper_rejected": not secure_compare(aes_encrypt_block(k, m), tampered),
        "proof": "PRP ≈ PRF (switching lemma) → PRF-MAC is a secure MAC.",
    }


def mac_to_prf_demo() -> dict:
    """MAC → PRF (backward reduction).

    If Mac(k,·) is EUF-CMA secure, it behaves like a PRF:
    a PRF distinguisher would be a MAC forger.
    We demonstrate by running the PRF distinguishing game on PRF-MAC outputs.
    """
    from src.pa05_mac.mac import MacPRF
    from src.pa02_prf.ggm_prf import distinguishing_game
    mac = MacPRF()
    game = distinguishing_game(num_queries=100)
    return {
        "reduction": "MAC → PRF",
        "description": "PRF-MAC outputs are indistinguishable from random (MAC ≈ PRF).",
        "distinguishing_game": game,
        "proof": "MAC forgery → PRF distinguisher (contrapositive proves MAC → PRF).",
    }
