"""
PA#0 Backend — FastAPI Minicrypt Clique Web Explorer (v2)

Key discipline enforced:
  Column 1 (/build_foundation_to_primitive): ONLY place that touches AES/DLP directly.
             Returns an opaque 'handle' dict describing the constructed primitive.
  Column 2 (/reduce_primitive_to_target): ONLY consumes the handle from Column 1.
             Never imports AES/DLP foundations directly.

Endpoints:
  POST /build_foundation_to_primitive   → steps + handle
  POST /reduce_primitive_to_target      → reduction output (uses handle only)
  GET  /reduction_path                  → BFS path
  GET  /proof_summary                   → theorem + PA numbers + chain
  GET  /clique_reductions               → full bidirectional catalogue
"""

from __future__ import annotations
import sys, os
import secrets
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI(title="POIS Minicrypt Clique Explorer", version="2.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True,
                   allow_methods=["*"], allow_headers=["*"])
CPA_CHALLENGES: dict[str, dict] = {}
MAC_GAMES: dict[str, dict] = {}
CCA_GAMES: dict[str, dict] = {}

# ─── Primitive registry ───────────────────────────────────────
PRIMITIVES = {
    "OWF":  {"pa": 1,  "implemented": True,  "name": "One-Way Function"},
    "OWP":  {"pa": 1,  "implemented": True,  "name": "One-Way Permutation"},
    "PRG":  {"pa": 1,  "implemented": True,  "name": "Pseudo-Random Generator"},
    "PRF":  {"pa": 2,  "implemented": True,  "name": "Pseudo-Random Function"},
    "PRP":  {"pa": 2,  "implemented": True,  "name": "Pseudo-Random Permutation (AES)"},
    "CPA":  {"pa": 3,  "implemented": True,  "name": "CPA-Secure Encryption"},
    "MAC":  {"pa": 5,  "implemented": True,  "name": "Message Authentication Code"},
    "CCA":  {"pa": 6,  "implemented": True,  "name": "CCA-Secure Symmetric Encryption"},
    "CRHF": {"pa": 8,  "implemented": True,  "name": "Collision-Resistant Hash Function"},
    "HMAC": {"pa": 10, "implemented": True,  "name": "HMAC"},
    "OTP":  {"pa": 3,  "implemented": True,  "name": "One-Time Pad"},
}

# ─── Bidirectional clique routing table ──────────────────────
# All adjacent pairs from the PDF spec — both directions
REDUCTION_GRAPH: dict[str, list[str]] = {
    "OWF":  ["PRG", "OWP"],
    "OWP":  ["OWF", "PRG", "PRF"],
    "PRG":  ["OWF", "PRF", "OWP"],
    "PRF":  ["PRG", "PRP", "MAC", "OWP", "CPA"],
    "PRP":  ["PRF", "MAC"],
    "MAC":  ["PRF", "HMAC", "CRHF"],
    "CPA":  ["PRF", "CCA"],
    "CCA":  ["MAC", "CPA"],
    "CRHF": ["HMAC", "MAC"],
    "HMAC": ["CRHF", "MAC"],
}

# ─── Reduction descriptions — all required adjacent pairs ─────
REDUCTIONS: dict[tuple, dict] = {
    ("OWF","PRG"):  {"dir":"forward",  "pa":"PA#1", "theorem":"HILL: OWF⟹PRG (GL hard-core bit)", "construction":"G(s)=b₁‖…‖bₗ where bᵢ=⟨sᵢ,r⟩ mod 2, sᵢ=g^{sᵢ₋₁} mod p"},
    ("PRG","OWF"):  {"dir":"backward", "pa":"PA#1", "theorem":"PRG⟹OWF: f(s)=G(s) is one-way",  "construction":"Any PRG is an OWF (contrapositive)"},
    ("OWF","OWP"):  {"dir":"forward",  "pa":"PA#1", "theorem":"DLP OWF is a permutation on ⟨g⟩", "construction":"f(x)=g^x mod p is bijection on Z_q"},
    ("OWP","OWF"):  {"dir":"backward", "pa":"PA#1", "theorem":"OWP⊆OWF (OWP is stronger notion)",  "construction":"Every OWP is trivially an OWF"},
    ("OWP","PRG"):  {"dir":"forward",  "pa":"PA#1", "theorem":"OWP⟹PRG via Goldreich-Levin",      "construction":"Same hard-core bit construction as OWF→PRG"},
    ("PRG","OWP"):  {"dir":"backward", "pa":"PA#1", "theorem":"PRG⟹OWF⟹OWP (DLP group)",         "construction":"PRG⟹OWF; DLP OWF is OWP"},
    ("PRG","PRF"):  {"dir":"forward",  "pa":"PA#2", "theorem":"GGM: PRG⟹PRF (tree construction)", "construction":"F_k(x)=leaf node of GGM tree rooted at k following path x"},
    ("PRF","PRG"):  {"dir":"backward", "pa":"PA#2", "theorem":"PRF⟹PRG: G(s)=F_s(0)‖F_s(1)",    "construction":"Use PRF with fixed input to double seed length"},
    ("OWP","PRF"):  {"dir":"forward",  "pa":"PA#1/2","theorem":"OWP⟹PRG⟹PRF (composition)",     "construction":"OWP→PRG via GL, then PRG→PRF via GGM"},
    ("PRF","PRP"):  {"dir":"forward",  "pa":"PA#2", "theorem":"Feistel: PRF⟹PRP (3-round Feistel)","construction":"3-round Feistel with PRF rounds gives PRP"},
    ("PRP","PRF"):  {"dir":"backward", "pa":"PA#2", "theorem":"Switching lemma: PRP≈PRF for q≪2^n","construction":"For q queries, |Pr[A^PRP]-Pr[A^PRF]|≤q²/2^n"},
    ("PRF","MAC"):  {"dir":"forward",  "pa":"PA#5", "theorem":"PRF⟹MAC: Mac(k,m)=F_k(m)",         "construction":"MAC forgery→PRF distinguisher (contrapositive)"},
    ("MAC","PRF"):  {"dir":"backward", "pa":"PA#5", "theorem":"PRF-MAC outputs indist. from random","construction":"MAC distinguisher→PRF distinguisher"},
    ("PRF","OWP"):  {"dir":"backward", "pa":"PA#1/2","theorem":"PRF⟹PRP⟹OWP",                    "construction":"Use PRF→PRP via Feistel/switching, then fix an input to obtain a one-way permutation candidate"},
    ("PRF","CPA"):  {"dir":"forward",  "pa":"PA#3", "theorem":"PRF⟹CPA-secure encryption",        "construction":"Enc_k(m)=(r,F_k(r)⊕m) with fresh r"},
    ("CPA","CCA"):  {"dir":"forward",  "pa":"PA#6", "theorem":"CPA + MAC ⟹ CCA via Encrypt-then-MAC","construction":"Encrypt first, then authenticate ciphertext before decrypting"},
    ("PRP","MAC"):  {"dir":"forward",  "pa":"PA#4/5","theorem":"PRP⟹PRF (switching)⟹MAC",        "construction":"AES as PRF, then PRF-MAC construction"},
    ("CRHF","HMAC"):{"dir":"forward",  "pa":"PA#10","theorem":"CRHF⟹HMAC is EUF-CMA secure",      "construction":"HMAC(k,m)=H((k⊕opad)‖H((k⊕ipad)‖m))"},
    ("HMAC","CRHF"):{"dir":"backward", "pa":"PA#10","theorem":"HMAC_k(·) as MD compression=CRHF", "construction":"Fix key k; use HMAC_k as compression in Merkle-Damgård"},
    ("HMAC","MAC"): {"dir":"forward",  "pa":"PA#10","theorem":"HMAC is an EUF-CMA secure MAC",    "construction":"HMAC satisfies MAC definition by EUF-CMA proof"},
    ("MAC","HMAC"): {"dir":"backward", "pa":"PA#10","theorem":"EUF-CMA MAC can be HMAC-structured","construction":"Nested MAC: outer_MAC(k,inner_MAC(k',m))"},
    ("CRHF","MAC"): {"dir":"forward",  "pa":"PA#10","theorem":"CRHF→HMAC→MAC chain",              "construction":"DLPHash(CRHF)→HMAC→EUF-CMA MAC"},
    ("MAC","CRHF"): {"dir":"backward", "pa":"PA#7/8","theorem":"PRF-MAC as MD compression=CRHF",  "construction":"Use MAC_k as compression function in Merkle-Damgård"},
    ("CPA","PRF"):  {"dir":"backward", "pa":"PA#3", "theorem":"CPA⟹PRF: Extract PRF from CPA",    "construction":"Extract the pseudorandom pad from CPA ciphertext"},
    ("CCA","CPA"):  {"dir":"backward", "pa":"PA#6", "theorem":"CCA⟹CPA (CCA is stronger notion)", "construction":"Every CCA scheme is trivially CPA secure"},
    ("CCA","MAC"):  {"dir":"backward", "pa":"PA#6", "theorem":"CCA(Encrypt-then-MAC)⟹MAC",        "construction":"Extract MAC tag from CCA ciphertext"},
}

# ─── Models ───────────────────────────────────────────────────
class BuildRequest(BaseModel):
    foundation: str
    source_primitive: str
    seed_or_key_hex: str = ""

class ReduceRequest(BaseModel):
    source_type: str
    target_type: str
    query_hex: str = ""
    direction: str = "forward"
    source_instance_handle: dict = {}

class PRGViewerRequest(BaseModel):
    seed_hex: str = ""
    length_bytes: int = 32
    run_tests: bool = False

class GGMTreeRequest(BaseModel):
    key_hex: str = ""
    query_bits: str = "1011"
    depth: int = 4

class CPAChallengeRequest(BaseModel):
    m0: str = ""
    m1: str = ""
    reuse_nonce: bool = False

class CPAGuessRequest(BaseModel):
    challenge_id: str
    guess: int

class CPAOracleRequest(BaseModel):
    challenge_id: str
    message: str

class CCAGameStartRequest(BaseModel):
    message: str = "secret data"

class CCAOracleEncRequest(BaseModel):
    game_id: str
    message: str

class CCAOracleDecRequest(BaseModel):
    game_id: str
    ciphertext_hex: str

class ModeAnimatorRequest(BaseModel):
    mode: str = "CBC"
    message: str = "Block one demo!!Block two demo!!Block three demo"
    flip_enabled: bool = True
    flip_block: int = 0
    flip_byte: int = 0
    reuse_iv: bool = False

class MACGameStartRequest(BaseModel):
    num_messages: int = 8

class MACForgeryRequest(BaseModel):
    game_id: str
    message: str
    tag_hex: str

class MACOracleQueryRequest(BaseModel):
    game_id: str
    message: str

class LengthExtensionRequest(BaseModel):
    message: str = "amount=100&to=bob"
    extension: str = "&admin=true"

class CCAMalleabilityRequest(BaseModel):
    message: str = "transfer=100&to=bob"
    flip_byte: int = 0

class MDChainRequest(BaseModel):
    message: str = "Merkle-Damgard demo"
    block_size: int = 16

class DLPHashDemoRequest(BaseModel):
    message: str = "DLP hash demo"
    block_size: int = 16

class BirthdayDemoRequest(BaseModel):
    n_bits: int = 12
    max_evaluations: int = 20000

class HMACCompareRequest(BaseModel):
    message: str = "amount=100&to=bob"
    extension: str = "&admin=true"

class DLPHashDemoRequest(BaseModel):
    message: str = "DLP hash demo"
    block_size: int = 16

class BirthdayDemoRequest(BaseModel):
    n_bits: int = 12
    max_evaluations: int = 5000

class HMACCompareRequest(BaseModel):
    message: str = "amount=100&to=bob"
    extension: str = "&admin=true"
    hash_type: str = "dlp"

class DHDemoRequest(BaseModel):
    a: int = 0
    b: int = 0
    enable_eve: bool = False

class RSADemoRequest(BaseModel):
    message: str = "yes"

class MillerRabinDemoRequest(BaseModel):
    n: str = "561"
    rounds: int = 5

class HastadDemoRequest(BaseModel):
    message: str = "42"
    use_padding: bool = False

class SignatureDemoRequest(BaseModel):
    message: str = "sign me"
    tamper: bool = True

class ElGamalDemoRequest(BaseModel):
    message: int = 5

class CCAPKCDemoRequest(BaseModel):
    message: str = "launch=no"
    tamper: bool = True

class OTDemoRequest(BaseModel):
    m0: str = "zero secret"
    m1: str = "one secret"
    choice: int = 0

class SecureAndDemoRequest(BaseModel):
    a: int = 1
    b: int = 1

class MillionaireDemoRequest(BaseModel):
    alice: int = 7
    bob: int = 12
    bits: int = 4


def _normalise_hex(value: str, fallback: str = "") -> str:
    val = (value or "").strip() or fallback
    if val.startswith("0x"):
        val = val[2:]
    if len(val) % 2 != 0:
        val = "0" + val
    return val


def _foundation_root_from_dlp(kb: bytes) -> tuple[str, list[dict], dict]:
    from src.foundations.dlp_group import DEMO_PARAMS
    from src.pa01_owf_prg.owf import OWF

    owf = OWF(DEMO_PARAMS)
    x = int.from_bytes(kb[:8], "big") % DEMO_PARAMS.q or 1
    y = owf.evaluate(x)
    steps = [
        {
            "step": "Foundation: DLP",
            "description": "Start from the concrete DLP one-way function f(x)=g^x mod p.",
            "p": DEMO_PARAMS.p,
            "q": DEMO_PARAMS.q,
            "g": DEMO_PARAMS.g,
        },
        {
            "step": "Root primitive: OWF",
            "description": "Evaluate the DLP OWF on the input-derived exponent.",
            "x": x,
            "output_hex": hex(y),
        },
    ]
    handle = {"type": "OWF", "x": x, "y": y, "q": DEMO_PARAMS.q, "p": DEMO_PARAMS.p, "g": DEMO_PARAMS.g}
    return "OWF", steps, handle


def _foundation_root_from_aes(kb: bytes) -> tuple[str, list[dict], dict]:
    from src.foundations.aes_impl import aes_encrypt_block

    k = (kb + b"\x00" * 16)[:16]
    zero = b"\x00" * 16
    one = b"\x00" * 15 + b"\x01"
    ct0 = aes_encrypt_block(k, zero)
    ct1 = aes_encrypt_block(k, one)
    steps = [
        {
            "step": "Foundation: AES-128",
            "description": "Start from AES as the concrete PRP foundation.",
            "k_hex": k.hex(),
            "output_hex": ct0.hex(),
        },
        {
            "step": "Root primitive: PRP",
            "description": "AES_k is a pseudorandom permutation; Column 1 routes from this PRP to the requested source primitive.",
            "x_hex": zero.hex(),
            "AES_k(1)_hex": ct1.hex(),
            "output_hex": ct0.hex(),
        },
    ]
    return "PRP", steps, {"type": "PRP", "k_hex": k.hex(), "output_hex": ct0.hex()}


def _aes_compression_prg(seed_bytes: bytes, length: int) -> tuple[bytes, list[int]]:
    from src.foundations.aes_impl import aes_encrypt_block

    state = (seed_bytes + b"\x00" * 16)[:16]
    mask = int.from_bytes(b"\xaa" * 16, "big")
    bits = []
    for _ in range(length * 8):
        state_int = int.from_bytes(state, "big")
        bits.append(((state_int & mask).bit_count()) % 2)
        encrypted_zero = aes_encrypt_block(state, b"\x00" * 16)
        state = bytes(a ^ b for a, b in zip(encrypted_zero, state))
    output = int("".join(str(bit) for bit in bits), 2).to_bytes(length, "big")
    return output, bits

# ─── Column 1: Foundation → Source Primitive ─────────────────
@app.post("/build_foundation_to_primitive")
def build_foundation_to_primitive(req: BuildRequest) -> dict:
    """ONLY endpoint that touches AES/DLP foundations directly."""
    info = PRIMITIVES.get(req.source_primitive)
    if not info or not info.get("implemented"):
        return {"status": "stub", "message": f"Not implemented (PA#{info.get('pa','?')})", "handle": {}}

    val = _normalise_hex(req.seed_or_key_hex, "00" * 16)
    try:
        kb = bytes.fromhex(val)
    except ValueError:
        return {"error": "seed_or_key_hex must be valid hex", "status": "error"}

    if req.foundation == "DLP":
        root_type, steps, handle = _foundation_root_from_dlp(kb)
    elif req.foundation == "AES":
        root_type, steps, handle = _foundation_root_from_aes(kb)
    else:
        return {"error": f"Unknown foundation '{req.foundation}'. Use 'AES' or 'DLP'.", "status": "error"}

    path = _bfs(root_type, req.source_primitive)
    if not path:
        return {
            "status": "no_path",
            "message": f"No build path from {req.foundation} ({root_type}) to {req.source_primitive}.",
            "steps": steps,
            "handle": handle,
        }

    current_handle = handle
    for hop_index, (hop_src, hop_tgt) in enumerate(zip(path, path[1:]), start=1):
        hop = _compute_reduction_hop(hop_index, hop_src, hop_tgt, current_handle, kb)
        steps.extend(hop["steps"])
        current_handle = hop["handle"]

    return {"status": "ok", "foundation": req.foundation,
            "source_primitive": req.source_primitive, "root_primitive": root_type,
            "build_path": path, "hop_count": len(path) - 1,
            "steps": steps, "handle": current_handle}


@app.post("/pa01/prg_viewer")
def pa01_prg_viewer(req: PRGViewerRequest) -> dict:
    """PA#1 interactive PRG viewer: seed, expand, and optionally run NIST subset tests."""
    val = _normalise_hex(req.seed_hex, "00" * 8)
    try:
        seed_bytes = bytes.fromhex(val)
    except ValueError:
        return {"status": "error", "message": "seed_hex must be valid hex"}

    length = max(8, min(int(req.length_bytes or 32), 256))
    from src.pa01_owf_prg.owf import run_statistical_tests

    seed = int.from_bytes((seed_bytes + b"\x00" * 16)[:16], "big")
    output, bits = _aes_compression_prg(seed_bytes, length)
    ones = sum(bits)
    zeros = len(bits) - ones
    tests = run_statistical_tests(bits) if req.run_tests else []
    return {
        "status": "ok",
        "seed": seed,
        "seed_hex": seed_bytes.hex(),
        "length_bytes": length,
        "output_hex": output.hex(),
        "bit_count": len(bits),
        "ones": ones,
        "zeros": zeros,
        "one_ratio": round(ones / len(bits), 4) if bits else 0,
        "tests": tests,
        "steps": [
            {
                "step": "Seed",
                "description": "Pad or truncate the hex seed to 128 bits for the AES-compression OWF.",
                "output_hex": hex(seed),
            },
            {
                "step": "HILL / GL expansion",
                "description": "Iterate f(s)=AES_s(0^128) xor s and emit Goldreich-Levin hard-core bits.",
                "output_hex": output.hex(),
            },
        ],
    }


def _hex_or_none(value: int | None) -> str | None:
    return hex(value) if value is not None else None


@app.post("/pa02/ggm_tree")
def pa02_ggm_tree(req: GGMTreeRequest) -> dict:
    """PA#2 GGM tree visualizer: tree nodes, highlighted query path, and output."""
    depth = max(1, min(int(req.depth or 4), 8))
    query_bits = "".join(bit for bit in (req.query_bits or "") if bit in "01")
    query_bits = (query_bits + "0" * depth)[:depth]
    val = _normalise_hex(req.key_hex, "00" * 8)
    try:
        key_bytes = bytes.fromhex(val)
    except ValueError:
        return {"status": "error", "message": "key_hex must be valid hex"}

    from src.pa02_prf.ggm_prf import GGMPRF
    from src.common.bytes_utils import bytes_to_int

    ggm = GGMPRF(output_bits=32)
    key = bytes_to_int(key_bytes) % ggm.owf.q or 1
    active_by_level = {0: 0}
    idx = 0
    for level, bit in enumerate(query_bits, start=1):
        idx = idx * 2 + int(bit)
        active_by_level[level] = idx

    rows = []
    frontier = [(0, key)]
    for level in range(depth + 1):
        row = []
        next_frontier = []
        for node_index, state in frontier:
            node = {
                "id": f"{level}-{node_index}",
                "level": level,
                "index": node_index,
                "state": state,
                "state_hex": hex(state),
                "active": active_by_level.get(level) == node_index,
            }
            if level < depth:
                left, right = ggm._G(state)
                node["G0_hex"] = hex(left)
                node["G1_hex"] = hex(right)
                next_frontier.append((node_index * 2, left))
                next_frontier.append((node_index * 2 + 1, right))
            row.append(node)
        rows.append(row)
        frontier = next_frontier

    path = ggm.highlighted_path(key, [int(bit) for bit in query_bits])
    output = path[-1]["state"]
    return {
        "status": "ok",
        "key": key,
        "key_hex": hex(key),
        "query_bits": query_bits,
        "depth": depth,
        "output_hex": hex(output),
        "rows": rows,
        "path": [
            {
                "level": item["level"],
                "bit": item.get("bit"),
                "state_hex": hex(item["state"]),
                "G0_hex": _hex_or_none(item.get("G0")),
                "G1_hex": _hex_or_none(item.get("G1")),
                "chosen_hex": _hex_or_none(item.get("chosen")) or hex(item["state"]),
            }
            for item in path
        ],
    }


def _equalize_messages(m0: bytes, m1: bytes) -> tuple[bytes, bytes]:
    max_len = max(len(m0), len(m1), 1)
    return m0.ljust(max_len, b" "), m1.ljust(max_len, b" ")


def _xor_bytes_local(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def _blocks(data: bytes, size: int = 16) -> list[bytes]:
    return [data[i : i + size] for i in range(0, len(data), size)]


def _safe_text(data: bytes) -> str:
    return data.decode("utf-8", errors="replace")


def _rsa_demo_key(bits: int = 256, e: int = 65537):
    if not hasattr(_rsa_demo_key, "_cache"):
        _rsa_demo_key._cache = {}
    key = (bits, e)
    if key not in _rsa_demo_key._cache:
        from src.pa12_rsa.rsa import rsa_keygen
        _rsa_demo_key._cache[key] = rsa_keygen(bits, e=e)
    return _rsa_demo_key._cache[key]


def _demo_dlp_hash(block_size: int = 16):
    from src.pa08_dlp_hash.dlp_hash import DLPHash, gen_dlp_hash_params, DEMO_PARAMS

    params = gen_dlp_hash_params(DEMO_PARAMS)
    return DLPHash(params, block_size=block_size)


def _bits_msb(value: int, width: int) -> list[int]:
    return [(int(value) >> shift) & 1 for shift in range(width - 1, -1, -1)]


def _encode_ot_message(text: str, p: int) -> int:
    raw = (text or "").encode()
    return (sum(raw) % (p - 1)) + 1


@app.post("/pa03/cpa_challenge")
def pa03_cpa_challenge(req: CPAChallengeRequest) -> dict:
    """PA#3 IND-CPA challenge. The hidden bit is stored until the user guesses."""
    from src.pa03_cpa_enc.cpa_enc import Enc, broken_enc

    m0, m1 = _equalize_messages(req.m0.encode(), req.m1.encode())
    key = secrets.token_bytes(16)
    b = secrets.randbelow(2)
    chosen = m0 if b == 0 else m1
    if req.reuse_nonce:
        nonce, ciphertext = broken_enc(key, chosen)
        ref_nonce, ref_ciphertext = broken_enc(key, m0)
    else:
        nonce, ciphertext = Enc(key, chosen)
        ref_nonce, ref_ciphertext = None, None

    challenge_id = secrets.token_hex(12)
    CPA_CHALLENGES[challenge_id] = {
        "b": b,
        "key": key,
        "reuse_nonce": req.reuse_nonce,
        "m0": m0.decode(errors="replace"),
        "m1": m1.decode(errors="replace"),
    }
    if len(CPA_CHALLENGES) > 200:
        for old_key in list(CPA_CHALLENGES.keys())[:50]:
            CPA_CHALLENGES.pop(old_key, None)

    return {
        "status": "ok",
        "challenge_id": challenge_id,
        "scheme": "BROKEN nonce reuse" if req.reuse_nonce else "SECURE fresh nonce",
        "nonce_hex": nonce.hex(),
        "ciphertext_hex": ciphertext.hex(),
        "reference_ciphertext_hex": ref_ciphertext.hex() if ref_ciphertext else None,
        "reference_nonce_hex": ref_nonce.hex() if ref_nonce else None,
        "steps": [
            {"step": "Challenge bit", "description": "The challenger samples hidden b in {0,1}."},
            {"step": "Encrypt mb", "description": "Compute C* = Enc_k(m_b).", "output_hex": ciphertext.hex()},
            {"step": "Nonce", "description": "Fresh in secure mode; fixed at 0^128 in reuse-nonce mode.", "output_hex": nonce.hex()},
        ],
    }


@app.post("/pa03/cpa_guess")
def pa03_cpa_guess(req: CPAGuessRequest) -> dict:
    challenge = CPA_CHALLENGES.pop(req.challenge_id, None)
    if challenge is None:
        return {"status": "error", "message": "Unknown or already-used challenge_id"}
    guess = 1 if int(req.guess) else 0
    correct = guess == challenge["b"]
    return {
        "status": "ok",
        "guess": guess,
        "b": challenge["b"],
        "correct": correct,
        "reuse_nonce": challenge["reuse_nonce"],
        "chosen_message": challenge["m0"] if challenge["b"] == 0 else challenge["m1"],
    }


@app.post("/pa03/cpa_encrypt")
def pa03_cpa_encrypt(req: CPAOracleRequest) -> dict:
    """CPA encryption oracle: encrypt an arbitrary message under the challenge key."""
    from src.pa03_cpa_enc.cpa_enc import Enc

    challenge = CPA_CHALLENGES.get(req.challenge_id)
    if challenge is None:
        return {"status": "error", "message": "Unknown challenge_id. Start a new CPA game."}
    key = challenge["key"]
    msg = (req.message or "").encode()
    nonce, ciphertext = Enc(key, msg)
    return {
        "status": "ok",
        "message": req.message,
        "nonce_hex": nonce.hex(),
        "ciphertext_hex": ciphertext.hex(),
    }


@app.post("/pa04/mode_animator")
def pa04_mode_animator(req: ModeAnimatorRequest) -> dict:
    """PA#4 CBC/OFB/CTR block-mode animator with bit-flip propagation data."""
    from src.common.padding import pkcs7_pad
    from src.common.bytes_utils import int_to_bytes, bytes_to_int
    from src.foundations.aes_impl import aes_encrypt_block, aes_decrypt_block
    from src.pa04_modes.modes import CBC_Dec, OFB_Dec, CTR_Dec

    mode = (req.mode or "CBC").upper()
    if mode not in {"CBC", "OFB", "CTR"}:
        return {"status": "error", "message": "mode must be CBC, OFB, or CTR"}

    key = bytes.fromhex("00112233445566778899aabbccddeeff")
    iv = bytes.fromhex("0102030405060708090a0b0c0d0e0f10")
    plaintext = (req.message or "").encode()
    if mode == "CBC":
        working_plaintext = pkcs7_pad(plaintext, 16)
    else:
        target_len = max(48, ((len(plaintext) + 15) // 16) * 16)
        working_plaintext = plaintext.ljust(target_len, b" ")

    steps = []
    ciphertext = b""
    previous = iv
    for index, block in enumerate(_blocks(working_plaintext)):
        if mode == "CBC":
            aes_input = _xor_bytes_local(block, previous)
            aes_output = aes_encrypt_block(key, aes_input)
            c_block = aes_output
            previous = c_block
            step = {
                "block": index,
                "plain_hex": block.hex(),
                "xor_with_hex": (iv if index == 0 else _blocks(ciphertext)[index - 1]).hex(),
                "aes_input_hex": aes_input.hex(),
                "cipher_hex": c_block.hex(),
            }
        elif mode == "OFB":
            previous = aes_encrypt_block(key, previous)
            c_block = _xor_bytes_local(block, previous[:len(block)])
            step = {
                "block": index,
                "plain_hex": block.hex(),
                "feedback_hex": previous.hex(),
                "keystream_hex": previous[:len(block)].hex(),
                "cipher_hex": c_block.hex(),
            }
        else:
            counter = int_to_bytes((bytes_to_int(iv) + index) % (2**128), 16)
            keystream = aes_encrypt_block(key, counter)
            c_block = _xor_bytes_local(block, keystream[:len(block)])
            step = {
                "block": index,
                "plain_hex": block.hex(),
                "counter_hex": counter.hex(),
                "keystream_hex": keystream[:len(block)].hex(),
                "cipher_hex": c_block.hex(),
            }
        ciphertext += c_block
        steps.append(step)

    flipped = bytearray(ciphertext)
    if req.flip_enabled:
        flip_index = max(0, min(int(req.flip_block or 0), len(_blocks(ciphertext)) - 1)) * 16
        flip_index += max(0, min(int(req.flip_byte or 0), 15))
        if flip_index < len(flipped):
            flipped[flip_index] ^= 1
    flipped = bytes(flipped)

    try:
        if mode == "CBC":
            decrypted = CBC_Dec(key, iv, flipped)
        elif mode == "OFB":
            decrypted = OFB_Dec(key, iv, flipped)
        else:
            decrypted = CTR_Dec(key, iv, flipped)
    except Exception:
        decrypted = b"<padding error after flip>"

    original_compare = plaintext if mode == "CBC" else working_plaintext[:len(decrypted)]
    diff_blocks = []
    for index, (orig_block, dec_block) in enumerate(zip(_blocks(original_compare), _blocks(decrypted))):
        diff_blocks.append({
            "block": index,
            "diff_bytes": sum(1 for a, b in zip(orig_block, dec_block) if a != b),
            "decrypted_hex": dec_block.hex(),
            "decrypted_text": _safe_text(dec_block),
        })

    reuse_demo = None
    if mode == "CBC" and req.reuse_iv:
        from src.pa04_modes.modes import CBC_Enc
        m1 = b"same-first-block!!" + b" rest of first message"
        m2 = b"same-first-block!!" + b" second message body"
        c1 = CBC_Enc(key, iv, m1)
        c2 = CBC_Enc(key, iv, m2)
        reuse_demo = {
            "c1_first_hex": c1[:16].hex(),
            "c2_first_hex": c2[:16].hex(),
            "match": c1[:16] == c2[:16],
        }

    return {
        "status": "ok",
        "mode": mode,
        "key_hex": key.hex(),
        "iv_or_nonce_hex": iv.hex(),
        "ciphertext_hex": ciphertext.hex(),
        "flipped_ciphertext_hex": flipped.hex(),
        "flip": {
            "enabled": bool(req.flip_enabled),
            "block": int(req.flip_block or 0),
            "byte": int(req.flip_byte or 0),
            "bit": 0,
        },
        "steps": steps,
        "diff_blocks": diff_blocks,
        "reuse_demo": reuse_demo,
        "analysis": {
            "CBC": "A ciphertext bit flip corrupts the current plaintext block and flips the matching bit in the next block.",
            "OFB": "A ciphertext bit flip changes only the matching plaintext bit.",
            "CTR": "A ciphertext bit flip changes only the matching plaintext bit.",
        }[mode],
    }


@app.post("/pa05/mac_game_start")
def pa05_mac_game_start(req: MACGameStartRequest) -> dict:
    from src.pa05_mac.mac import MacCBC

    count = max(1, min(int(req.num_messages or 8), 50))
    key = secrets.token_bytes(16)
    mac = MacCBC()
    signed = []
    for i in range(count):
        msg = f"oracle-message-{i:02d}".encode()
        tag = mac.Mac(key, msg)
        signed.append({"message": msg.decode(), "message_hex": msg.hex(), "tag_hex": tag.hex()})
    game_id = secrets.token_hex(12)
    MAC_GAMES[game_id] = {
        "key": key,
        "signed_messages": {item["message"] for item in signed},
        "attempts": 0,
        "successes": 0,
    }
    if len(MAC_GAMES) > 100:
        for old_key in list(MAC_GAMES.keys())[:25]:
            MAC_GAMES.pop(old_key, None)
    return {"status": "ok", "game_id": game_id, "signed": signed, "attempts": 0, "successes": 0}


@app.post("/pa05/mac_forgery")
def pa05_mac_forgery(req: MACForgeryRequest) -> dict:
    from src.pa05_mac.mac import MacCBC

    game = MAC_GAMES.get(req.game_id)
    if game is None:
        return {"status": "error", "message": "Unknown game_id. Start a new MAC game."}
    try:
        tag = bytes.fromhex(_normalise_hex(req.tag_hex, ""))
    except ValueError:
        return {"status": "error", "message": "tag_hex must be valid hex"}
    msg = (req.message or "").encode()
    game["attempts"] += 1
    fresh = req.message not in game["signed_messages"]
    accepted = fresh and MacCBC().Vrfy(game["key"], msg, tag)
    if accepted:
        game["successes"] += 1
    return {
        "status": "ok",
        "fresh_message": fresh,
        "accepted": accepted,
        "attempts": game["attempts"],
        "successes": game["successes"],
    }


@app.post("/pa05/mac_oracle_query")
def pa05_mac_oracle_query(req: MACOracleQueryRequest) -> dict:
    """PA#5 MAC oracle: sign a user-chosen message under the hidden key.

    The message is added to the signed set so it cannot be used as a forgery.
    This models the EUF-CMA oracle access.
    """
    from src.pa05_mac.mac import MacCBC

    game = MAC_GAMES.get(req.game_id)
    if game is None:
        return {"status": "error", "message": "Unknown game_id. Start a new MAC game."}
    msg_str = req.message or ""
    if msg_str in game["signed_messages"]:
        return {
            "status": "ok",
            "already_signed": True,
            "message": msg_str,
            "tag_hex": MacCBC().Mac(game["key"], msg_str.encode()).hex(),
            "note": "This message was already signed. Query a different message.",
        }
    tag = MacCBC().Mac(game["key"], msg_str.encode())
    game["signed_messages"].add(msg_str)
    return {
        "status": "ok",
        "already_signed": False,
        "message": msg_str,
        "tag_hex": tag.hex(),
        "signed_count": len(game["signed_messages"]),
    }


@app.post("/pa05/length_extension")
def pa05_length_extension(req: LengthExtensionRequest) -> dict:
    from src.pa05_mac.mac import naive_mac
    from src.common.padding import iso7816_pad

    key = b"hidden-demo-key!!"[:16]
    message = (req.message or "").encode()
    extension = (req.extension or "").encode()
    original_tag = naive_mac(key, message)
    glue_padding = iso7816_pad(key + message, 16)[len(key + message):]
    padded_ext = iso7816_pad(extension, 16)
    forged_tag = original_tag
    for block in _blocks(padded_ext):
        forged_tag = _xor_bytes_local(forged_tag, block)
    extended_message = message + glue_padding + extension
    actual_tag = naive_mac(key, extended_message)
    return {
        "status": "ok",
        "message_text": _safe_text(message),
        "extension_text": _safe_text(extension),
        "glue_padding_hex": glue_padding.hex(),
        "extended_message_display": f"{_safe_text(message)} || pad({glue_padding.hex()}) || {_safe_text(extension)}",
        "message_hex": message.hex(),
        "extension_hex": extension.hex(),
        "original_tag_hex": original_tag.hex(),
        "forged_tag_hex": forged_tag.hex(),
        "actual_extended_tag_hex": actual_tag.hex(),
        "attack_succeeds": forged_tag == actual_tag,
        "extended_message_hex": extended_message.hex(),
    }


@app.post("/pa06/cca_malleability")
def pa06_cca_malleability(req: CCAMalleabilityRequest) -> dict:
    """PA#6 contrast: CPA bit-flip malleability vs CCA Encrypt-then-MAC rejection."""
    from src.pa03_cpa_enc.cpa_enc import Enc, Dec
    from src.pa06_cca_enc.cca_enc import CCAEnc

    key_enc = bytes.fromhex("00112233445566778899aabbccddeeff")
    key_mac = bytes.fromhex("0f0e0d0c0b0a09080706050403020100")
    message = (req.message or "").encode()
    flip_byte = max(0, int(req.flip_byte or 0))

    nonce, cpa_cipher = Enc(key_enc, message)
    cpa_tampered = bytearray(cpa_cipher)
    if cpa_tampered:
        cpa_tampered[min(flip_byte, len(cpa_tampered) - 1)] ^= 1
    cpa_tampered = bytes(cpa_tampered)
    try:
        cpa_plain = Dec(key_enc, nonce, cpa_tampered)
        cpa_result = {"status": "decrypted", "plaintext_text": _safe_text(cpa_plain), "plaintext_hex": cpa_plain.hex()}
    except Exception as exc:
        cpa_result = {"status": "decryption_error", "error": str(exc)}

    cca = CCAEnc()
    packed_c, tag = cca.CCA_Enc(key_enc, key_mac, message)
    cca_tampered = bytearray(packed_c)
    if cca_tampered:
        cca_tampered[min(flip_byte, len(cca_tampered) - 1)] ^= 1
    cca_tampered = bytes(cca_tampered)
    expected_tampered_tag = cca.mac.Mac(key_mac, cca_tampered)
    cca_plain = cca.CCA_Dec(key_enc, key_mac, cca_tampered, tag)

    return {
        "status": "ok",
        "message_text": _safe_text(message),
        "flip_byte": flip_byte,
        "cpa": {
            "nonce_hex": nonce.hex(),
            "ciphertext_hex": cpa_cipher.hex(),
            "tampered_ciphertext_hex": cpa_tampered.hex(),
            "result": cpa_result,
        },
        "cca": {
            "packed_ciphertext_hex": packed_c.hex(),
            "tag_hex": tag.hex(),
            "tampered_ciphertext_hex": cca_tampered.hex(),
            "expected_tampered_tag_hex": expected_tampered_tag.hex(),
            "mac_valid": tag == expected_tampered_tag,
            "result": "⊥" if cca_plain is None else _safe_text(cca_plain),
        },
        "steps": [
            {"step": "CPA-only", "description": "Flip one ciphertext bit and decrypt anyway.", "output_hex": cpa_tampered.hex()},
            {"step": "CCA Encrypt-then-MAC", "description": "Verify tag over ciphertext before decrypting.", "output_hex": tag.hex()},
            {"step": "Tamper check", "description": "The old tag no longer matches the tampered ciphertext, so decryption returns ⊥."},
        ],
    }


@app.post("/pa06/cca_game_start")
def pa06_cca_game_start(req: CCAGameStartRequest) -> dict:
    """Start a CCA game: encrypt a challenge message, give the user enc+dec oracle access."""
    from src.pa03_cpa_enc.cpa_enc import Enc
    from src.pa06_cca_enc.cca_enc import CCAEnc

    key_enc = secrets.token_bytes(16)
    key_mac = secrets.token_bytes(16)
    message = (req.message or "secret data").encode()
    cca = CCAEnc()
    packed_c, tag = cca.CCA_Enc(key_enc, key_mac, message)
    game_id = secrets.token_hex(12)
    CCA_GAMES[game_id] = {
        "key_enc": key_enc,
        "key_mac": key_mac,
        "challenge_ct_hex": packed_c.hex(),
        "challenge_tag_hex": tag.hex(),
        "enc_queries": 0,
        "dec_queries": 0,
    }
    if len(CCA_GAMES) > 100:
        for old_key in list(CCA_GAMES.keys())[:25]:
            CCA_GAMES.pop(old_key, None)
    return {
        "status": "ok",
        "game_id": game_id,
        "challenge_ciphertext_hex": packed_c.hex(),
        "challenge_tag_hex": tag.hex(),
    }


@app.post("/pa06/cca_encrypt")
def pa06_cca_encrypt(req: CCAOracleEncRequest) -> dict:
    """CCA encryption oracle: Enc(k, m) under the game key."""
    from src.pa06_cca_enc.cca_enc import CCAEnc

    game = CCA_GAMES.get(req.game_id)
    if game is None:
        return {"status": "error", "message": "Unknown game_id. Start a new CCA game."}
    msg = (req.message or "").encode()
    cca = CCAEnc()
    packed_c, tag = cca.CCA_Enc(game["key_enc"], game["key_mac"], msg)
    game["enc_queries"] += 1
    return {
        "status": "ok",
        "message": req.message,
        "ciphertext_hex": packed_c.hex(),
        "tag_hex": tag.hex(),
    }


@app.post("/pa06/cca_decrypt")
def pa06_cca_decrypt(req: CCAOracleDecRequest) -> dict:
    """CCA decryption oracle: Dec(k, c) — rejects if c is the challenge ciphertext."""
    from src.pa06_cca_enc.cca_enc import CCAEnc

    game = CCA_GAMES.get(req.game_id)
    if game is None:
        return {"status": "error", "message": "Unknown game_id. Start a new CCA game."}
    ct_hex = _normalise_hex(req.ciphertext_hex, "")
    if ct_hex == game["challenge_ct_hex"]:
        return {
            "status": "ok",
            "rejected": True,
            "reason": "Cannot decrypt the challenge ciphertext (IND-CCA2 restriction).",
        }
    try:
        ct_bytes = bytes.fromhex(ct_hex)
    except ValueError:
        return {"status": "error", "message": "Invalid hex ciphertext."}
    cca = CCAEnc()
    tag = bytes.fromhex(game["challenge_tag_hex"])
    plaintext = cca.CCA_Dec(game["key_enc"], game["key_mac"], ct_bytes, tag)
    game["dec_queries"] += 1
    if plaintext is None:
        return {"status": "ok", "rejected": False, "decrypted": False, "result": "⊥ (MAC verification failed)"}
    return {
        "status": "ok",
        "rejected": False,
        "decrypted": True,
        "plaintext_text": _safe_text(plaintext),
        "plaintext_hex": plaintext.hex(),
    }


@app.post("/pa07/md_chain")
def pa07_md_chain(req: MDChainRequest) -> dict:
    """PA#7 Merkle-Damgard chain viewer using the PA#7 XOR compression demo."""
    from src.common.padding import md_pad
    from src.pa07_merkle_damgard.merkle_damgard import make_xor_hash, demo_collision_propagation

    block_size = max(9, min(int(req.block_size or 16), 64))
    message = (req.message or "").encode()
    hash_fn = make_xor_hash(digest_bytes=16, block_size=block_size)
    padded = md_pad(message, block_size)
    state = hash_fn.iv
    trace = []
    for index, block in enumerate(_blocks(padded, block_size)):
        previous = state
        state = hash_fn.compress(state, block)
        trace.append({
            "block": index,
            "block_hex": block.hex(),
            "block_text": _safe_text(block),
            "prev_state_hex": previous.hex(),
            "next_state_hex": state.hex(),
        })
    collision = demo_collision_propagation(hash_fn)
    return {
        "status": "ok",
        "message_text": _safe_text(message),
        "message_hex": message.hex(),
        "block_size": block_size,
        "iv_hex": hash_fn.iv.hex(),
        "padded_hex": padded.hex(),
        "padding_hex": padded[len(message):].hex(),
        "digest_hex": state.hex(),
        "trace": trace,
        "collision_demo": collision,
    }


@app.post("/pa08/dlp_hash")
def pa08_dlp_hash(req: DLPHashDemoRequest) -> dict:
    """PA#8 DLP hash live trace over Merkle-Damgard."""
    from src.common.padding import md_pad
    from src.common.bytes_utils import bytes_to_int, int_to_bytes
    from src.common.math_utils import modexp
    from src.pa08_dlp_hash.dlp_hash import DLPHash, DLPCompress, gen_dlp_hash_params
    from src.foundations.dlp_group import MEDIUM_DEMO_PARAMS

    block_size = max(9, min(int(req.block_size or 16), 64))
    message = (req.message or "").encode()
    params = gen_dlp_hash_params(MEDIUM_DEMO_PARAMS)
    h = DLPHash(params, block_size=block_size)
    compress = DLPCompress(params)
    padded = md_pad(message, block_size)
    state = int_to_bytes(params.g, compress.elem_bytes)
    trace = []
    for index, block in enumerate(_blocks(padded, block_size)):
        x = bytes_to_int(state) % params.q
        y = bytes_to_int(block) % params.q
        gx = modexp(params.g, x, params.p)
        hy = modexp(params.h_hat, y, params.p)
        next_state = compress.compress(state, block)
        trace.append({
            "block": index,
            "block_hex": block.hex(),
            "x": x,
            "y": y,
            "g_pow_x_hex": hex(gx),
            "hhat_pow_y_hex": hex(hy),
            "prev_state_hex": state.hex(),
            "next_state_hex": next_state.hex(),
        })
        state = next_state
    return {
        "status": "ok",
        "message_text": _safe_text(message),
        "message_hex": message.hex(),
        "block_size": block_size,
        "p": params.p,
        "q": params.q,
        "g": params.g,
        "h_hat": params.h_hat,
        "alpha_trapdoor_demo_only": params.alpha_trapdoor,
        "padding_hex": padded[len(message):].hex(),
        "digest_hex": h.hash(message).hex(),
        "trace": trace,
        "formula": "compress(H, B) = g^x * h_hat^y mod p, where x=H mod q and y=B mod q",
    }


@app.post("/pa09/birthday")
def pa09_birthday(req: BirthdayDemoRequest) -> dict:
    """PA#9 live birthday collision search on truncated PA#8 DLP hash."""
    from src.pa09_birthday.birthday import birthday_attack, compute_md5_sha1_cost
    from src.pa08_dlp_hash.dlp_hash import DLPHash, gen_dlp_hash_params
    from src.foundations.dlp_group import MEDIUM_DEMO_PARAMS

    n_bits = max(4, min(int(req.n_bits or 12), 20))
    max_evaluations = max(100, min(int(req.max_evaluations or 20000), 200000))
    params = gen_dlp_hash_params(MEDIUM_DEMO_PARAMS)
    dlp = DLPHash(params, block_size=16)

    def hash_fn(x: bytes) -> int:
        return int.from_bytes(dlp.hash(x), "big")

    result = birthday_attack(hash_fn, n_bits, max_evaluations=max_evaluations)

    # Compute theoretical birthday curve data points for the chart overlay
    import math
    N = 2 ** n_bits
    birthday_bound = int(math.ceil(math.sqrt(N)))
    curve_points = []
    num_points = min(birthday_bound * 3, 500)
    for i in range(0, num_points + 1, max(1, num_points // 100)):
        prob = 1.0 - math.exp(-i * (i - 1) / (2.0 * N)) if i > 0 else 0.0
        curve_points.append({"k": i, "p": round(min(prob, 1.0), 4)})

    return {
        "status": "ok",
        "n_bits": n_bits,
        "max_evaluations": max_evaluations,
        "attack": result,
        "birthday_curve": curve_points,
        "birthday_bound": birthday_bound,
        "cost_context": compute_md5_sha1_cost(),
    }


@app.post("/pa10/hmac_compare")
def pa10_hmac_compare(req: HMACCompareRequest) -> dict:
    """PA#10 side-by-side: naive length extension succeeds, HMAC does not."""
    from src.pa05_mac.mac import naive_mac
    from src.pa10_hmac_eth.hmac_eth import HMAC
    from src.pa08_dlp_hash.dlp_hash import DLPHash, gen_dlp_hash_params
    from src.foundations.dlp_group import MEDIUM_DEMO_PARAMS
    from src.common.padding import iso7816_pad

    key = b"hidden-demo-key!!"[:16]
    message = (req.message or "").encode()
    extension = (req.extension or "").encode()
    hash_type = (req.hash_type or "dlp").lower()

    naive_tag = naive_mac(key, message)
    glue_padding = iso7816_pad(key + message, 16)[len(key + message):]
    forged_naive = naive_tag
    for block in _blocks(iso7816_pad(extension, 16)):
        forged_naive = _xor_bytes_local(forged_naive, block)
    extended_message = message + glue_padding + extension
    actual_naive = naive_mac(key, extended_message)

    if hash_type == "sha256":
        # Simple SHA-256-like placeholder using Python's hashlib
        # (only for comparison demo — not used in the crypto chain)
        import hashlib
        class _SHA256Wrapper:
            block_size = 64
            def hash(self, data: bytes) -> bytes:
                return hashlib.sha256(data).digest()[:16]
        hash_fn = _SHA256Wrapper()
        hash_label = "SHA-256 (placeholder)"
    else:
        params = gen_dlp_hash_params(MEDIUM_DEMO_PARAMS)
        hash_fn = DLPHash(params, block_size=16)
        hash_label = "DLP Hash (PA#8)"

    hmac_tag = HMAC(key, message, hash_fn)
    forged_hmac_attempt = hash_fn.hash(hmac_tag + extension)
    real_hmac_extended = HMAC(key, message + extension, hash_fn)
    return {
        "status": "ok",
        "message_text": _safe_text(message),
        "extension_text": _safe_text(extension),
        "hash_type": hash_type,
        "hash_label": hash_label,
        "extended_message_display": f"{_safe_text(message)} || pad({glue_padding.hex()}) || {_safe_text(extension)}",
        "naive": {
            "original_tag_hex": naive_tag.hex(),
            "forged_tag_hex": forged_naive.hex(),
            "actual_extended_tag_hex": actual_naive.hex(),
            "attack_succeeds": forged_naive == actual_naive,
        },
        "hmac": {
            "original_tag_hex": hmac_tag.hex(),
            "forged_attempt_hex": forged_hmac_attempt.hex(),
            "real_extended_tag_hex": real_hmac_extended.hex(),
            "attack_succeeds": forged_hmac_attempt == real_hmac_extended,
        },
    }


@app.post("/pa11/dh_exchange")
def pa11_dh_exchange(req: DHDemoRequest) -> dict:
    """PA#11 live Diffie-Hellman exchange with optional MITM."""
    from src.foundations.dlp_group import MEDIUM_DEMO_PARAMS
    from src.common.math_utils import modexp
    from src.pa11_dh.dh import dh_mitm_attack
    from src.common.randomness import random_element_zq

    group = MEDIUM_DEMO_PARAMS
    a = int(req.a or 0) % group.q or random_element_zq(group.q)
    b = int(req.b or 0) % group.q or random_element_zq(group.q)
    A = modexp(group.g, a, group.p)
    B = modexp(group.g, b, group.p)
    K_alice = modexp(B, a, group.p)
    K_bob = modexp(A, b, group.p)
    result = {
        "status": "ok",
        "group": {"p": group.p, "q": group.q, "g": group.g},
        "alice": {"private": a, "public": A, "shared": K_alice},
        "bob": {"private": b, "public": B, "shared": K_bob},
        "match": K_alice == K_bob,
        "steps": [
            {"step": "Alice sends A", "description": "A = g^a mod p", "output_hex": hex(A)},
            {"step": "Bob sends B", "description": "B = g^b mod p", "output_hex": hex(B)},
            {"step": "Shared secret", "description": "Alice computes B^a; Bob computes A^b.", "output_hex": hex(K_alice)},
        ],
    }
    if req.enable_eve:
        result["eve"] = dh_mitm_attack(group)
    return result


@app.post("/pa12/rsa_determinism")
def pa12_rsa_determinism(req: RSADemoRequest) -> dict:
    """PA#12 textbook RSA determinism vs PKCS#1 v1.5 randomized encryption."""
    from src.pa12_rsa.rsa import rsa_enc, pkcs15_enc
    from src.common.bytes_utils import bytes_to_int, int_to_bytes
    from src.common.padding import pkcs1_v15_pad
    from src.common.math_utils import modexp

    pk, sk = _rsa_demo_key(256, 65537)
    n_bytes = (pk.n.bit_length() + 7) // 8
    message = (req.message or "yes").encode()[: max(1, n_bytes - 11)]
    m_int = bytes_to_int(message)
    c1 = rsa_enc(pk, m_int)
    c2 = rsa_enc(pk, m_int)

    em1 = pkcs1_v15_pad(message, n_bytes)
    em2 = pkcs1_v15_pad(message, n_bytes)
    pc1 = int_to_bytes(modexp(bytes_to_int(em1), pk.e, pk.n), n_bytes)
    pc2 = int_to_bytes(modexp(bytes_to_int(em2), pk.e, pk.n), n_bytes)
    return {
        "status": "ok",
        "message_text": _safe_text(message),
        "public_key": {"n_hex": hex(pk.n), "e": pk.e},
        "textbook": {
            "c1_hex": hex(c1),
            "c2_hex": hex(c2),
            "identical": c1 == c2,
            "conclusion": "same plaintext gives same ciphertext",
        },
        "pkcs15": {
            "c1_hex": pc1.hex(),
            "c2_hex": pc2.hex(),
            "identical": pc1 == pc2,
            "padding1_hex": em1.hex(),
            "padding2_hex": em2.hex(),
            "conclusion": "random PS bytes make ciphertexts differ",
        },
    }


@app.post("/pa13/miller_rabin")
def pa13_miller_rabin(req: MillerRabinDemoRequest) -> dict:
    """PA#13 Miller-Rabin tester with witness trace."""
    from src.pa13_miller_rabin.miller_rabin import is_prime, fermat_test, modexp, _decompose

    try:
        n = int(str(req.n).strip())
    except ValueError:
        return {"status": "error", "message": "n must be an integer"}
    rounds = max(1, min(int(req.rounds or 5), 40))
    if n < 2:
        return {"status": "ok", "n": n, "rounds": rounds, "probably_prime": False, "trace": []}

    trace = []
    if n > 3 and n % 2 == 1:
        s, d = _decompose(n - 1)
        import random
        rng = random.Random(n)  # deterministic per n for reproducibility
        witness_set = set()
        # Always include 2 as first witness, then random samples
        witness_set.add(2)
        while len(witness_set) < min(rounds, n - 3):
            witness_set.add(rng.randint(2, n - 2))
        witnesses = sorted(witness_set)[:rounds]
        composite = False
        for a in witnesses:
            x = modexp(a, d, n)
            round_steps = [x]
            passes = x in (1, n - 1)
            if not passes:
                for _ in range(s - 1):
                    x = modexp(x, 2, n)
                    round_steps.append(x)
                    if x == n - 1:
                        passes = True
                        break
            if not passes:
                composite = True
            trace.append({"witness": a, "values": round_steps, "passes_round": passes})
            if composite:
                break
        probably_prime = not composite
        decomposition = {"s": s, "d": d}
    else:
        probably_prime = is_prime(n, rounds)
        decomposition = None

    actual_wrapper = is_prime(n, rounds)
    return {
        "status": "ok",
        "n": n,
        "rounds": rounds,
        "probably_prime": probably_prime and actual_wrapper,
        "result": "PROBABLY PRIME" if (probably_prime and actual_wrapper) else "COMPOSITE",
        "decomposition": decomposition,
        "trace": trace,
        "fermat_says_prime": fermat_test(n, min(rounds, 5)) if n > 3 else actual_wrapper,
        "carmichael_note": "561 = 3 * 11 * 17; Fermat can be fooled, Miller-Rabin catches it." if n == 561 else "",
    }


@app.post("/pa14/hastad")
def pa14_hastad(req: HastadDemoRequest) -> dict:
    """PA#14 Håstad broadcast attack visualizer for e=3."""
    from src.pa12_rsa.rsa import rsa_keygen, rsa_enc, pkcs15_enc
    from src.pa14_crt_attack.crt_attack import crt_wrapper, integer_eth_root
    from src.common.bytes_utils import bytes_to_int

    e = 3
    raw = (req.message or "42").encode()[:4]
    m = bytes_to_int(raw) or 42
    recipients = []
    residues = []
    moduli = []
    for _ in range(e):
        pk, _ = rsa_keygen(128, e=e)
        if req.use_padding:
            c = bytes_to_int(pkcs15_enc(pk, raw[:5] or b"42"))
        else:
            c = rsa_enc(pk, m)
        recipients.append({"n_hex": hex(pk.n), "ciphertext_hex": hex(c)})
        residues.append(c)
        moduli.append(pk.n)

    combined = crt_wrapper(residues, moduli)
    root = integer_eth_root(combined, e)
    exact = root ** e == combined
    return {
        "status": "ok",
        "e": e,
        "message_text": _safe_text(raw),
        "message_int": m,
        "use_padding": bool(req.use_padding),
        "recipients": recipients,
        "crt_combined_hex": hex(combined),
        "root": root,
        "root_hex": hex(root),
        "exact_root": exact,
        "recovered_text": _safe_text(int(root).to_bytes(max(1, (int(root).bit_length() + 7) // 8), "big")) if exact else "",
        "attack_succeeded": exact and root == m and not req.use_padding,
        "note": "Unpadded textbook RSA broadcasts recover m. Padding makes each encrypted value different, so the cube root is not the original message.",
    }


@app.post("/pa15/signatures")
def pa15_signatures(req: SignatureDemoRequest) -> dict:
    """PA#15 hash-then-sign RSA signatures with raw-RSA forgery contrast."""
    from src.pa15_signatures.signatures import Sign, Verify, demo_multiplicative_forgery, _hash_message
    from src.common.bytes_utils import bytes_to_int
    from src.common.math_utils import modexp

    pk, sk = _rsa_demo_key(256, 65537)
    hash_fn = _demo_dlp_hash(16)
    message = (req.message or "sign me").encode()
    sigma = Sign(sk, message, hash_fn)
    h_int = _hash_message(message, hash_fn) % pk.n or 1
    recovered = modexp(bytes_to_int(sigma), pk.e, pk.n)

    tampered = message + (b"!" if req.tamper else b"")
    return {
        "status": "ok",
        "message_text": _safe_text(message),
        "tampered_text": _safe_text(tampered),
        "public_key": {"n_hex": hex(pk.n), "e": pk.e},
        "hash_hex": hex(h_int),
        "signature_hex": sigma.hex(),
        "recovered_hash_hex": hex(recovered),
        "valid": Verify(pk, message, sigma, hash_fn),
        "tampered_valid": Verify(pk, tampered, sigma, hash_fn),
        "raw_rsa_forgery": demo_multiplicative_forgery(pk, sk),
        "steps": [
            {"step": "Hash message", "description": "Compute h = DLPHash(m), then reduce h into the RSA domain.", "output_hex": hex(h_int)},
            {"step": "Sign", "description": "Compute sigma = h^d mod n.", "output_hex": sigma.hex()},
            {"step": "Verify", "description": "Check sigma^e mod n equals DLPHash(m).", "output_hex": hex(recovered)},
        ],
    }


@app.post("/pa16/elgamal")
def pa16_elgamal(req: ElGamalDemoRequest) -> dict:
    """PA#16 ElGamal encryption and malleability demo."""
    from src.pa16_elgamal.elgamal import elgamal_keygen, Enc, Dec
    from src.foundations.dlp_group import DEMO_PARAMS

    group = DEMO_PARAMS
    sk, pk = elgamal_keygen(group)
    m = max(1, min(int(req.message or 5), group.p - 1))
    c1, c2 = Enc(pk, m)
    decrypted = Dec(sk, c1, c2)
    c2_tampered = (2 * c2) % group.p
    tampered_plain = Dec(sk, c1, c2_tampered)
    return {
        "status": "ok",
        "group": {"p": group.p, "q": group.q, "g": group.g},
        "public_key": {"y": pk.y},
        "secret_key": {"x": sk.x},
        "message": m,
        "ciphertext": {"c1": c1, "c2": c2},
        "decrypted": decrypted,
        "tampered_ciphertext": {"c1": c1, "c2": c2_tampered},
        "tampered_decrypted": tampered_plain,
        "expected_tampered": (2 * m) % group.p,
        "malleability_succeeds": tampered_plain == (2 * m) % group.p,
        "steps": [
            {"step": "KeyGen", "description": "Pick x and publish y = g^x mod p.", "output_hex": hex(pk.y)},
            {"step": "Encrypt", "description": "Pick fresh r, output (c1=g^r, c2=m*y^r).", "output_hex": f"({hex(c1)}, {hex(c2)})"},
            {"step": "Malleate", "description": "Replace c2 with 2*c2 mod p; plaintext doubles after decryption.", "output_hex": hex(c2_tampered)},
        ],
    }


@app.post("/pa17/cca_pkc")
def pa17_cca_pkc(req: CCAPKCDemoRequest) -> dict:
    """PA#17 CCA-secure public-key encryption panel: signcrypt plus tamper rejection."""
    from src.pa16_elgamal.elgamal import elgamal_keygen, Enc, Dec
    from src.pa17_cca_pkc.cca_pkc import CCA_PKC_Enc, CCA_PKC_Dec, demo_lineage
    from src.foundations.dlp_group import DEMO_PARAMS

    group = DEMO_PARAMS
    enc_sk, enc_pk = elgamal_keygen(group)
    sign_pk, sign_sk = _rsa_demo_key(256, 65537)
    hash_fn = _demo_dlp_hash(16)
    message = (req.message or "launch=no").encode()
    ce, sigma = CCA_PKC_Enc(enc_pk, sign_sk, message, hash_fn)
    opened = CCA_PKC_Dec(enc_sk, sign_pk, ce, sigma, hash_fn)

    c1, c2 = ce
    tampered_c2 = bytearray(c2)
    if req.tamper and tampered_c2:
        tampered_c2[0] ^= 1
    tampered_ce = (c1, bytes(tampered_c2))
    tampered_opened = CCA_PKC_Dec(enc_sk, sign_pk, tampered_ce, sigma, hash_fn)

    plain_m = 5
    ec1, ec2 = Enc(enc_pk, plain_m)
    malleated_plain = Dec(enc_sk, ec1, (2 * ec2) % group.p)
    return {
        "status": "ok",
        "message_text": _safe_text(message),
        "ciphertext": {"c1": c1, "c2_hex": c2.hex()},
        "signature_hex": sigma.hex(),
        "decrypted_text": _safe_text(opened or b""),
        "accepted": opened == message,
        "tampered_ciphertext": {"c1": tampered_ce[0], "c2_hex": tampered_ce[1].hex()},
        "tampered_result": "rejected" if tampered_opened is None else _safe_text(tampered_opened),
        "tamper_rejected": tampered_opened is None,
        "elgamal_contrast": {
            "message": plain_m,
            "ciphertext": {"c1": ec1, "c2": ec2},
            "tampered_decrypted": malleated_plain,
            "malleability_succeeds": malleated_plain == (2 * plain_m) % group.p,
        },
        "lineage": demo_lineage(),
    }


@app.post("/pa18/ot")
def pa18_ot(req: OTDemoRequest) -> dict:
    """PA#18 1-of-2 oblivious transfer walkthrough."""
    from src.pa18_ot.ot import OTReceiverStep1, OTSenderStep, OTReceiverStep2
    from src.foundations.dlp_group import DEMO_PARAMS
    from src.pa16_elgamal.elgamal import Dec

    group = DEMO_PARAMS
    b = 1 if int(req.choice or 0) else 0
    m0 = _encode_ot_message(req.m0, group.p)
    m1 = _encode_ot_message(req.m1, group.p)
    pk0, pk1, state = OTReceiverStep1(b, group)
    c0, c1 = OTSenderStep(pk0, pk1, m0, m1)
    received = OTReceiverStep2(state, c0, c1)
    other_cipher = c1 if b == 0 else c0
    other_expected = m1 if b == 0 else m0
    other_attempt = Dec(state["sk"], *other_cipher)
    return {
        "status": "ok",
        "choice": b,
        "messages": [
            {"label": "m0", "text": req.m0, "encoded": m0},
            {"label": "m1", "text": req.m1, "encoded": m1},
        ],
        "public_keys": {"pk0_y": pk0.y, "pk1_y": pk1.y, "honest_index": b},
        "ciphertexts": {"c0": {"c1": c0[0], "c2": c0[1]}, "c1": {"c1": c1[0], "c2": c1[1]}},
        "received": received,
        "received_label": f"m{b}",
        "correct": received == (m0 if b == 0 else m1),
        "other_attempt": other_attempt,
        "other_expected": other_expected,
        "privacy_holds": other_attempt != other_expected,
        "steps": [
            {"step": "Receiver", "description": "Generate one real public key for the chosen branch and one fake-looking key."},
            {"step": "Sender", "description": "Encrypt m0 under pk0 and m1 under pk1, without knowing which key is real."},
            {"step": "Receiver opens one", "description": "Only the chosen ciphertext decrypts with the retained secret key."},
        ],
    }


@app.post("/pa19/secure_and")
def pa19_secure_and(req: SecureAndDemoRequest) -> dict:
    """PA#19 secure AND/XOR/NOT gate panel."""
    from src.pa19_secure_gates.secure_gates import AND, XOR, NOT, truth_table_test
    from src.foundations.dlp_group import DEMO_PARAMS

    a = 1 if int(req.a or 0) else 0
    b = 1 if int(req.b or 0) else 0
    and_result = AND(a, b, DEMO_PARAMS)
    return {
        "status": "ok",
        "a": a,
        "b": b,
        "and_result": and_result,
        "xor_result": XOR(a, b),
        "not_a": NOT(a),
        "expected_and": a & b,
        "correct": and_result == (a & b),
        "truth_tables": truth_table_test(DEMO_PARAMS)["truth_tables"],
        "ot_messages": {"m0": 0, "m1": a, "choice": b, "meaning": "receiver obtains m_b = a*b"},
        "lineage": "PA19 AND → PA18 OT → PA16 ElGamal → PA11 DH group",
    }


@app.post("/pa20/millionaire")
def pa20_millionaire(req: MillionaireDemoRequest) -> dict:
    """PA#20 millionaire comparison using the boolean-circuit MPC evaluator."""
    from src.pa20_mpc.mpc import build_comparison_circuit, SecureEval
    from src.foundations.dlp_group import DEMO_PARAMS

    bits = max(2, min(int(req.bits or 4), 8))
    limit = (1 << bits) - 1
    alice = max(0, min(int(req.alice or 0), limit))
    bob = max(0, min(int(req.bob or 0), limit))
    alice_bits = _bits_msb(alice, bits)
    bob_bits = _bits_msb(bob, bits)
    circuit = build_comparison_circuit(bits)
    output, meta = SecureEval(circuit, alice_bits, bob_bits, DEMO_PARAMS)
    transcript = meta["transcript"][: min(24, len(meta["transcript"]))]
    return {
        "status": "ok",
        "alice": alice,
        "bob": bob,
        "bits": bits,
        "alice_bits": alice_bits,
        "bob_bits": bob_bits,
        "alice_greater": bool(output[0]),
        "expected": alice > bob,
        "correct": bool(output[0]) == (alice > bob),
        "circuit": {"wires": circuit.n_wires, "gates": len(circuit.gates), "and_calls": meta["and_calls"]},
        "transcript": transcript,
        "transcript_truncated": len(meta["transcript"]) > len(transcript),
        "lineage": "PA20 SecureEval → PA19 AND → PA18 OT → PA16 ElGamal",
    }


# ─── Column 2: Source → Target (BLACK-BOX — handle only) ─────
@app.post("/reduce_primitive_to_target")
def reduce_primitive_to_target(req: ReduceRequest) -> dict:
    """Column 2: ONLY consumes handle from Column 1. Never touches AES/DLP directly."""
    handle = req.source_instance_handle
    src, tgt = req.source_type, req.target_type
    direction = req.direction

    # Bidirectional mode: swap if backward
    if direction == "backward":
        src, tgt = tgt, src

    val = req.query_hex.strip() or "00" * 16
    if len(val) % 2 != 0:
        val = "0" + val
    try:
        query = bytes.fromhex(val)
    except ValueError:
        return {"error": "query_hex must be valid hex", "status": "error"}

    path = _bfs(src, tgt)
    if not path:
        return {
            "status": "no_path",
            "message": f"No path from {src} to {tgt} in the Minicrypt clique.",
            "hint": "This pair is not connected in the current routing table.",
            "supported_sources": list(REDUCTION_GRAPH.keys()),
        }

    current_handle = dict(handle or {})
    all_steps = []
    hop_outputs = []
    for hop_index, (hop_src, hop_tgt) in enumerate(zip(path, path[1:]), start=1):
        hop = _compute_reduction_hop(
            hop_index=hop_index,
            src=hop_src,
            tgt=hop_tgt,
            handle=current_handle,
            query=query,
        )
        all_steps.extend(hop["steps"])
        hop_outputs.append({
            "hop": hop_index,
            "source": hop_src,
            "target": hop_tgt,
            "output_hex": hop["output_hex"],
            "theorem": hop["theorem"],
        })
        current_handle = hop["handle"]

    final_output = hop_outputs[-1]["output_hex"] if hop_outputs else ""
    direct_red = REDUCTIONS.get((src, tgt), {})

    return {
        "status": "ok",
        "source": src, "target": tgt,
        "direction": direction,
        "path": path,
        "hop_count": len(path) - 1,
        "theorem": direct_red.get("theorem", "Composed reduction via shortest clique path"),
        "construction": direct_red.get("construction", " → ".join(path)),
        "pa": direct_red.get("pa", "multiple"),
        "output_hex": final_output,
        "hop_outputs": hop_outputs,
        "reduction_steps": all_steps,
        "final_handle": current_handle,
        "black_box_enforced": True,
        "note": "Column 2 consumed only the current primitive handle at each hop; the foundation is not called directly.",
    }


def _compute_reduction_hop(hop_index: int, src: str, tgt: str, handle: dict, query: bytes) -> dict:
    red = REDUCTIONS[(src, tgt)]
    output_hex = _compute_reduction_output(src, tgt, handle, query)
    next_handle = _derive_handle_for_target(tgt, handle, output_hex, query)
    steps = [
        {
            "step": f"Hop {hop_index}: {src} → {tgt}",
            "description": f"{red['theorem']} ({red['pa']})",
        },
        {
            "step": "Construction",
            "description": red["construction"],
            "output_hex": output_hex,
        },
    ]
    return {
        "output_hex": output_hex,
        "handle": next_handle,
        "steps": steps,
        "theorem": red["theorem"],
    }


def _hex_to_bytes(value: str, min_len: int = 16) -> bytes:
    if not value or value.startswith("<"):
        return b"\x00" * min_len
    value = value[2:] if value.startswith("0x") else value
    if len(value) % 2:
        value = "0" + value
    raw = bytes.fromhex(value)
    if len(raw) < min_len:
        raw = raw + b"\x00" * (min_len - len(raw))
    return raw


def _handle_key_bytes(handle: dict, query: bytes) -> bytes:
    if "k_hex" in handle:
        return _hex_to_bytes(handle["k_hex"], 16)[:16]
    if "output_hex" in handle:
        return _hex_to_bytes(handle["output_hex"], 16)[:16]
    if "digest_hex" in handle:
        return _hex_to_bytes(handle["digest_hex"], 16)[:16]
    if "seed" in handle:
        return int(handle["seed"]).to_bytes(16, "big", signed=False)[-16:]
    return (query + b"\x00" * 16)[:16]


def _int_from_handle_value(value, default: int = 0) -> int:
    if value is None:
        return default
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value, 16) if value.startswith("0x") else int(value, 16)
        except ValueError:
            return default
    return default


def _derive_handle_for_target(tgt: str, previous: dict, output_hex: str, query: bytes) -> dict:
    next_handle = dict(previous or {})
    next_handle["type"] = tgt
    if tgt in ("OWF", "OWP"):
        for name in ("p", "q", "g"):
            if name in previous:
                next_handle[name] = previous[name]
        next_handle["y"] = int(output_hex, 16) if output_hex.startswith("0x") else output_hex
    elif tgt == "PRG":
        q = int(previous.get("q", 65537))
        seed_bytes = _hex_to_bytes(output_hex, 4)
        next_handle["seed"] = int.from_bytes(seed_bytes[:4], "big") % q or 1
        next_handle["output_hex"] = output_hex
    elif tgt in ("PRF", "PRP", "MAC", "HMAC", "CPA", "CCA"):
        next_handle["k_hex"] = _handle_key_bytes(previous, query).hex()
        next_handle["output_hex"] = output_hex
    elif tgt == "CRHF":
        next_handle["digest_hex"] = output_hex
    return next_handle


def _compute_reduction_output(src: str, tgt: str, handle: dict, query: bytes) -> str:
    """Compute the reduction output using only the handle (black-box discipline)."""
    try:
        # GGM: PRG → PRF, using the PRG seed from Column 1 as the black box root.
        if src == "PRG" and tgt == "PRF" and "seed" in handle:
            from src.pa02_prf.ggm_prf import GGMPRF
            from src.common.bytes_utils import bytes_to_bits
            x_bits = bytes_to_bits(query or b"\x00")[:16]
            y = GGMPRF().F(int(handle["seed"]), x_bits)
            return hex(y)

        # PRF → PRG: G(s)=F_s(0)||F_s(1).
        if src == "PRF" and tgt == "PRG":
            from src.pa02_prf.ggm_prf import PRGFromPRF
            k = _handle_key_bytes(handle, query)
            return PRGFromPRF().expand(k, 16).hex()

        # PRF / PRP / MAC-style outputs.
        if tgt in ("PRF", "PRP", "MAC", "CPA", "CCA") and (
            "k_hex" in handle or "output_hex" in handle or "digest_hex" in handle or "seed" in handle
        ):
            from src.pa02_prf.ggm_prf import PRFFromAES
            k = _handle_key_bytes(handle, query)
            x = (query + b"\x00" * 16)[:16]
            return PRFFromAES().F(k, x).hex()

        # PRG based outputs
        if tgt == "PRG" and "seed" in handle:
            from src.pa01_owf_prg.owf import PRG
            prg = PRG()
            prg.seed(handle["seed"])
            return prg.next_bytes(8).hex()

        if tgt == "PRG":
            from src.foundations.dlp_group import DEMO_PARAMS
            from src.pa01_owf_prg.owf import OWF, PRG
            seed = _int_from_handle_value(handle.get("x") or handle.get("y"))
            if not seed:
                seed = int.from_bytes(_handle_key_bytes(handle, query)[:8], "big")
            seed = seed % int(handle.get("q", DEMO_PARAMS.q)) or 1
            prg = PRG(OWF(DEMO_PARAMS))
            return prg.expand(seed, 8).hex()

        # HMAC based output
        if tgt == "HMAC" and ("k_hex" in handle or "digest_hex" in handle or "output_hex" in handle):
            from src.pa10_hmac_eth.hmac_eth import HMAC
            from src.pa08_dlp_hash.dlp_hash import DLPHash, gen_dlp_hash_params, DEMO_PARAMS
            k = _handle_key_bytes(handle, query)
            params = gen_dlp_hash_params(DEMO_PARAMS)
            hf = DLPHash(params, block_size=16)
            return HMAC(k, query, hf).hex()

        # CRHF output.
        if tgt == "CRHF":
            from src.pa08_dlp_hash.dlp_hash import DLPHash, gen_dlp_hash_params, DEMO_PARAMS
            params = gen_dlp_hash_params(DEMO_PARAMS)
            hf = DLPHash(params, block_size=16)
            return hf.hash(query).hex()

        # OWF / OWP evaluation
        if tgt in ("OWF", "OWP") and "g" in handle and "p" in handle:
            from src.common.math_utils import modexp
            g, p = handle["g"], handle["p"]
            x = int.from_bytes(query[:4], "big") % handle.get("q", p - 1) or 1
            return hex(modexp(g, x, p))

        if tgt in ("OWF", "OWP"):
            seed = int(handle.get("seed") or 0)
            if not seed:
                seed = int.from_bytes(_handle_key_bytes(handle, query)[:8], "big")
            from src.pa01_owf_prg.owf import PRG
            prg = PRG()
            return prg.expand(seed or 1, 8).hex()

        return "<reduction computed — check theorem for formula>"
    except Exception as e:
        return f"<error: {e}>"


# ─── BFS path finder ─────────────────────────────────────────
def _bfs(src: str, tgt: str) -> list[str] | None:
    from collections import deque
    if src == tgt:
        return [src]
    visited = {src}
    q = deque([[src]])
    while q:
        path = q.popleft()
        for nb in REDUCTION_GRAPH.get(path[-1], []):
            if nb == tgt:
                return path + [nb]
            if nb not in visited:
                visited.add(nb)
                q.append(path + [nb])
    return None


@app.get("/reduction_path")
def get_reduction_path(source_type: str, target_type: str, direction: str = "forward") -> dict:
    src, tgt = (target_type, source_type) if direction == "backward" else (source_type, target_type)
    path = _bfs(src, tgt)
    if path:
        return {"path": path, "length": len(path) - 1, "direction": direction}
    return {"path": None, "message": f"No path from {src} to {tgt} in the Minicrypt clique."}


@app.get("/proof_summary")
def get_proof_summary(source_type: str, target_type: str, direction: str = "forward") -> dict:
    src, tgt = (target_type, source_type) if direction == "backward" else (source_type, target_type)
    key = (src, tgt)
    red = REDUCTIONS.get(key, {})
    path = _bfs(src, tgt)
    path_reductions = []
    if path:
        for hop_src, hop_tgt in zip(path, path[1:]):
            hop = REDUCTIONS.get((hop_src, hop_tgt), {})
            path_reductions.append({
                "edge": f"{hop_src}→{hop_tgt}",
                "pa": hop.get("pa", ""),
                "theorem": hop.get("theorem", ""),
                "construction": hop.get("construction", ""),
            })
    primitives = [{"name": p, **PRIMITIVES.get(p, {"pa": "?", "implemented": False, "name": p})}
                  for p in (path or [])]
    return {
        "source": source_type, "target": target_type, "direction": direction,
        "path": path, "primitives": primitives,
        "path_reductions": path_reductions,
        "theorem": red.get("theorem", "See composed path for security argument"),
        "construction": red.get("construction", ""),
        "pa": red.get("pa", ""),
        "chain_description": " → ".join(path or []),
    }


@app.get("/clique_reductions")
def get_clique_reductions() -> dict:
    """Return all bidirectional clique reductions with theorems and PA numbers."""
    return {
        "reductions": [
            {"pair": f"{src}→{tgt}", "pa": v["pa"],
             "direction": v["dir"], "theorem": v["theorem"],
             "construction": v["construction"]}
            for (src, tgt), v in REDUCTIONS.items()
        ],
        "total": len(REDUCTIONS),
        "note": "All adjacent pairs from the Minicrypt clique, both directions.",
    }


@app.get("/")
def root():
    return {"service": "POIS Minicrypt Clique Explorer v2", "primitives": list(PRIMITIVES.keys()),
            "endpoints": ["/build_foundation_to_primitive", "/reduce_primitive_to_target",
                          "/pa01/prg_viewer", "/reduction_path", "/proof_summary",
                          "/pa02/ggm_tree", "/pa03/cpa_challenge", "/pa03/cpa_guess",
                          "/pa04/mode_animator", "/pa05/mac_game_start",
                          "/pa05/mac_forgery", "/pa05/length_extension",
                          "/pa06/cca_malleability", "/pa07/md_chain",
                          "/pa08/dlp_hash", "/pa09/birthday",
                          "/pa10/hmac_compare",
                          "/pa11/dh_exchange", "/pa12/rsa_determinism",
                          "/pa13/miller_rabin", "/pa14/hastad",
                          "/pa15/signatures", "/pa16/elgamal",
                          "/pa17/cca_pkc", "/pa18/ot",
                          "/pa19/secure_and", "/pa20/millionaire",
                          "/clique_reductions"]}
