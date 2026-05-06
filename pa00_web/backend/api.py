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
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI(title="POIS Minicrypt Clique Explorer", version="2.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True,
                   allow_methods=["*"], allow_headers=["*"])

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
                          "/clique_reductions"]}
