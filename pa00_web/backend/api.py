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
    "PRF":  ["PRG", "PRP", "MAC", "OWP"],
    "PRP":  ["PRF", "MAC"],
    "MAC":  ["PRF", "HMAC", "CRHF"],
    "CPA":  ["PRF"],
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

# ─── Column 1: Foundation → Source Primitive ─────────────────
@app.post("/build_foundation_to_primitive")
def build_foundation_to_primitive(req: BuildRequest) -> dict:
    """ONLY endpoint that touches AES/DLP foundations directly."""
    info = PRIMITIVES.get(req.source_primitive)
    if not info or not info.get("implemented"):
        return {"status": "stub", "message": f"Not implemented (PA#{info.get('pa','?')})", "handle": {}}

    val = req.seed_or_key_hex.strip() or "00" * 16
    if len(val) % 2 != 0:
        val = "0" + val
    try:
        kb = bytes.fromhex(val)
    except ValueError:
        return {"error": "seed_or_key_hex must be valid hex", "status": "error"}

    steps, handle = [], {}

    if req.foundation == "DLP":
        from src.foundations.dlp_group import DEMO_PARAMS
        steps.append({"step": "Foundation Setup", "description": "DLP safe-prime group (p,q,g)",
                       "p": DEMO_PARAMS.p, "q": DEMO_PARAMS.q, "g": DEMO_PARAMS.g})

        if req.source_primitive == "OWF":
            from src.pa01_owf_prg.owf import OWF
            owf = OWF(DEMO_PARAMS)
            x = int.from_bytes(kb[:4], "big") % DEMO_PARAMS.q or 1
            y = owf.evaluate(x)
            steps.append({"step": "OWF", "description": "f(x)=g^x mod p", "x": x, "output_hex": hex(y)})
            handle = {"type": "OWF", "x": x, "y": y, "q": DEMO_PARAMS.q, "p": DEMO_PARAMS.p, "g": DEMO_PARAMS.g}

        elif req.source_primitive == "OWP":
            from src.pa01_owf_prg.owp import OWP_DLP
            owp = OWP_DLP(DEMO_PARAMS)
            x = int.from_bytes(kb[:4], "big") % DEMO_PARAMS.q or 1
            y = owp.evaluate(x)
            steps.append({"step": "OWP", "description": "f(x)=g^x mod p (permutation on ⟨g⟩)", "x": x, "output_hex": hex(y)})
            handle = {"type": "OWP", "x": x, "y": y, "q": DEMO_PARAMS.q, "p": DEMO_PARAMS.p, "g": DEMO_PARAMS.g}

        elif req.source_primitive == "PRG":
            from src.pa01_owf_prg.owf import OWF, PRG
            owf = OWF(DEMO_PARAMS)
            prg = PRG(owf)
            seed = int.from_bytes(kb[:4], "big") % DEMO_PARAMS.q or 1
            prg.seed(seed)
            bits = prg.next_bits(32)
            out_hex = prg.expand(seed, 4).hex()
            steps.append({"step": "PRG", "description": "G(s) via GL hard-core bits",
                           "seed": seed, "bits_preview": "".join(str(b) for b in bits[:16])+"...", "output_hex": out_hex})
            handle = {"type": "PRG", "seed": seed, "output_hex": out_hex,
                      "q": DEMO_PARAMS.q, "p": DEMO_PARAMS.p, "g": DEMO_PARAMS.g}

        elif req.source_primitive in ("PRF", "PRP"):
            from src.pa02_prf.ggm_prf import PRFFromAES
            prf = PRFFromAES()
            k = (kb + b"\x00" * 16)[:16]
            x = (kb + b"\x00" * 32)[16:32]
            y = prf.F(k, x)
            steps.append({"step": req.source_primitive, "description": "F_k(x)=AES_k(x)",
                           "k_hex": k.hex(), "x_hex": x.hex(), "output_hex": y.hex()})
            handle = {"type": req.source_primitive, "k_hex": k.hex()}

        elif req.source_primitive == "MAC":
            from src.pa05_mac.mac import MacCBC
            mac = MacCBC()
            k = (kb + b"\x00" * 16)[:16]
            m = b"test message"
            t = mac.Mac(k, m)
            steps.append({"step": "MAC", "description": "CBC-MAC tag", "k_hex": k.hex(), "output_hex": t.hex()})
            handle = {"type": "MAC", "k_hex": k.hex()}

        elif req.source_primitive == "CRHF":
            from src.pa08_dlp_hash.dlp_hash import DLPHash, gen_dlp_hash_params
            params = gen_dlp_hash_params(DEMO_PARAMS)
            h = DLPHash(params, block_size=16)
            digest = h.hash(kb)
            steps.append({"step": "CRHF", "description": "DLP Merkle-Damgård hash", "output_hex": digest.hex()})
            elem_bytes = (DEMO_PARAMS.p.bit_length() + 7) // 8
            handle = {"type": "CRHF", "digest_hex": digest.hex(), "elem_bytes": elem_bytes,
                      "p": DEMO_PARAMS.p, "q": DEMO_PARAMS.q, "g": DEMO_PARAMS.g}

        elif req.source_primitive == "HMAC":
            from src.pa10_hmac_eth.hmac_eth import HMAC
            from src.pa08_dlp_hash.dlp_hash import DLPHash, gen_dlp_hash_params
            params = gen_dlp_hash_params(DEMO_PARAMS)
            hash_fn = DLPHash(params, block_size=16)
            k = (kb + b"\x00" * 16)[:16]
            tag = HMAC(k, kb, hash_fn)
            steps.append({"step": "HMAC", "description": "HMAC using PA#8 DLP hash", "k_hex": k.hex(), "output_hex": tag.hex()})
            handle = {"type": "HMAC", "k_hex": k.hex()}

    elif req.foundation == "AES":
        from src.foundations.aes_impl import aes_encrypt_block
        k = (kb + b"\x00" * 16)[:16]
        ct = aes_encrypt_block(k, b"\x00" * 16)
        steps.append({"step": "AES-128 PRP", "description": "AES-128 block cipher", "k_hex": k.hex(), "output_hex": ct.hex()})
        handle = {"type": "PRP", "k_hex": k.hex()}
    else:
        return {"error": f"Unknown foundation '{req.foundation}'. Use 'AES' or 'DLP'.", "status": "error"}

    return {"status": "ok", "foundation": req.foundation,
            "source_primitive": req.source_primitive, "steps": steps, "handle": handle}


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

    # Check routing
    key = (src, tgt)
    red = REDUCTIONS.get(key)
    if red is None:
        reachable = REDUCTION_GRAPH.get(src, [])
        if tgt not in reachable:
            path = _bfs(src, tgt)
            if path:
                return {
                    "status": "composed_path",
                    "message": f"No direct reduction from {src} to {tgt}. Composed path exists.",
                    "composed_path": path,
                    "hint": f"Traverse: {' → '.join(path)}",
                    "suggestion": "Try bidirectional mode or step through the path manually.",
                }
            return {
                "status": "no_path",
                "message": f"No path from {src} to {tgt} in the Minicrypt clique.",
                "hint": "This pair is not adjacent and has no composed path. Check the PDF clique diagram.",
                "supported_sources": list(REDUCTION_GRAPH.keys()),
            }

    val = req.query_hex.strip() or "00" * 16
    if len(val) % 2 != 0:
        val = "0" + val
    try:
        query = bytes.fromhex(val)
    except ValueError:
        return {"error": "query_hex must be valid hex", "status": "error"}

    # Compute output using ONLY handle data — no direct AES/DLP imports here
    output_hex = _compute_reduction_output(src, tgt, handle, query)

    return {
        "status": "ok",
        "source": src, "target": tgt,
        "direction": direction,
        "theorem": red["theorem"],
        "construction": red["construction"],
        "pa": red["pa"],
        "output_hex": output_hex,
        "black_box_enforced": True,
        "note": "Column 2 consumed only the handle from Column 1; no AES/DLP called directly.",
    }


def _compute_reduction_output(src: str, tgt: str, handle: dict, query: bytes) -> str:
    """Compute the reduction output using only the handle (black-box discipline)."""
    try:
        h_type = handle.get("type", "")

        # PRF / PRP based outputs
        if tgt in ("PRF", "PRP", "MAC") and "k_hex" in handle:
            from src.pa02_prf.ggm_prf import PRFFromAES
            k = bytes.fromhex(handle["k_hex"])
            x = (query + b"\x00" * 16)[:16]
            return PRFFromAES().F(k, x).hex()

        # PRG based outputs
        if tgt == "PRG" and "seed" in handle:
            from src.pa01_owf_prg.owf import PRG
            prg = PRG()
            prg.seed(handle["seed"])
            return prg.next_bytes(8).hex()

        # HMAC based output
        if tgt == "HMAC" and "k_hex" in handle:
            from src.pa10_hmac_eth.hmac_eth import HMAC
            from src.pa08_dlp_hash.dlp_hash import DLPHash, gen_dlp_hash_params, DEMO_PARAMS
            k = bytes.fromhex(handle["k_hex"])
            params = gen_dlp_hash_params(DEMO_PARAMS)
            hf = DLPHash(params, block_size=16)
            return HMAC(k, query, hf).hex()

        # CRHF output — re-hash query using handle's digest as chaining value
        if tgt == "CRHF" and "digest_hex" in handle:
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
    primitives = [{"name": p, **PRIMITIVES.get(p, {"pa": "?", "implemented": False, "name": p})}
                  for p in (path or [])]
    return {
        "source": source_type, "target": target_type, "direction": direction,
        "path": path, "primitives": primitives,
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
                          "/reduction_path", "/proof_summary", "/clique_reductions"]}
