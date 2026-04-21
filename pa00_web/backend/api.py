"""
PA#0 Backend — FastAPI server exposing the Minicrypt Clique Web Explorer API.

Endpoints:
  POST /build_foundation_to_primitive
  POST /reduce_primitive_to_target
  GET  /reduction_path
  GET  /proof_summary

All crypto calls delegate to PA#1–PA#20 modules.
Stubs return placeholder data for unimplemented primitives.
"""

from __future__ import annotations
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Any

app = FastAPI(title="POIS Minicrypt Clique Explorer", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─────────────────────────────────────────────────────────────
#  Primitive registry: maps name → status and PA number
# ─────────────────────────────────────────────────────────────

PRIMITIVES = {
    "OWF":  {"pa": 1,  "implemented": True,  "name": "One-Way Function"},
    "PRG":  {"pa": 1,  "implemented": True,  "name": "Pseudo-Random Generator"},
    "PRF":  {"pa": 2,  "implemented": True,  "name": "Pseudo-Random Function"},
    "PRP":  {"pa": 2,  "implemented": True,  "name": "Pseudo-Random Permutation (AES)"},
    "CPA":  {"pa": 3,  "implemented": True,  "name": "CPA-Secure Encryption"},
    "MAC":  {"pa": 5,  "implemented": True,  "name": "Message Authentication Code"},
    "CCA":  {"pa": 6,  "implemented": True,  "name": "CCA-Secure Encryption"},
    "CRHF": {"pa": 8,  "implemented": True,  "name": "Collision-Resistant Hash Function"},
    "HMAC": {"pa": 10, "implemented": True,  "name": "HMAC"},
    "OTP":  {"pa": 3,  "implemented": True,  "name": "One-Time Pad"},
    "OWP":  {"pa": 1,  "implemented": True,  "name": "One-Way Permutation"},
}

# Reduction routing table (source → [reachable targets])
REDUCTION_GRAPH = {
    "OWF":  ["PRG", "OWP"],
    "PRG":  ["PRF", "OWF"],
    "PRF":  ["PRP", "MAC", "PRG"],
    "PRP":  ["PRF", "MAC"],
    "OWP":  ["PRG", "PRF"],
    "MAC":  ["PRF"],
    "CRHF": ["HMAC", "MAC"],
    "HMAC": ["MAC", "CRHF"],
}

# Reduction descriptions
REDUCTION_DESCRIPTIONS = {
    ("OWF", "PRG"): {
        "direction": "forward",
        "construction": "Goldreich-Levin hard-core bit extraction",
        "theorem": "If OWF exists, PRG exists (Hastad-Impagliazzo-Levin-Luby theorem)",
        "pa": "PA#1",
        "steps": [
            "Pick safe-prime group (p, q, g)",
            "For i=1..ℓ: extract hard-core bit b_i = ⟨s_{i-1}, r⟩ mod 2",
            "Advance state: s_i = g^{s_{i-1}} mod p",
            "Output b_1 ∥ ... ∥ b_ℓ",
        ],
    },
    ("PRG", "OWF"): {
        "direction": "backward",
        "construction": "f(s) = G(s) is one-way if G is a PRG",
        "theorem": "PRG implies OWF (trivial reduction)",
        "pa": "PA#1",
        "steps": [
            "Given G(s) = PRG output",
            "f(s) = G(s) is one-way: inverting f requires inverting G",
            "Distinguisher for G → inverter for f",
        ],
    },
    ("PRG", "PRF"): {
        "direction": "forward",
        "construction": "GGM tree construction",
        "theorem": "GGM: PRG secure ⟹ GGM-PRF is a PRF (Goldreich-Goldwasser-Micali)",
        "pa": "PA#2",
        "steps": [
            "Root: k = seed",
            "For each query bit x_i: traverse left (G_0) or right (G_1)",
            "Output leaf node value",
        ],
    },
    ("PRF", "MAC"): {
        "direction": "forward",
        "construction": "Mac(k, m) = F_k(m)",
        "theorem": "PRF implies MAC (direct reduction: MAC forgery → PRF distinguisher)",
        "pa": "PA#5",
        "steps": [
            "Key: k ← {0,1}^n",
            "Tag: t = F_k(m)",
            "Verify: F_k(m) == t",
        ],
    },
    ("CRHF", "HMAC"): {
        "direction": "forward",
        "construction": "HMAC(k,m) = H((k⊕opad) ∥ H((k⊕ipad) ∥ m))",
        "theorem": "CRHF ⟹ HMAC is a secure MAC",
        "pa": "PA#10",
        "steps": [
            "ipad = 0x36^{block_size}, opad = 0x5C^{block_size}",
            "Inner: H((k⊕ipad) ∥ m)",
            "Outer: H((k⊕opad) ∥ inner)",
        ],
    },
    ("CRHF", "OWP"): {
        "error": True,
        "message": "No known direct reduction from CRHF to OWP exists in the Minicrypt clique.",
        "hint": "Try: CRHF → HMAC → MAC → PRF → PRG → OWF → OWP (composed path)",
    },
}


# ─────────────────────────────────────────────────────────────
#  Request/Response Models
# ─────────────────────────────────────────────────────────────

class BuildRequest(BaseModel):
    foundation: str          # "AES" or "DLP"
    source_primitive: str    # e.g. "PRG"
    seed_or_key_hex: str     # hex string


class ReduceRequest(BaseModel):
    source_type: str
    target_type: str
    query_hex: str
    direction: str = "forward"
    source_instance_handle: dict = {}


class PathRequest(BaseModel):
    source_type: str
    target_type: str
    direction: str = "forward"


class ProofRequest(BaseModel):
    source_type: str
    target_type: str
    direction: str = "forward"


# ─────────────────────────────────────────────────────────────
#  Helper: check if primitive is implemented
# ─────────────────────────────────────────────────────────────

def _check_primitive(name: str) -> dict:
    info = PRIMITIVES.get(name)
    if info is None:
        return {"implemented": False, "pa": "?", "name": name}
    return info


# ─────────────────────────────────────────────────────────────
#  Endpoints
# ─────────────────────────────────────────────────────────────

@app.get("/")
def root():
    return {"service": "POIS Minicrypt Clique Explorer", "version": "1.0.0",
            "primitives": list(PRIMITIVES.keys())}


@app.get("/primitives")
def list_primitives():
    return {"primitives": PRIMITIVES}


@app.post("/build_foundation_to_primitive")
def build_foundation_to_primitive(req: BuildRequest) -> dict:
    """Build from foundation to the source primitive.

    Returns intermediate steps and output handle for Column 1 of PA#0.
    """
    info = _check_primitive(req.source_primitive)
    if not info.get("implemented"):
        return {
            "status": "stub",
            "message": f"Not implemented yet (due: PA#{info.get('pa', '?')})",
            "source_primitive": req.source_primitive,
        }

    try:
        key_bytes = bytes.fromhex(req.seed_or_key_hex.strip() or "00" * 16)
    except ValueError:
        raise HTTPException(400, "seed_or_key_hex must be a valid hex string")

    steps = []
    handle = {}

    if req.foundation == "DLP":
        from src.foundations.dlp_group import DEMO_PARAMS
        steps.append({
            "step": "Foundation Setup",
            "description": "Load DLP safe-prime group (p, q, g)",
            "p": DEMO_PARAMS.p, "q": DEMO_PARAMS.q, "g": DEMO_PARAMS.g,
        })

        if req.source_primitive == "OWF":
            from src.pa01_owf_prg.owf import OWF
            owf = OWF(DEMO_PARAMS)
            seed_int = int.from_bytes(key_bytes[:4], "big") % DEMO_PARAMS.q or 1
            y = owf.evaluate(seed_int)
            steps.append({
                "step": "OWF Evaluation",
                "description": f"f(x) = g^x mod p",
                "x": seed_int, "y": y,
            })
            handle = {"type": "OWF", "x": seed_int, "y": y}

        elif req.source_primitive == "PRG":
            from src.pa01_owf_prg.owf import PRG, OWF
            owf = OWF(DEMO_PARAMS)
            prg = PRG(owf)
            seed_int = int.from_bytes(key_bytes[:4], "big") % DEMO_PARAMS.q or 1
            prg.seed(seed_int)
            bits = prg.next_bits(32)
            steps.append({
                "step": "PRG Expansion",
                "description": "G(s) via hard-core bit extraction",
                "seed": seed_int,
                "output_bits": "".join(str(b) for b in bits[:16]) + "...",
                "output_hex": prg.expand(seed_int, 4).hex(),
            })
            handle = {"type": "PRG", "seed": seed_int}

        elif req.source_primitive in ("PRF", "PRP"):
            from src.pa02_prf.ggm_prf import PRFFromAES
            prf = PRFFromAES()
            k = (key_bytes + b"\x00" * 16)[:16]
            x = (key_bytes + b"\x00" * 16)[16:32] or b"\x01" * 16
            y = prf.F(k, x[:16])
            steps.append({
                "step": f"{req.source_primitive} Evaluation",
                "description": f"F_k(x) = AES_k(x)",
                "k_hex": k.hex(), "x_hex": x[:16].hex(), "y_hex": y.hex(),
            })
            handle = {"type": req.source_primitive, "k_hex": k.hex()}

    elif req.foundation == "AES":
        from src.foundations.aes_impl import aes_encrypt_block
        k = (key_bytes + b"\x00" * 16)[:16]
        block = b"\x00" * 16
        ct = aes_encrypt_block(k, block)
        steps.append({
            "step": "AES Foundation",
            "description": "AES-128 block cipher (PRP)",
            "key_hex": k.hex(),
            "plaintext_hex": block.hex(),
            "ciphertext_hex": ct.hex(),
        })
        handle = {"type": "AES-PRP", "k_hex": k.hex()}
    else:
        raise HTTPException(400, f"Unknown foundation: {req.foundation}. Use 'AES' or 'DLP'.")

    return {"status": "ok", "foundation": req.foundation,
            "source_primitive": req.source_primitive, "steps": steps, "handle": handle}


@app.post("/reduce_primitive_to_target")
def reduce_primitive_to_target(req: ReduceRequest) -> dict:
    """Reduce from source primitive to target primitive (Column 2 of PA#0)."""
    info = _check_primitive(req.target_type)
    if not info.get("implemented"):
        return {
            "status": "stub",
            "message": f"Not implemented yet (due: PA#{info.get('pa', '?')})",
            "target": req.target_type,
        }

    key = (req.source_type, req.target_type)
    reduction = REDUCTION_DESCRIPTIONS.get(key)

    if reduction is None:
        # Check if reachable
        reachable = REDUCTION_GRAPH.get(req.source_type, [])
        if req.target_type not in reachable:
            return {
                "status": "no_path",
                "message": f"No known direct reduction from {req.source_type} to {req.target_type}.",
                "hint": "Check /reduction_path for composed paths.",
            }

    if reduction and reduction.get("error"):
        return {"status": "error", "message": reduction["message"], "hint": reduction.get("hint")}

    try:
        query = bytes.fromhex(req.query_hex.strip() or "00" * 16)
    except ValueError:
        raise HTTPException(400, "query_hex must be valid hex")

    steps = reduction.get("steps", []) if reduction else []
    construction = reduction.get("construction", "See PA documentation") if reduction else ""
    theorem = reduction.get("theorem", "") if reduction else ""
    pa = reduction.get("pa", "N/A") if reduction else "N/A"

    # Compute actual output
    output_hex = None
    try:
        if req.target_type == "PRG":
            from src.pa01_owf_prg.owf import PRG
            prg = PRG()
            prg.seed(int.from_bytes(query[:4], "big") % prg.owf.q or 1)
            output_hex = prg.next_bytes(8).hex()
        elif req.target_type in ("PRF", "MAC"):
            from src.pa02_prf.ggm_prf import PRFFromAES
            prf = PRFFromAES()
            k = req.source_instance_handle.get("k_hex")
            k_bytes = bytes.fromhex(k) if k else b"\x00" * 16
            x = (query + b"\x00" * 16)[:16]
            output_hex = prf.F(k_bytes, x).hex()
        elif req.target_type == "HMAC":
            from src.pa10_hmac_eth.hmac_eth import HMAC
            from src.pa08_dlp_hash.dlp_hash import gen_dlp_hash_params, DLPHash, DEMO_PARAMS
            params = gen_dlp_hash_params(DEMO_PARAMS)
            hash_fn = DLPHash(params, block_size=16)
            k = req.source_instance_handle.get("k_hex")
            k_bytes = bytes.fromhex(k) if k else b"\x00" * 16
            output_hex = HMAC(k_bytes, query, hash_fn).hex()
    except Exception as e:
        output_hex = f"<error: {e}>"

    return {
        "status": "ok",
        "source": req.source_type,
        "target": req.target_type,
        "construction": construction,
        "theorem": theorem,
        "pa": pa,
        "reduction_steps": steps,
        "output_hex": output_hex,
    }


@app.get("/reduction_path")
def get_reduction_path(source_type: str, target_type: str, direction: str = "forward") -> dict:
    """Return a path from source_type to target_type in the Minicrypt clique."""
    # BFS to find shortest path
    from collections import deque
    if source_type == target_type:
        return {"path": [source_type], "length": 0}

    visited = {source_type}
    queue = deque([[source_type]])
    while queue:
        path = queue.popleft()
        current = path[-1]
        for neighbor in REDUCTION_GRAPH.get(current, []):
            if neighbor == target_type:
                full_path = path + [neighbor]
                return {"path": full_path, "length": len(full_path) - 1}
            if neighbor not in visited:
                visited.add(neighbor)
                queue.append(path + [neighbor])

    return {"path": None, "message": f"No path from {source_type} to {target_type}"}


@app.get("/proof_summary")
def get_proof_summary(source_type: str, target_type: str, direction: str = "forward") -> dict:
    """Return theorem names and security reduction statements for the given pair."""
    key = (source_type, target_type)
    reduction = REDUCTION_DESCRIPTIONS.get(key, {})
    path_result = get_reduction_path(source_type, target_type, direction)

    primitives_in_path = []
    for p in (path_result.get("path") or []):
        info = PRIMITIVES.get(p, {})
        primitives_in_path.append({
            "name": p,
            "full_name": info.get("name", p),
            "pa": info.get("pa", "?"),
            "implemented": info.get("implemented", False),
        })

    return {
        "source": source_type,
        "target": target_type,
        "direction": direction,
        "path": path_result.get("path"),
        "primitives": primitives_in_path,
        "theorem": reduction.get("theorem", "See reduction path for composed security proof"),
        "construction": reduction.get("construction", ""),
        "reduction_steps": reduction.get("steps", []),
        "pa": reduction.get("pa", ""),
        "chain_description": " → ".join(path_result.get("path") or []),
    }
