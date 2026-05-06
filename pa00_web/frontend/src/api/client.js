const API_BASE = "http://localhost:8000";

export async function listPrimitives() {
  const res = await fetch(`${API_BASE}/primitives`);
  return res.json();
}

export async function buildFoundationToPrimitive({ foundation, source_primitive, seed_or_key_hex }) {
  const res = await fetch(`${API_BASE}/build_foundation_to_primitive`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ foundation, source_primitive, seed_or_key_hex }),
  });
  return res.json();
}

export async function reducePrimitiveToTarget({
  source_type, target_type, query_hex, direction = "forward", source_instance_handle = {}
}) {
  const res = await fetch(`${API_BASE}/reduce_primitive_to_target`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ source_type, target_type, query_hex, direction, source_instance_handle }),
  });
  return res.json();
}

export async function getReductionPath(source_type, target_type, direction = "forward") {
  const res = await fetch(
    `${API_BASE}/reduction_path?source_type=${source_type}&target_type=${target_type}&direction=${direction}`
  );
  return res.json();
}

export async function getProofSummary(source_type, target_type, direction = "forward") {
  const res = await fetch(
    `${API_BASE}/proof_summary?source_type=${source_type}&target_type=${target_type}&direction=${direction}`
  );
  return res.json();
}

export async function runPrgViewer({ seed_hex, length_bytes, run_tests = false }) {
  const res = await fetch(`${API_BASE}/pa01/prg_viewer`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ seed_hex, length_bytes, run_tests }),
  });
  return res.json();
}

export async function runGgmTree({ key_hex, query_bits, depth }) {
  const res = await fetch(`${API_BASE}/pa02/ggm_tree`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ key_hex, query_bits, depth }),
  });
  return res.json();
}

export async function startCpaChallenge({ m0, m1, reuse_nonce = false }) {
  const res = await fetch(`${API_BASE}/pa03/cpa_challenge`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ m0, m1, reuse_nonce }),
  });
  return res.json();
}

export async function submitCpaGuess({ challenge_id, guess }) {
  const res = await fetch(`${API_BASE}/pa03/cpa_guess`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ challenge_id, guess }),
  });
  return res.json();
}

export async function runModeAnimator({ mode, message, flip_enabled = true, flip_block, flip_byte, reuse_iv = false }) {
  const res = await fetch(`${API_BASE}/pa04/mode_animator`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ mode, message, flip_enabled, flip_block, flip_byte, reuse_iv }),
  });
  return res.json();
}

export async function startMacGame({ num_messages = 8 }) {
  const res = await fetch(`${API_BASE}/pa05/mac_game_start`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ num_messages }),
  });
  return res.json();
}

export async function submitMacForgery({ game_id, message, tag_hex }) {
  const res = await fetch(`${API_BASE}/pa05/mac_forgery`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ game_id, message, tag_hex }),
  });
  return res.json();
}

export async function runLengthExtension({ message, extension }) {
  const res = await fetch(`${API_BASE}/pa05/length_extension`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ message, extension }),
  });
  return res.json();
}

export async function runCcaMalleability({ message, flip_byte }) {
  const res = await fetch(`${API_BASE}/pa06/cca_malleability`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ message, flip_byte }),
  });
  return res.json();
}

export async function runMdChain({ message, block_size }) {
  const res = await fetch(`${API_BASE}/pa07/md_chain`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ message, block_size }),
  });
  return res.json();
}

export async function runDlpHash({ message, block_size }) {
  const res = await fetch(`${API_BASE}/pa08/dlp_hash`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ message, block_size }),
  });
  return res.json();
}

export async function runBirthdayAttack({ n_bits, max_evaluations }) {
  const res = await fetch(`${API_BASE}/pa09/birthday`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ n_bits, max_evaluations }),
  });
  return res.json();
}

export async function runHmacCompare({ message, extension, hash_type = "dlp" }) {
  const res = await fetch(`${API_BASE}/pa10/hmac_compare`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ message, extension, hash_type }),
  });
  return res.json();
}

export async function runDhExchange({ a, b, enable_eve = false }) {
  const res = await fetch(`${API_BASE}/pa11/dh_exchange`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ a, b, enable_eve }),
  });
  return res.json();
}

export async function runRsaDeterminism({ message }) {
  const res = await fetch(`${API_BASE}/pa12/rsa_determinism`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ message }),
  });
  return res.json();
}

export async function runMillerRabin({ n, rounds }) {
  const res = await fetch(`${API_BASE}/pa13/miller_rabin`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ n, rounds }),
  });
  return res.json();
}

export async function runHastad({ message, use_padding = false }) {
  const res = await fetch(`${API_BASE}/pa14/hastad`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ message, use_padding }),
  });
  return res.json();
}

export async function runSignatures({ message, tamper = true }) {
  const res = await fetch(`${API_BASE}/pa15/signatures`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ message, tamper }),
  });
  return res.json();
}

export async function runElGamal({ message }) {
  const res = await fetch(`${API_BASE}/pa16/elgamal`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ message }),
  });
  return res.json();
}

export async function runCcaPkc({ message, tamper = true }) {
  const res = await fetch(`${API_BASE}/pa17/cca_pkc`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ message, tamper }),
  });
  return res.json();
}

export async function runOtDemo({ m0, m1, choice }) {
  const res = await fetch(`${API_BASE}/pa18/ot`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ m0, m1, choice }),
  });
  return res.json();
}

export async function runSecureAnd({ a, b }) {
  const res = await fetch(`${API_BASE}/pa19/secure_and`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ a, b }),
  });
  return res.json();
}

export async function runMillionaire({ alice, bob, bits }) {
  const res = await fetch(`${API_BASE}/pa20/millionaire`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ alice, bob, bits }),
  });
  return res.json();
}
