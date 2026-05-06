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
