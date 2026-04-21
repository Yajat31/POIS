import { useState, useCallback } from "react";
import {
  buildFoundationToPrimitive,
  reducePrimitiveToTarget,
  getReductionPath,
  getProofSummary,
} from "./api/client.js";

const FOUNDATIONS = ["DLP", "AES"];
const PRIMITIVES = ["OWF", "PRG", "PRF", "PRP", "MAC", "CCA", "CRHF", "HMAC", "OWP"];

function FoundationToggle({ value, onChange }) {
  return (
    <div className="foundation-bar">
      <span className="foundation-label">Foundation</span>
      {FOUNDATIONS.map((f) => (
        <button
          key={f}
          id={`foundation-${f}`}
          className={`foundation-btn ${value === f ? "active" : ""}`}
          onClick={() => onChange(f)}
        >
          {f === "AES" ? "AES-128 (PRP)" : "DLP (g^x mod p)"}
        </button>
      ))}
    </div>
  );
}

function PrimitiveSelect({ id, label, value, onChange }) {
  return (
    <div className="select-wrapper">
      <label className="select-label">{label}</label>
      <select id={id} className="styled-select" value={value} onChange={(e) => onChange(e.target.value)}>
        {PRIMITIVES.map((p) => (
          <option key={p} value={p}>{p}</option>
        ))}
      </select>
    </div>
  );
}

function StepList({ steps }) {
  if (!steps || steps.length === 0) return null;
  return (
    <div className="steps-container">
      {steps.map((s, i) => (
        <div key={i} className="step-item">
          {typeof s === "string" ? (
            <div className="step-desc">{s}</div>
          ) : (
            <>
              <div className="step-title">{s.step || s.gate || `Step ${i + 1}`}</div>
              {s.description && <div className="step-desc">{s.description}</div>}
              {s.output_hex && <div className="step-value">→ {s.output_hex}</div>}
              {s.y !== undefined && <div className="step-value">f(x) = {String(s.y)}</div>}
            </>
          )}
        </div>
      ))}
    </div>
  );
}

function StubCard({ message }) {
  return <div className="stub-card">⚠ {message}</div>;
}

function BuildPanel({ foundation, onHandle }) {
  const [srcPrimitive, setSrcPrimitive] = useState("PRG");
  const [seedHex, setSeedHex] = useState("deadbeef1234");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);

  const handleBuild = useCallback(async () => {
    setLoading(true);
    try {
      const r = await buildFoundationToPrimitive({
        foundation,
        source_primitive: srcPrimitive,
        seed_or_key_hex: seedHex || "00000000000000000000000000000000",
      });
      setResult(r);
      if (r.handle) onHandle(r.handle, srcPrimitive);
    } catch (e) {
      setResult({ error: String(e) });
    } finally {
      setLoading(false);
    }
  }, [foundation, srcPrimitive, seedHex, onHandle]);

  return (
    <div className="panel-card">
      <div className="panel-title">① Build — Foundation → Source Primitive</div>
      <PrimitiveSelect id="build-source" label="Source Primitive (A)" value={srcPrimitive} onChange={setSrcPrimitive} />
      <div className="input-wrapper">
        <label className="select-label">Key / Seed (hex)</label>
        <input
          id="build-seed"
          className="styled-input"
          value={seedHex}
          onChange={(e) => setSeedHex(e.target.value)}
          placeholder="e.g. deadbeef1234..."
        />
      </div>
      <button id="build-btn" className="action-btn" onClick={handleBuild} disabled={loading}>
        {loading ? <span className="spinner" /> : "Build →"}
      </button>
      {result && (
        result.status === "stub" ? <StubCard message={result.message} /> :
        result.error ? <StubCard message={`Error: ${result.error}`} /> :
        <>
          <div style={{ display: "flex", gap: "0.5rem", alignItems: "center" }}>
            <span className="tag tag-ok">✓ {foundation} → {srcPrimitive}</span>
          </div>
          <StepList steps={result.steps} />
        </>
      )}
    </div>
  );
}

function ReducePanel({ srcHandle, srcPrimitive, foundation }) {
  const [tgtPrimitive, setTgtPrimitive] = useState("MAC");
  const [queryHex, setQueryHex] = useState("0102030405060708090a0b0c0d0e0f10");
  const [direction, setDirection] = useState("forward");
  const [result, setResult] = useState(null);
  const [pathResult, setPathResult] = useState(null);
  const [loading, setLoading] = useState(false);

  const handleReduce = useCallback(async () => {
    setLoading(true);
    try {
      const [r, p] = await Promise.all([
        reducePrimitiveToTarget({
          source_type: srcPrimitive,
          target_type: tgtPrimitive,
          query_hex: queryHex || "00000000000000000000000000000000",
          direction,
          source_instance_handle: srcHandle || {},
        }),
        getReductionPath(srcPrimitive, tgtPrimitive, direction),
      ]);
      setResult(r);
      setPathResult(p);
    } catch (e) {
      setResult({ error: String(e) });
    } finally {
      setLoading(false);
    }
  }, [srcPrimitive, tgtPrimitive, queryHex, direction, srcHandle]);

  return (
    <div className="panel-card">
      <div className="panel-title">② Reduce — Source Primitive → Target</div>
      <div style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>
        Using <strong style={{ color: "var(--accent2)" }}>{srcPrimitive}</strong> from Column 1 as black-box
      </div>
      <PrimitiveSelect id="reduce-target" label="Target Primitive (B)" value={tgtPrimitive} onChange={setTgtPrimitive} />
      <div className="select-wrapper">
        <label className="select-label">Direction</label>
        <select id="reduce-direction" className="styled-select" value={direction} onChange={(e) => setDirection(e.target.value)}>
          <option value="forward">Forward (A → B)</option>
          <option value="backward">Backward (B → A)</option>
        </select>
      </div>
      <div className="input-wrapper">
        <label className="select-label">Query (hex)</label>
        <input
          id="reduce-query"
          className="styled-input"
          value={queryHex}
          onChange={(e) => setQueryHex(e.target.value)}
          placeholder="query hex..."
        />
      </div>
      <button id="reduce-btn" className="action-btn" onClick={handleReduce} disabled={loading}>
        {loading ? <span className="spinner" /> : "Reduce →"}
      </button>

      {pathResult?.path && (
        <div className="path-pills">
          {pathResult.path.map((p, i) => (
            <span key={i}>
              <span className="path-pill">{p}</span>
              {i < pathResult.path.length - 1 && <span className="path-arrow">→</span>}
            </span>
          ))}
        </div>
      )}
      {pathResult && !pathResult.path && (
        <div className="stub-card">No direct path found. {pathResult.message}</div>
      )}

      {result && (
        result.status === "stub" ? <StubCard message={result.message} /> :
        result.status === "no_path" ? <StubCard message={result.message + " " + (result.hint || "")} /> :
        result.status === "error" ? <StubCard message={result.message} /> :
        result.error ? <StubCard message={`Error: ${result.error}`} /> :
        <>
          <div style={{ display: "flex", gap: "0.5rem", alignItems: "center" }}>
            <span className="tag tag-ok">✓ {srcPrimitive} → {tgtPrimitive}</span>
          </div>
          {result.construction && (
            <div className="step-item">
              <div className="step-title">Construction</div>
              <div className="step-desc">{result.construction}</div>
            </div>
          )}
          {result.output_hex && (
            <div className="step-item">
              <div className="step-title">Output</div>
              <div className="step-value">{result.output_hex}</div>
            </div>
          )}
          <StepList steps={result.reduction_steps} />
        </>
      )}
    </div>
  );
}

function ProofSummaryPanel({ srcPrimitive, tgtPrimitive, foundation, isOpen, onToggle }) {
  const [proof, setProof] = useState(null);
  const [loading, setLoading] = useState(false);

  const fetchProof = useCallback(async () => {
    if (!srcPrimitive || !tgtPrimitive) return;
    setLoading(true);
    try {
      const p = await getProofSummary(srcPrimitive, tgtPrimitive);
      setProof(p);
    } finally {
      setLoading(false);
    }
  }, [srcPrimitive, tgtPrimitive]);

  const handleToggle = () => {
    if (!isOpen) fetchProof();
    onToggle();
  };

  return (
    <>
      <div id="proof-toggle" className="proof-toggle-bar" onClick={handleToggle}>
        <span>▾ Proof Summary — {foundation} → {srcPrimitive} → {tgtPrimitive}</span>
        <span>{isOpen ? "▲ Collapse" : "▼ Expand"}</span>
      </div>
      <div id="proof-panel" className={`proof-panel ${isOpen ? "open" : "closed"}`}>
        {loading && <span className="spinner" />}
        {proof && (
          <>
            <div className="proof-chain">
              <span style={{ fontSize: "0.72rem", color: "var(--text-muted)", marginRight: "0.25rem" }}>Chain:</span>
              {(proof.path || []).map((p, i) => (
                <span key={i} style={{ display: "flex", alignItems: "center", gap: "0.4rem" }}>
                  <span className="proof-prim">{p}</span>
                  {i < (proof.path?.length || 1) - 1 && <span className="proof-arrow">→</span>}
                </span>
              ))}
            </div>
            {proof.theorem && (
              <div className="proof-detail">
                <div className="proof-theorem">📐 {proof.theorem}</div>
                {proof.construction && <div style={{ marginBottom: "0.4rem" }}>{proof.construction}</div>}
                {proof.pa && <span className="proof-pa">{proof.pa}</span>}
                {proof.primitives?.map((prim, i) => (
                  <div key={i} style={{ marginTop: "0.3rem", display: "flex", gap: "0.5rem", alignItems: "center" }}>
                    <span className={`tag ${prim.implemented ? "tag-ok" : "tag-stub"}`}>
                      {prim.name} (PA#{prim.pa})
                    </span>
                    {!prim.implemented && <span style={{ fontSize: "0.7rem", color: "var(--text-muted)" }}>Not implemented yet</span>}
                  </div>
                ))}
              </div>
            )}
          </>
        )}
      </div>
    </>
  );
}

export default function App() {
  const [foundation, setFoundation] = useState("DLP");
  const [srcHandle, setSrcHandle] = useState(null);
  const [srcPrimitive, setSrcPrimitive] = useState("PRG");
  const [proofOpen, setProofOpen] = useState(false);
  const [tgtPrimitive, setTgtPrimitive] = useState("MAC");

  const handleHandle = useCallback((handle, prim) => {
    setSrcHandle(handle);
    setSrcPrimitive(prim);
  }, []);

  return (
    <>
      <header className="app-header">
        <div>
          <div className="app-title">Minicrypt Clique Explorer</div>
          <div className="app-subtitle">CS8.401 — Principles of Information Security</div>
        </div>
      </header>

      <FoundationToggle value={foundation} onChange={setFoundation} />

      <div className="main-columns">
        <BuildPanel foundation={foundation} onHandle={handleHandle} />
        <ReducePanel srcHandle={srcHandle} srcPrimitive={srcPrimitive} foundation={foundation} />
      </div>

      <ProofSummaryPanel
        srcPrimitive={srcPrimitive}
        tgtPrimitive={tgtPrimitive}
        foundation={foundation}
        isOpen={proofOpen}
        onToggle={() => setProofOpen((o) => !o)}
      />
    </>
  );
}
