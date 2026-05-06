import { useState, useCallback, useEffect } from "react";
import {
  buildFoundationToPrimitive,
  reducePrimitiveToTarget,
  getReductionPath,
  getProofSummary,
  runPrgViewer,
  runGgmTree,
  startCpaChallenge,
  submitCpaGuess,
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
            <span className="tag tag-ok">✓ {result.build_path?.join(" → ") || `${foundation} → ${srcPrimitive}`}</span>
            {result.hop_count > 0 && <span className="tag tag-stub">{result.hop_count} hops</span>}
          </div>
          <StepList steps={result.steps} />
        </>
      )}
    </div>
  );
}

function PrgViewerPanel() {
  const [seedHex, setSeedHex] = useState("deadbeef1234abcd");
  const [lengthBytes, setLengthBytes] = useState(32);
  const [runTests, setRunTests] = useState(false);
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);

  const fetchPrg = useCallback(async (withTests = false) => {
    setLoading(true);
    try {
      const r = await runPrgViewer({ seed_hex: seedHex, length_bytes: lengthBytes, run_tests: withTests });
      setResult(r);
      setRunTests(withTests);
    } catch (e) {
      setResult({ status: "error", message: String(e) });
    } finally {
      setLoading(false);
    }
  }, [seedHex, lengthBytes]);

  useEffect(() => {
    const id = setTimeout(() => {
      fetchPrg(false);
    }, 180);
    return () => clearTimeout(id);
  }, [seedHex, lengthBytes, fetchPrg]);

  const ratio = result?.one_ratio ?? 0;

  return (
    <section className="demo-panel">
      <div className="panel-title">PA#1 — Live PRG Output Viewer</div>
      <div className="demo-grid">
        <div className="input-wrapper">
          <label className="select-label">Seed (hex)</label>
          <input
            id="pa01-seed"
            className="styled-input"
            value={seedHex}
            onChange={(e) => setSeedHex(e.target.value)}
          />
        </div>
        <div className="input-wrapper">
          <label className="select-label">Output Length: {lengthBytes} bytes</label>
          <input
            id="pa01-length"
            className="styled-range"
            type="range"
            min="8"
            max="256"
            step="8"
            value={lengthBytes}
            onChange={(e) => setLengthBytes(Number(e.target.value))}
          />
        </div>
      </div>

      <div className="prg-output-box">
        {loading && !result ? <span className="spinner" /> : result?.output_hex || "Waiting for output..."}
      </div>

      {result?.status === "error" && <StubCard message={result.message} />}
      {result?.status === "ok" && (
        <>
          <div className="metric-row">
            <span className="tag tag-ok">seed integer: {result.seed}</span>
            <span className="tag tag-stub">{result.bit_count} bits</span>
            <span className="tag tag-stub">{result.ones} ones / {result.zeros} zeros</span>
          </div>
          <div className="ratio-track">
            <div className="ratio-fill" style={{ width: `${Math.round(ratio * 100)}%` }} />
          </div>
          <button className="action-btn" onClick={() => fetchPrg(true)} disabled={loading}>
            {loading && runTests ? <span className="spinner" /> : "Randomness Test"}
          </button>
          {result.tests?.length > 0 && (
            <div className="test-grid">
              {result.tests.map((test, i) => (
                <div key={i} className={`test-card ${test.pass ? "pass" : "fail"}`}>
                  <div className="step-title">{test.test}</div>
                  <div className="step-desc">{test.pass ? "Pass" : "Fail"}</div>
                  {"p_value" in test && <div className="step-value">p = {test.p_value}</div>}
                  {"p1" in test && <div className="step-value">p1 = {test.p1}, p2 = {test.p2}</div>}
                  {test.note && <div className="step-desc">{test.note}</div>}
                </div>
              ))}
            </div>
          )}
        </>
      )}
    </section>
  );
}

function GgmTreePanel() {
  const [keyHex, setKeyHex] = useState("deadbeef1234abcd");
  const [queryBits, setQueryBits] = useState("1011");
  const [depth, setDepth] = useState(4);
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);

  const fetchTree = useCallback(async () => {
    setLoading(true);
    try {
      setResult(await runGgmTree({ key_hex: keyHex, query_bits: queryBits, depth }));
    } catch (e) {
      setResult({ status: "error", message: String(e) });
    } finally {
      setLoading(false);
    }
  }, [keyHex, queryBits, depth]);

  useEffect(() => {
    const id = setTimeout(fetchTree, 180);
    return () => clearTimeout(id);
  }, [fetchTree]);

  return (
    <section className="demo-panel">
      <div className="panel-title">PA#2 — GGM Tree Visualizer</div>
      <div className="demo-grid three">
        <div className="input-wrapper">
          <label className="select-label">Key k (hex)</label>
          <input className="styled-input" value={keyHex} onChange={(e) => setKeyHex(e.target.value)} />
        </div>
        <div className="input-wrapper">
          <label className="select-label">Query x (bits)</label>
          <input
            className="styled-input"
            value={queryBits}
            onChange={(e) => setQueryBits(e.target.value.replace(/[^01]/g, "").slice(0, 8))}
          />
        </div>
        <div className="input-wrapper">
          <label className="select-label">Depth: {depth}</label>
          <input className="styled-range" type="range" min="1" max="8" value={depth} onChange={(e) => setDepth(Number(e.target.value))} />
        </div>
      </div>

      {result?.status === "error" && <StubCard message={result.message} />}
      {result?.status === "ok" && (
        <>
          <div className="metric-row">
            <span className="tag tag-ok">F_k({result.query_bits}) = {result.output_hex}</span>
            <span className="tag tag-stub">depth {result.depth}</span>
          </div>
          <div className="tree-viewport">
            {result.rows.map((row) => (
              <div key={row[0]?.level ?? "row"} className="tree-row">
                {row.map((node) => (
                  <div key={node.id} className={`tree-node ${node.active ? "active" : ""}`}>
                    <div className="tree-label">L{node.level} · {node.index}</div>
                    <div className="tree-value">{node.state_hex}</div>
                  </div>
                ))}
              </div>
            ))}
          </div>
          <div className="steps-container">
            {result.path.slice(0, -1).map((step) => (
              <div key={step.level} className="step-item">
                <div className="step-title">Level {step.level}: bit {step.bit}</div>
                <div className="step-desc">G0 = {step.G0_hex}, G1 = {step.G1_hex}</div>
                <div className="step-value">chosen: {step.chosen_hex}</div>
              </div>
            ))}
          </div>
        </>
      )}
      {loading && !result && <span className="spinner" />}
    </section>
  );
}

function CpaGamePanel() {
  const [m0, setM0] = useState("attack at dawn");
  const [m1, setM1] = useState("retreat now!!");
  const [reuseNonce, setReuseNonce] = useState(false);
  const [challenge, setChallenge] = useState(null);
  const [lastGuess, setLastGuess] = useState(null);
  const [stats, setStats] = useState({ rounds: 0, wins: 0 });
  const [loading, setLoading] = useState(false);

  const startRound = useCallback(async () => {
    setLoading(true);
    setLastGuess(null);
    try {
      setChallenge(await startCpaChallenge({ m0, m1, reuse_nonce: reuseNonce }));
    } catch (e) {
      setChallenge({ status: "error", message: String(e) });
    } finally {
      setLoading(false);
    }
  }, [m0, m1, reuseNonce]);

  const guess = useCallback(async (value) => {
    if (!challenge?.challenge_id) return;
    setLoading(true);
    try {
      const result = await submitCpaGuess({ challenge_id: challenge.challenge_id, guess: value });
      setLastGuess(result);
      if (result.status === "ok") {
        setStats((s) => ({ rounds: s.rounds + 1, wins: s.wins + (result.correct ? 1 : 0) }));
      }
    } finally {
      setLoading(false);
    }
  }, [challenge]);

  const winRate = stats.rounds ? stats.wins / stats.rounds : 0;
  const advantage = stats.rounds ? Math.abs(winRate - 0.5) : 0;

  return (
    <section className="demo-panel">
      <div className="panel-title">PA#3 — IND-CPA Game</div>
      <div className="demo-grid">
        <div className="input-wrapper">
          <label className="select-label">m0</label>
          <input className="styled-input text-input" value={m0} onChange={(e) => setM0(e.target.value)} />
        </div>
        <div className="input-wrapper">
          <label className="select-label">m1</label>
          <input className="styled-input text-input" value={m1} onChange={(e) => setM1(e.target.value)} />
        </div>
      </div>
      <label className="toggle-line">
        <input type="checkbox" checked={reuseNonce} onChange={(e) => setReuseNonce(e.target.checked)} />
        Reuse nonce
      </label>
      <button className="action-btn" onClick={startRound} disabled={loading}>
        {loading && !challenge ? <span className="spinner" /> : "Encrypt Challenge"}
      </button>

      {challenge?.status === "error" && <StubCard message={challenge.message} />}
      {challenge?.status === "ok" && (
        <>
          <div className="metric-row">
            <span className="tag tag-ok">{challenge.scheme}</span>
            <span className="tag tag-stub">rounds {stats.rounds}</span>
            <span className="tag tag-stub">advantage {advantage.toFixed(2)}</span>
          </div>
          <div className="step-item">
            <div className="step-title">C*</div>
            <div className="step-desc">nonce: {challenge.nonce_hex}</div>
            <div className="step-value">{challenge.ciphertext_hex}</div>
          </div>
          {challenge.reference_ciphertext_hex && (
            <div className="step-item">
              <div className="step-title">Reference Enc(m0)</div>
              <div className="step-value">{challenge.reference_ciphertext_hex}</div>
            </div>
          )}
          {!lastGuess && (
            <div className="button-row">
              <button className="action-btn" onClick={() => guess(0)} disabled={loading}>Guess m0</button>
              <button className="action-btn" onClick={() => guess(1)} disabled={loading}>Guess m1</button>
            </div>
          )}
          {lastGuess?.status === "ok" && (
            <div className={`result-banner ${lastGuess.correct ? "pass" : "fail"}`}>
              Guess {lastGuess.guess}; hidden b was {lastGuess.b}. {lastGuess.correct ? "Correct" : "Incorrect"}.
            </div>
          )}
        </>
      )}
    </section>
  );
}

function ReducePanel({ srcHandle, srcPrimitive, onTargetChange }) {
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

  const handleTargetChange = useCallback((target) => {
    setTgtPrimitive(target);
    onTargetChange?.(target);
  }, [onTargetChange]);

  return (
    <div className="panel-card">
      <div className="panel-title">② Reduce — Source Primitive → Target</div>
      <div style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>
        Using <strong style={{ color: "var(--accent2)" }}>{srcPrimitive}</strong> from Column 1 as black-box
      </div>
      <PrimitiveSelect id="reduce-target" label="Target Primitive (B)" value={tgtPrimitive} onChange={handleTargetChange} />
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
        result.status === "composed_path" ? <StubCard message={result.message + " " + (result.hint || "") + " " + (result.suggestion || "")} /> :
        result.status === "error" ? <StubCard message={result.message} /> :
        result.error ? <StubCard message={`Error: ${result.error}`} /> :
        <>
          <div style={{ display: "flex", gap: "0.5rem", alignItems: "center" }}>
            <span className="tag tag-ok">
              ✓ {result.path?.join(" → ") || `${srcPrimitive} → ${tgtPrimitive}`}
            </span>
            {result.hop_count > 1 && <span className="tag tag-stub">{result.hop_count} hops</span>}
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
                {proof.path_reductions?.map((red, i) => (
                  <div key={i} className="proof-hop">
                    <strong>{red.edge}</strong>: {red.theorem}
                    {red.pa && <span className="proof-pa">{red.pa}</span>}
                  </div>
                ))}
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
        <ReducePanel srcHandle={srcHandle} srcPrimitive={srcPrimitive} onTargetChange={setTgtPrimitive} />
      </div>

      <PrgViewerPanel />
      <GgmTreePanel />
      <CpaGamePanel />

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
