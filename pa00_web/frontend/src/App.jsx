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
  runModeAnimator,
  startMacGame,
  submitMacForgery,
  runLengthExtension,
  runCcaMalleability,
  runMdChain,
  runDlpHash,
  runBirthdayAttack,
  runHmacCompare,
  runDhExchange,
  runRsaDeterminism,
  runMillerRabin,
  runHastad,
  runSignatures,
  runElGamal,
  runCcaPkc,
  runOtDemo,
  runSecureAnd,
  runMillionaire,
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

function ModeAnimatorPanel() {
  const [mode, setMode] = useState("CBC");
  const [message, setMessage] = useState("Block one demo!!Block two demo!!Block three demo");
  const [flipEnabled, setFlipEnabled] = useState(false);
  const [flipBlock, setFlipBlock] = useState(0);
  const [flipByte, setFlipByte] = useState(0);
  const [reuseIv, setReuseIv] = useState(false);
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);

  const fetchMode = useCallback(async () => {
    setLoading(true);
    try {
      setResult(await runModeAnimator({
        mode,
        message,
        flip_enabled: flipEnabled,
        flip_block: flipBlock,
        flip_byte: flipByte,
        reuse_iv: reuseIv,
      }));
    } catch (e) {
      setResult({ status: "error", message: String(e) });
    } finally {
      setLoading(false);
    }
  }, [mode, message, flipEnabled, flipBlock, flipByte, reuseIv]);

  useEffect(() => {
    const id = setTimeout(fetchMode, 180);
    return () => clearTimeout(id);
  }, [fetchMode]);

  return (
    <section className="demo-panel">
      <div className="panel-title">PA#4 — CBC/OFB/CTR Block-Mode Animator</div>
      <div className="segmented">
        {["CBC", "OFB", "CTR"].map((item) => (
          <button key={item} className={`segment ${mode === item ? "active" : ""}`} onClick={() => setMode(item)}>
            {item}
          </button>
        ))}
      </div>
      <div className="demo-grid three">
        <div className="input-wrapper">
          <label className="select-label">Plaintext</label>
          <input className="styled-input text-input" value={message} onChange={(e) => setMessage(e.target.value)} />
        </div>
        <div className="input-wrapper">
          <label className="select-label">Flip Block: {flipBlock}</label>
          <input className="styled-range" type="range" min="0" max="2" value={flipBlock} onChange={(e) => setFlipBlock(Number(e.target.value))} />
        </div>
        <div className="input-wrapper">
          <label className="select-label">Flip Byte: {flipByte}</label>
          <input className="styled-range" type="range" min="0" max="15" value={flipByte} onChange={(e) => setFlipByte(Number(e.target.value))} />
        </div>
      </div>
      <label className="toggle-line">
        <input type="checkbox" checked={flipEnabled} onChange={(e) => setFlipEnabled(e.target.checked)} />
        Flip one ciphertext bit
      </label>
      {mode === "CBC" && (
        <label className="toggle-line">
          <input type="checkbox" checked={reuseIv} onChange={(e) => setReuseIv(e.target.checked)} />
          Reuse IV demo
        </label>
      )}

      {result?.status === "error" && <StubCard message={result.message} />}
      {result?.status === "ok" && (
        <>
          <div className="metric-row">
            <span className="tag tag-ok">{result.mode}</span>
            <span className="tag tag-stub">IV/nonce {result.iv_or_nonce_hex}</span>
          </div>
          <div className="block-grid">
            {result.steps.slice(0, 3).map((step) => (
              <div key={step.block} className="block-card">
                <div className="step-title">Block {step.block}</div>
                <div className="step-desc">M: {step.plain_hex}</div>
                {step.xor_with_hex && <div className="step-desc">xor: {step.xor_with_hex}</div>}
                {step.counter_hex && <div className="step-desc">ctr: {step.counter_hex}</div>}
                {step.feedback_hex && <div className="step-desc">ofb: {step.feedback_hex}</div>}
                {step.keystream_hex && <div className="step-desc">ks: {step.keystream_hex}</div>}
                {step.aes_input_hex && <div className="step-desc">AES in: {step.aes_input_hex}</div>}
                <div className="step-value">C: {step.cipher_hex}</div>
              </div>
            ))}
          </div>
          <div className="step-item">
            <div className="step-title">{result.flip.enabled ? "Bit Flip Propagation" : "Clean Decryption"}</div>
            <div className="step-desc">
              {result.flip.enabled ? result.analysis : "No ciphertext bit is flipped, so decryption should recover the original plaintext blocks."}
            </div>
          </div>
          <div className="block-grid">
            {result.diff_blocks.slice(0, 3).map((block) => (
              <div key={block.block} className={`block-card ${block.diff_bytes ? "changed" : ""}`}>
                <div className="step-title">Plaintext block {block.block}</div>
                <div className="step-desc">changed bytes: {block.diff_bytes}</div>
                <div className="step-value">{block.decrypted_text}</div>
              </div>
            ))}
          </div>
          {result.reuse_demo && (
            <div className={`result-banner ${result.reuse_demo.match ? "fail" : "pass"}`}>
              CBC IV reuse: first ciphertext blocks {result.reuse_demo.match ? "match" : "differ"}.
            </div>
          )}
        </>
      )}
      {loading && !result && <span className="spinner" />}
    </section>
  );
}

function MacGamePanel() {
  const [game, setGame] = useState(null);
  const [message, setMessage] = useState("new-message");
  const [tagHex, setTagHex] = useState("00");
  const [forgery, setForgery] = useState(null);
  const [leMessage, setLeMessage] = useState("amount=100&to=bob");
  const [extension, setExtension] = useState("&admin=true");
  const [lengthResult, setLengthResult] = useState(null);
  const [loading, setLoading] = useState(false);

  const startGame = useCallback(async () => {
    setLoading(true);
    setForgery(null);
    try {
      setGame(await startMacGame({ num_messages: 8 }));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    startGame();
  }, [startGame]);

  const submitForgery = useCallback(async () => {
    if (!game?.game_id) return;
    setLoading(true);
    try {
      setForgery(await submitMacForgery({ game_id: game.game_id, message, tag_hex: tagHex }));
    } finally {
      setLoading(false);
    }
  }, [game, message, tagHex]);

  const runExtension = useCallback(async () => {
    setLoading(true);
    try {
      setLengthResult(await runLengthExtension({ message: leMessage, extension }));
    } finally {
      setLoading(false);
    }
  }, [leMessage, extension]);

  return (
    <section className="demo-panel">
      <div className="panel-title">PA#5 — MAC Forgery Game</div>
      <div className="info-card">
        <strong>CBC-MAC forgery game:</strong> the signed messages below are oracle queries under a hidden key.
        The textbox lets you play the attacker: submit a new message and a guessed tag.
        Success means producing a valid tag for a message that was not already signed.
      </div>
      <div className="metric-row">
        <button className="action-btn" onClick={startGame} disabled={loading}>New MAC Game</button>
        {game?.status === "ok" && <span className="tag tag-stub">{game.signed.length} oracle tags</span>}
        {forgery?.status === "ok" && <span className="tag tag-stub">attempts {forgery.attempts}, successes {forgery.successes}</span>}
      </div>
      {game?.status === "ok" && (
        <div className="oracle-list">
          {game.signed.map((item) => (
            <div key={item.message} className="oracle-row">
              <span>{item.message}</span>
              <code>{item.tag_hex}</code>
            </div>
          ))}
        </div>
      )}
      <div className="demo-grid">
        <div className="input-wrapper">
          <label className="select-label">Fresh message m*</label>
          <input className="styled-input text-input" value={message} onChange={(e) => setMessage(e.target.value)} />
        </div>
        <div className="input-wrapper">
          <label className="select-label">Tag t* (hex)</label>
          <input className="styled-input" value={tagHex} onChange={(e) => setTagHex(e.target.value)} />
        </div>
      </div>
      <button className="action-btn" onClick={submitForgery} disabled={loading || !game?.game_id}>Submit Forgery</button>
      {forgery?.status === "ok" && (
        <div className={`result-banner ${forgery.accepted ? "pass" : "fail"}`}>
          {forgery.accepted ? "Forgery accepted" : "Forgery rejected"}.
          {!forgery.fresh_message ? " The message was already signed." : ""}
        </div>
      )}

      <div className="panel-title subtle">Length-Extension Demo</div>
      <div className="demo-grid">
        <div className="input-wrapper">
          <label className="select-label">Message</label>
          <input className="styled-input text-input" value={leMessage} onChange={(e) => setLeMessage(e.target.value)} />
        </div>
        <div className="input-wrapper">
          <label className="select-label">Suffix</label>
          <input className="styled-input text-input" value={extension} onChange={(e) => setExtension(e.target.value)} />
        </div>
      </div>
      <button className="action-btn" onClick={runExtension} disabled={loading}>Run Extension</button>
      {lengthResult?.status === "ok" && (
        <>
          <div className="message-compare">
            <div className="block-card">
              <div className="step-title">Original message</div>
              <div className="message-text">{lengthResult.message_text}</div>
              <div className="step-value">{lengthResult.message_hex}</div>
            </div>
            <div className="block-card changed">
              <div className="step-title">Extended message</div>
              <div className="step-desc">Readable formula, not literal text to paste into the secure MAC game</div>
              <div className="message-text">{lengthResult.extended_message_display}</div>
              <div className="step-desc">exact bytes</div>
              <div className="step-value">{lengthResult.extended_message_hex}</div>
            </div>
          </div>
          <div className={`result-banner ${lengthResult.attack_succeeds ? "pass" : "fail"}`}>
            {lengthResult.attack_succeeds
              ? "Naive H(k || m) accepts the forged tag for the extended message. The secure CBC-MAC game above should still reject it."
              : "The length-extension forgery did not verify for this toy hash run."}
          </div>
          <div className="block-grid">
            <div className="block-card">
              <div className="step-title">Original tag</div>
              <div className="step-value">{lengthResult.original_tag_hex}</div>
            </div>
            <div className="block-card">
              <div className="step-title">Forged tag</div>
              <div className="step-value">{lengthResult.forged_tag_hex}</div>
            </div>
            <div className={`block-card ${lengthResult.attack_succeeds ? "changed" : ""}`}>
              <div className="step-title">Actual extended tag</div>
              <div className="step-value">{lengthResult.actual_extended_tag_hex}</div>
            </div>
          </div>
        </>
      )}
    </section>
  );
}

function CcaMalleabilityPanel() {
  const [message, setMessage] = useState("transfer=100&to=bob");
  const [flipByte, setFlipByte] = useState(0);
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);

  const runDemo = useCallback(async () => {
    setLoading(true);
    try {
      setResult(await runCcaMalleability({ message, flip_byte: flipByte }));
    } finally {
      setLoading(false);
    }
  }, [message, flipByte]);

  useEffect(() => {
    const id = setTimeout(runDemo, 180);
    return () => clearTimeout(id);
  }, [runDemo]);

  return (
    <section className="demo-panel">
      <div className="panel-title">PA#6 — CPA Malleability vs CCA Encrypt-then-MAC</div>
      <div className="info-card">
        CPA encryption hides the message but still lets ciphertext edits flow into decryption.
        Encrypt-then-MAC authenticates the ciphertext first, so the same edit returns ⊥.
      </div>
      <div className="demo-grid">
        <div className="input-wrapper">
          <label className="select-label">Plaintext</label>
          <input className="styled-input text-input" value={message} onChange={(e) => setMessage(e.target.value)} />
        </div>
        <div className="input-wrapper">
          <label className="select-label">Flip Byte: {flipByte}</label>
          <input className="styled-range" type="range" min="0" max="31" value={flipByte} onChange={(e) => setFlipByte(Number(e.target.value))} />
        </div>
      </div>
      {result?.status === "ok" && (
        <div className="compare-grid">
          <div className="block-card changed">
            <div className="step-title">CPA-only</div>
            <div className="step-desc">tampered ciphertext still reaches decryption</div>
            <div className="step-value">{result.cpa.tampered_ciphertext_hex}</div>
            <div className="message-text">
              {result.cpa.result.status === "decrypted" ? result.cpa.result.plaintext_text : result.cpa.result.error}
            </div>
          </div>
          <div className="block-card">
            <div className="step-title">CCA: Encrypt-then-MAC</div>
            <div className="step-desc">tag valid after tamper? {String(result.cca.mac_valid)}</div>
            <div className="step-value">{result.cca.tag_hex}</div>
            <div className="result-banner fail">Decryption output: {result.cca.result}</div>
          </div>
        </div>
      )}
      {loading && !result && <span className="spinner" />}
    </section>
  );
}

function MerkleDamgardPanel() {
  const [message, setMessage] = useState("Merkle-Damgard demo");
  const [blockSize, setBlockSize] = useState(16);
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);

  const runDemo = useCallback(async () => {
    setLoading(true);
    try {
      setResult(await runMdChain({ message, block_size: blockSize }));
    } finally {
      setLoading(false);
    }
  }, [message, blockSize]);

  useEffect(() => {
    const id = setTimeout(runDemo, 180);
    return () => clearTimeout(id);
  }, [runDemo]);

  return (
    <section className="demo-panel">
      <div className="panel-title">PA#7 — Merkle-Damgard Chain Viewer</div>
      <div className="demo-grid">
        <div className="input-wrapper">
          <label className="select-label">Message</label>
          <input className="styled-input text-input" value={message} onChange={(e) => setMessage(e.target.value)} />
        </div>
        <div className="input-wrapper">
          <label className="select-label">Block Size: {blockSize}</label>
          <input className="styled-range" type="range" min="9" max="64" value={blockSize} onChange={(e) => setBlockSize(Number(e.target.value))} />
        </div>
      </div>
      {result?.status === "ok" && (
        <>
          <div className="metric-row">
            <span className="tag tag-ok">digest {result.digest_hex}</span>
            <span className="tag tag-stub">padding {result.padding_hex}</span>
          </div>
          <div className="chain-list">
            {result.trace.map((item) => (
              <div key={item.block} className="chain-row">
                <span className="path-pill">H{item.block}</span>
                <code>{item.prev_state_hex}</code>
                <span className="path-arrow">+</span>
                <code>{item.block_hex}</code>
                <span className="path-arrow">→</span>
                <code>{item.next_state_hex}</code>
              </div>
            ))}
          </div>
          <div className={`result-banner ${result.collision_demo.hash_collision_propagates ? "pass" : "fail"}`}>
            Collision propagation demo: {String(result.collision_demo.hash_collision_propagates)}
          </div>
        </>
      )}
      {loading && !result && <span className="spinner" />}
    </section>
  );
}

function DlpHashPanel() {
  const [message, setMessage] = useState("DLP hash demo");
  const [blockSize, setBlockSize] = useState(16);
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);

  const runDemo = useCallback(async () => {
    setLoading(true);
    try {
      setResult(await runDlpHash({ message, block_size: blockSize }));
    } finally {
      setLoading(false);
    }
  }, [message, blockSize]);

  useEffect(() => {
    const id = setTimeout(runDemo, 180);
    return () => clearTimeout(id);
  }, [runDemo]);

  return (
    <section className="demo-panel">
      <div className="panel-title">PA#8 — DLP Hash Live Demo</div>
      <div className="info-card">{result?.formula || "DLP compression: h(x,y)=g^x * h_hat^y mod p."}</div>
      <div className="demo-grid">
        <div className="input-wrapper">
          <label className="select-label">Message</label>
          <input className="styled-input text-input" value={message} onChange={(e) => setMessage(e.target.value)} />
        </div>
        <div className="input-wrapper">
          <label className="select-label">Block Size: {blockSize}</label>
          <input className="styled-range" type="range" min="9" max="64" value={blockSize} onChange={(e) => setBlockSize(Number(e.target.value))} />
        </div>
      </div>
      {result?.status === "ok" && (
        <>
          <div className="metric-row">
            <span className="tag tag-ok">digest {result.digest_hex}</span>
            <span className="tag tag-stub">p={result.p}</span>
            <span className="tag tag-stub">q={result.q}</span>
            <span className="tag tag-stub">h_hat={result.h_hat}</span>
          </div>
          <div className="chain-list">
            {result.trace.map((item) => (
              <div key={item.block} className="chain-row">
                <span className="path-pill">B{item.block}</span>
                <code>x={item.x}</code>
                <code>y={item.y}</code>
                <span className="path-arrow">→</span>
                <code>{item.next_state_hex}</code>
              </div>
            ))}
          </div>
        </>
      )}
      {loading && !result && <span className="spinner" />}
    </section>
  );
}

function BirthdayAttackPanel() {
  const [bits, setBits] = useState(12);
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);

  const runDemo = useCallback(async () => {
    setLoading(true);
    try {
      setResult(await runBirthdayAttack({ n_bits: bits, max_evaluations: 20000 }));
    } finally {
      setLoading(false);
    }
  }, [bits]);

  useEffect(() => {
    runDemo();
  }, [runDemo]);

  const attack = result?.attack;

  return (
    <section className="demo-panel">
      <div className="panel-title">PA#9 — Birthday Attack Live Demo</div>
      <div className="info-card">For an n-bit hash, collisions appear after about 2^(n/2) evaluations, not 2^n.</div>
      <div className="input-wrapper">
        <label className="select-label">Truncated output bits: {bits}</label>
        <input className="styled-range" type="range" min="4" max="20" value={bits} onChange={(e) => setBits(Number(e.target.value))} />
      </div>
      {attack && (
        <>
          <div className="metric-row">
            <span className={`tag ${attack.collision_found ? "tag-ok" : "tag-err"}`}>
              {attack.collision_found ? "collision found" : "no collision"}
            </span>
            <span className="tag tag-stub">evaluations {attack.evaluations}</span>
            <span className="tag tag-stub">birthday bound {attack.birthday_bound}</span>
            {attack.ratio && <span className="tag tag-stub">ratio {attack.ratio}</span>}
          </div>
          {attack.collision_found && (
            <div className="block-grid">
              <div className="block-card">
                <div className="step-title">x1</div>
                <div className="step-value">{attack.x1}</div>
              </div>
              <div className="block-card">
                <div className="step-title">x2</div>
                <div className="step-value">{attack.x2}</div>
              </div>
              <div className="block-card changed">
                <div className="step-title">same truncated hash</div>
                <div className="step-value">{attack.hash_value}</div>
              </div>
            </div>
          )}
        </>
      )}
      {loading && !result && <span className="spinner" />}
    </section>
  );
}

function HmacComparePanel() {
  const [message, setMessage] = useState("amount=100&to=bob");
  const [extension, setExtension] = useState("&admin=true");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);

  const runDemo = useCallback(async () => {
    setLoading(true);
    try {
      setResult(await runHmacCompare({ message, extension }));
    } finally {
      setLoading(false);
    }
  }, [message, extension]);

  useEffect(() => {
    const id = setTimeout(runDemo, 180);
    return () => clearTimeout(id);
  }, [runDemo]);

  return (
    <section className="demo-panel">
      <div className="panel-title">PA#10 — Length Extension vs HMAC</div>
      <div className="demo-grid">
        <div className="input-wrapper">
          <label className="select-label">Message</label>
          <input className="styled-input text-input" value={message} onChange={(e) => setMessage(e.target.value)} />
        </div>
        <div className="input-wrapper">
          <label className="select-label">Suffix</label>
          <input className="styled-input text-input" value={extension} onChange={(e) => setExtension(e.target.value)} />
        </div>
      </div>
      {result?.status === "ok" && (
        <>
          <div className="info-card">Extended message: {result.extended_message_display}</div>
          <div className="compare-grid">
            <div className={`block-card ${result.naive.attack_succeeds ? "changed" : ""}`}>
              <div className="step-title">Naive H(k || m)</div>
              <div className="step-desc">attack succeeds: {String(result.naive.attack_succeeds)}</div>
              <div className="step-value">forged {result.naive.forged_tag_hex}</div>
              <div className="step-value">actual {result.naive.actual_extended_tag_hex}</div>
            </div>
            <div className={`block-card ${result.hmac.attack_succeeds ? "changed" : ""}`}>
              <div className="step-title">HMAC</div>
              <div className="step-desc">attack succeeds: {String(result.hmac.attack_succeeds)}</div>
              <div className="step-value">attempt {result.hmac.forged_attempt_hex}</div>
              <div className="step-value">real {result.hmac.real_extended_tag_hex}</div>
            </div>
          </div>
        </>
      )}
      {loading && !result && <span className="spinner" />}
    </section>
  );
}

function DiffieHellmanPanel() {
  const [a, setA] = useState("5");
  const [b, setB] = useState("7");
  const [enableEve, setEnableEve] = useState(false);
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);

  const runDemo = useCallback(async () => {
    setLoading(true);
    try {
      setResult(await runDhExchange({ a: Number(a), b: Number(b), enable_eve: enableEve }));
    } finally {
      setLoading(false);
    }
  }, [a, b, enableEve]);

  useEffect(() => {
    const id = setTimeout(runDemo, 180);
    return () => clearTimeout(id);
  }, [runDemo]);

  return (
    <section className="demo-panel">
      <div className="panel-title">PA#11 — Live Diffie-Hellman Exchange</div>
      <div className="demo-grid">
        <div className="input-wrapper">
          <label className="select-label">Alice private a</label>
          <input className="styled-input" value={a} onChange={(e) => setA(e.target.value.replace(/\D/g, ""))} />
        </div>
        <div className="input-wrapper">
          <label className="select-label">Bob private b</label>
          <input className="styled-input" value={b} onChange={(e) => setB(e.target.value.replace(/\D/g, ""))} />
        </div>
      </div>
      <div className="button-row">
        <button className="action-btn" onClick={() => setA("0")}>Randomize Alice</button>
        <button className="action-btn" onClick={() => setB("0")}>Randomize Bob</button>
      </div>
      <label className="toggle-line">
        <input type="checkbox" checked={enableEve} onChange={(e) => setEnableEve(e.target.checked)} />
        Enable Eve MITM
      </label>
      {result?.status === "ok" && (
        <>
          <div className="metric-row">
            <span className="tag tag-stub">p {result.group.p}</span>
            <span className="tag tag-stub">g {result.group.g}</span>
            <span className={result.match ? "tag tag-ok" : "tag tag-err"}>K match {String(result.match)}</span>
          </div>
          <div className="compare-grid">
            <div className="block-card">
              <div className="step-title">Alice</div>
              <div className="step-desc">A = g^a mod p = {result.alice.public}</div>
              <div className="step-value">K = {result.alice.shared}</div>
            </div>
            <div className="block-card">
              <div className="step-title">Bob</div>
              <div className="step-desc">B = g^b mod p = {result.bob.public}</div>
              <div className="step-value">K = {result.bob.shared}</div>
            </div>
          </div>
          {result.eve && (
            <div className="block-card changed">
              <div className="step-title">Eve intercepts</div>
              <div className="step-desc">E = {result.eve.eve_public_key}</div>
              <div className="step-value">Alice/Eve K {result.eve.eve_key_to_alice}</div>
              <div className="step-value">Bob/Eve K {result.eve.eve_key_to_bob}</div>
            </div>
          )}
        </>
      )}
      {loading && !result && <span className="spinner" />}
    </section>
  );
}

function RsaDemoPanel() {
  const [message, setMessage] = useState("yes");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);

  const runDemo = useCallback(async () => {
    setLoading(true);
    try {
      setResult(await runRsaDeterminism({ message }));
    } finally {
      setLoading(false);
    }
  }, [message]);

  useEffect(() => {
    const id = setTimeout(runDemo, 180);
    return () => clearTimeout(id);
  }, [runDemo]);

  return (
    <section className="demo-panel">
      <div className="panel-title">PA#12 — Textbook RSA Determinism</div>
      <div className="input-wrapper">
        <label className="select-label">Message</label>
        <input className="styled-input text-input" value={message} onChange={(e) => setMessage(e.target.value)} />
      </div>
      {result?.status === "ok" && (
        <div className="compare-grid">
          <div className={`block-card ${result.textbook.identical ? "changed" : ""}`}>
            <div className="step-title">Textbook RSA</div>
            <div className="step-desc">identical: {String(result.textbook.identical)}</div>
            <div className="step-value">c1 {result.textbook.c1_hex}</div>
            <div className="step-value">c2 {result.textbook.c2_hex}</div>
          </div>
          <div className={`block-card ${!result.pkcs15.identical ? "" : "changed"}`}>
            <div className="step-title">PKCS#1 v1.5</div>
            <div className="step-desc">identical: {String(result.pkcs15.identical)}</div>
            <div className="step-value">c1 {result.pkcs15.c1_hex}</div>
            <div className="step-value">c2 {result.pkcs15.c2_hex}</div>
          </div>
          <div className="block-card">
            <div className="step-title">Padding bytes 1</div>
            <div className="step-value">{result.pkcs15.padding1_hex}</div>
          </div>
          <div className="block-card">
            <div className="step-title">Padding bytes 2</div>
            <div className="step-value">{result.pkcs15.padding2_hex}</div>
          </div>
        </div>
      )}
      {loading && !result && <span className="spinner" />}
    </section>
  );
}

function MillerRabinPanel() {
  const [n, setN] = useState("561");
  const [rounds, setRounds] = useState(5);
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);

  const runDemo = useCallback(async () => {
    setLoading(true);
    try {
      setResult(await runMillerRabin({ n, rounds }));
    } finally {
      setLoading(false);
    }
  }, [n, rounds]);

  useEffect(() => {
    const id = setTimeout(runDemo, 180);
    return () => clearTimeout(id);
  }, [runDemo]);

  return (
    <section className="demo-panel">
      <div className="panel-title">PA#13 — Miller-Rabin Primality Tester</div>
      <div className="demo-grid">
        <div className="input-wrapper">
          <label className="select-label">n</label>
          <input className="styled-input" value={n} onChange={(e) => setN(e.target.value.replace(/[^\d]/g, ""))} />
        </div>
        <div className="input-wrapper">
          <label className="select-label">Rounds: {rounds}</label>
          <input className="styled-range" type="range" min="1" max="40" value={rounds} onChange={(e) => setRounds(Number(e.target.value))} />
        </div>
      </div>
      <div className="button-row">
        <button className="action-btn" onClick={() => setN("561")}>561</button>
        <button className="action-btn" onClick={() => setN("32416190071")}>prime</button>
        <button className="action-btn" onClick={() => setN("32416190070")}>composite</button>
      </div>
      {result?.status === "ok" && (
        <>
          <div className={`result-banner ${result.probably_prime ? "pass" : "fail"}`}>{result.result}</div>
          {result.carmichael_note && <div className="info-card">{result.carmichael_note}</div>}
          <div className="chain-list">
            {result.trace.map((item) => (
              <div key={item.witness} className="chain-row compact">
                <span className="path-pill">a={item.witness}</span>
                <code>{item.values.join(" → ")}</code>
                <span className={item.passes_round ? "tag tag-ok" : "tag tag-err"}>{item.passes_round ? "pass" : "witness"}</span>
              </div>
            ))}
          </div>
        </>
      )}
      {loading && !result && <span className="spinner" />}
    </section>
  );
}

function HastadPanel() {
  const [message, setMessage] = useState("42");
  const [usePadding, setUsePadding] = useState(false);
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);

  const runDemo = useCallback(async () => {
    setLoading(true);
    try {
      setResult(await runHastad({ message, use_padding: usePadding }));
    } finally {
      setLoading(false);
    }
  }, [message, usePadding]);

  useEffect(() => {
    const id = setTimeout(runDemo, 180);
    return () => clearTimeout(id);
  }, [runDemo]);

  return (
    <section className="demo-panel">
      <div className="panel-title">PA#14 — Håstad Broadcast Attack</div>
      <div className="demo-grid">
        <div className="input-wrapper">
          <label className="select-label">Message</label>
          <input className="styled-input text-input" value={message} onChange={(e) => setMessage(e.target.value)} />
        </div>
        <label className="toggle-line">
          <input type="checkbox" checked={usePadding} onChange={(e) => setUsePadding(e.target.checked)} />
          Use PKCS padding
        </label>
      </div>
      {result?.status === "ok" && (
        <>
          <div className="block-grid">
            {result.recipients.map((r, i) => (
              <div key={i} className="block-card">
                <div className="step-title">Recipient {i + 1}</div>
                <div className="step-desc">N: {r.n_hex}</div>
                <div className="step-value">c: {r.ciphertext_hex}</div>
              </div>
            ))}
          </div>
          <div className={`result-banner ${result.attack_succeeded ? "pass" : "fail"}`}>
            exact cube root: {String(result.exact_root)}; recovered: {result.recovered_text || result.root}
          </div>
          <div className="step-item">
            <div className="step-title">CRT gives m^3</div>
            <div className="step-value">{result.crt_combined_hex}</div>
          </div>
        </>
      )}
      {loading && !result && <span className="spinner" />}
    </section>
  );
}

function SignaturePanel() {
  const [message, setMessage] = useState("sign me");
  const [tamper, setTamper] = useState(true);
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);

  const runDemo = useCallback(async () => {
    setLoading(true);
    try {
      setResult(await runSignatures({ message, tamper }));
    } finally {
      setLoading(false);
    }
  }, [message, tamper]);

  useEffect(() => {
    const id = setTimeout(runDemo, 180);
    return () => clearTimeout(id);
  }, [runDemo]);

  return (
    <section className="demo-panel">
      <div className="panel-title">PA#15 — Hash-then-Sign Signatures</div>
      <div className="demo-grid">
        <div className="input-wrapper">
          <label className="select-label">Message</label>
          <input className="styled-input text-input" value={message} onChange={(e) => setMessage(e.target.value)} />
        </div>
        <label className="toggle-line">
          <input type="checkbox" checked={tamper} onChange={(e) => setTamper(e.target.checked)} />
          Verify tampered message
        </label>
      </div>
      {result?.status === "ok" && (
        <>
          <div className="compare-grid">
            <div className={result.valid ? "block-card changed" : "block-card"}>
              <div className="step-title">Valid signature</div>
              <div className="step-desc">Verify(m, sigma): {String(result.valid)}</div>
              <div className="step-value">H(m) {result.hash_hex}</div>
              <div className="step-value">sigma {result.signature_hex}</div>
            </div>
            <div className={!result.tampered_valid ? "block-card" : "block-card changed"}>
              <div className="step-title">Tamper check</div>
              <div className="step-desc">{result.tampered_text}</div>
              <div className="step-value">accepted: {String(result.tampered_valid)}</div>
            </div>
          </div>
          <div className={`result-banner ${result.raw_rsa_forgery.forgery_valid ? "fail" : "pass"}`}>
            Raw RSA forgery for m1*m2 is valid: {String(result.raw_rsa_forgery.forgery_valid)}
          </div>
          <StepList steps={result.steps} />
        </>
      )}
      {loading && !result && <span className="spinner" />}
    </section>
  );
}

function ElGamalPanel() {
  const [message, setMessage] = useState(5);
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);

  const runDemo = useCallback(async () => {
    setLoading(true);
    try {
      setResult(await runElGamal({ message: Number(message) }));
    } finally {
      setLoading(false);
    }
  }, [message]);

  useEffect(() => {
    const id = setTimeout(runDemo, 180);
    return () => clearTimeout(id);
  }, [runDemo]);

  return (
    <section className="demo-panel">
      <div className="panel-title">PA#16 — ElGamal Malleability</div>
      <div className="input-wrapper">
        <label className="select-label">Message group element: {message}</label>
        <input className="styled-range" type="range" min="1" max="22" value={message} onChange={(e) => setMessage(Number(e.target.value))} />
      </div>
      {result?.status === "ok" && (
        <>
          <div className="metric-row">
            <span className="tag tag-stub">p {result.group.p}</span>
            <span className="tag tag-stub">g {result.group.g}</span>
            <span className="tag tag-ok">Dec(C) {result.decrypted}</span>
          </div>
          <div className="compare-grid">
            <div className="block-card">
              <div className="step-title">Ciphertext</div>
              <div className="step-value">c1 {result.ciphertext.c1}</div>
              <div className="step-value">c2 {result.ciphertext.c2}</div>
            </div>
            <div className="block-card changed">
              <div className="step-title">Tampered ciphertext</div>
              <div className="step-desc">c2 becomes 2*c2 mod p</div>
              <div className="step-value">Dec(C') {result.tampered_decrypted}</div>
              <div className="step-value">expected {result.expected_tampered}</div>
            </div>
          </div>
          <div className={`result-banner ${result.malleability_succeeds ? "fail" : "pass"}`}>
            Malleability succeeds: {String(result.malleability_succeeds)}
          </div>
        </>
      )}
      {loading && !result && <span className="spinner" />}
    </section>
  );
}

function CcaPkcPanel() {
  const [message, setMessage] = useState("launch=no");
  const [tamper, setTamper] = useState(true);
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);

  const runDemo = useCallback(async () => {
    setLoading(true);
    try {
      setResult(await runCcaPkc({ message, tamper }));
    } finally {
      setLoading(false);
    }
  }, [message, tamper]);

  useEffect(() => {
    const id = setTimeout(runDemo, 180);
    return () => clearTimeout(id);
  }, [runDemo]);

  return (
    <section className="demo-panel">
      <div className="panel-title">PA#17 — CCA-PKC Signcrypt Panel</div>
      <div className="demo-grid">
        <div className="input-wrapper">
          <label className="select-label">Message</label>
          <input className="styled-input text-input" value={message} onChange={(e) => setMessage(e.target.value)} />
        </div>
        <label className="toggle-line">
          <input type="checkbox" checked={tamper} onChange={(e) => setTamper(e.target.checked)} />
          Flip encrypted blob byte
        </label>
      </div>
      {result?.status === "ok" && (
        <>
          <div className="compare-grid">
            <div className={result.accepted ? "block-card changed" : "block-card"}>
              <div className="step-title">Original open</div>
              <div className="step-desc">accepted: {String(result.accepted)}</div>
              <div className="step-value">{result.decrypted_text}</div>
            </div>
            <div className={result.tamper_rejected ? "block-card" : "block-card changed"}>
              <div className="step-title">Tampered open</div>
              <div className="step-desc">result: {result.tampered_result}</div>
              <div className="step-value">rejected: {String(result.tamper_rejected)}</div>
            </div>
          </div>
          <div className="block-card changed">
            <div className="step-title">Plain ElGamal contrast</div>
            <div className="step-desc">A changed ciphertext decrypts to a related message.</div>
            <div className="step-value">tampered Dec {result.elgamal_contrast.tampered_decrypted}</div>
          </div>
          <div className="info-card">{result.lineage.split("\n").slice(0, 4).join(" | ")}</div>
        </>
      )}
      {loading && !result && <span className="spinner" />}
    </section>
  );
}

function OtPanel() {
  const [m0, setM0] = useState("zero secret");
  const [m1, setM1] = useState("one secret");
  const [choice, setChoice] = useState(0);
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);

  const runDemo = useCallback(async () => {
    setLoading(true);
    try {
      setResult(await runOtDemo({ m0, m1, choice }));
    } finally {
      setLoading(false);
    }
  }, [m0, m1, choice]);

  useEffect(() => {
    const id = setTimeout(runDemo, 180);
    return () => clearTimeout(id);
  }, [runDemo]);

  return (
    <section className="demo-panel">
      <div className="panel-title">PA#18 — 1-of-2 Oblivious Transfer</div>
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
      <div className="segmented">
        {[0, 1].map((b) => (
          <button key={b} className={`segment ${choice === b ? "active" : ""}`} onClick={() => setChoice(b)}>Choose m{b}</button>
        ))}
      </div>
      {result?.status === "ok" && (
        <>
          <div className="compare-grid">
            {result.messages.map((msg) => (
              <div key={msg.label} className={result.received_label === msg.label ? "block-card changed" : "block-card"}>
                <div className="step-title">{msg.label}</div>
                <div className="step-desc">{msg.text}</div>
                <div className="step-value">encoded {msg.encoded}</div>
              </div>
            ))}
          </div>
          <div className={`result-banner ${result.privacy_holds ? "pass" : "fail"}`}>
            Received {result.received_label} = {result.received}; other decrypt attempt = {result.other_attempt}
          </div>
          <StepList steps={result.steps} />
        </>
      )}
      {loading && !result && <span className="spinner" />}
    </section>
  );
}

function SecureAndPanel() {
  const [a, setA] = useState(1);
  const [b, setB] = useState(1);
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);

  const runDemo = useCallback(async () => {
    setLoading(true);
    try {
      setResult(await runSecureAnd({ a, b }));
    } finally {
      setLoading(false);
    }
  }, [a, b]);

  useEffect(() => {
    const id = setTimeout(runDemo, 180);
    return () => clearTimeout(id);
  }, [runDemo]);

  return (
    <section className="demo-panel">
      <div className="panel-title">PA#19 — Secure AND Gate</div>
      <div className="segmented">
        {[0, 1].map((bit) => <button key={`a${bit}`} className={`segment ${a === bit ? "active" : ""}`} onClick={() => setA(bit)}>A={bit}</button>)}
        {[0, 1].map((bit) => <button key={`b${bit}`} className={`segment ${b === bit ? "active" : ""}`} onClick={() => setB(bit)}>B={bit}</button>)}
      </div>
      {result?.status === "ok" && (
        <>
          <div className="metric-row">
            <span className={result.correct ? "tag tag-ok" : "tag tag-err"}>AND {result.and_result}</span>
            <span className="tag tag-stub">XOR {result.xor_result}</span>
            <span className="tag tag-stub">NOT A {result.not_a}</span>
          </div>
          <div className="info-card">
            AND is computed as OT messages (0, A) with receiver choice B, so the receiver obtains A*B without learning the unused branch.
          </div>
          <div className="block-grid">
            {result.truth_tables.AND.map((row) => (
              <div key={`${row.a}${row.b}`} className={row.a === a && row.b === b ? "block-card changed" : "block-card"}>
                <div className="step-title">{row.a} AND {row.b}</div>
                <div className="step-value">{row.result}</div>
              </div>
            ))}
          </div>
        </>
      )}
      {loading && !result && <span className="spinner" />}
    </section>
  );
}

function MillionairePanel() {
  const [alice, setAlice] = useState(7);
  const [bob, setBob] = useState(12);
  const [bits, setBits] = useState(4);
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);

  const runDemo = useCallback(async () => {
    setLoading(true);
    try {
      setResult(await runMillionaire({ alice: Number(alice), bob: Number(bob), bits: Number(bits) }));
    } finally {
      setLoading(false);
    }
  }, [alice, bob, bits]);

  useEffect(() => {
    const id = setTimeout(runDemo, 180);
    return () => clearTimeout(id);
  }, [runDemo]);

  const maxValue = 2 ** bits - 1;

  return (
    <section className="demo-panel">
      <div className="panel-title">PA#20 — Millionaire Comparison Circuit</div>
      <div className="demo-grid three">
        <div className="input-wrapper">
          <label className="select-label">Alice wealth: {alice}</label>
          <input className="styled-range" type="range" min="0" max={maxValue} value={alice} onChange={(e) => setAlice(Number(e.target.value))} />
        </div>
        <div className="input-wrapper">
          <label className="select-label">Bob wealth: {bob}</label>
          <input className="styled-range" type="range" min="0" max={maxValue} value={bob} onChange={(e) => setBob(Number(e.target.value))} />
        </div>
        <div className="input-wrapper">
          <label className="select-label">Bit width: {bits}</label>
          <input className="styled-range" type="range" min="2" max="8" value={bits} onChange={(e) => setBits(Number(e.target.value))} />
        </div>
      </div>
      {result?.status === "ok" && (
        <>
          <div className={`result-banner ${result.correct ? "pass" : "fail"}`}>
            Circuit says Alice greater: {String(result.alice_greater)}; expected {String(result.expected)}
          </div>
          <div className="metric-row">
            <span className="tag tag-stub">Alice bits {result.alice_bits.join("")}</span>
            <span className="tag tag-stub">Bob bits {result.bob_bits.join("")}</span>
            <span className="tag tag-ok">{result.circuit.and_calls} secure AND calls</span>
          </div>
          <div className="chain-list">
            {result.transcript.map((gate, i) => (
              <div key={i} className="chain-row compact">
                <span className="path-pill">{gate.gate}</span>
                <code>{JSON.stringify(gate.inputs ?? [gate.input])}</code>
                <span className="tag tag-stub">out {gate.output}</span>
              </div>
            ))}
          </div>
        </>
      )}
      {loading && !result && <span className="spinner" />}
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
      <ModeAnimatorPanel />
      <MacGamePanel />
      <CcaMalleabilityPanel />
      <MerkleDamgardPanel />
      <DlpHashPanel />
      <BirthdayAttackPanel />
      <HmacComparePanel />
      <DiffieHellmanPanel />
      <RsaDemoPanel />
      <MillerRabinPanel />
      <HastadPanel />
      <SignaturePanel />
      <ElGamalPanel />
      <CcaPkcPanel />
      <OtPanel />
      <SecureAndPanel />
      <MillionairePanel />

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
