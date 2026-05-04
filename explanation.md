# CS8.401 POIS Project Explanation

This project implements the programming assignments from `pois project.pdf`. The PDF's main idea is to make the cryptographic reduction chain concrete in code: start from low-level assumptions and foundations, build Minicrypt primitives, then use them to build symmetric encryption, hashing, public-key cryptography, oblivious transfer, secure gates, and finally general 2-party secure computation.

The implementation follows the PDF's no-library rule: cryptographic primitives are implemented in this repo instead of imported from external crypto libraries. The allowed external support is limited to ordinary Python facilities such as integer arithmetic and OS randomness.

## Big Picture

The assignment is organized around a dependency chain:

```text
Foundations: AES-128 and DLP group
  -> OWF / OWP / PRG
  -> PRF / PRP
  -> MAC / CPA encryption / CCA encryption
  -> Merkle-Damgard / DLP hash / HMAC
  -> DH / RSA / Miller-Rabin / CRT attacks / signatures / ElGamal / CCA-PKC
  -> Oblivious Transfer
  -> Secure AND, XOR, NOT
  -> General 2-party MPC
```

The PDF emphasizes that each later primitive should call the earlier assignment implementation. For example, MPC should not use an MPC library. It should call the secure AND gate from PA#19, which calls OT from PA#18, which calls ElGamal from PA#16, which relies on the DLP group and primality generation.

## Foundations

The foundational code lives in:

- `src/foundations/aes_impl.py`
- `src/foundations/dlp_group.py`
- `src/common/`

`aes_impl.py` is the project's own AES-128 block cipher implementation. It gives the concrete PRP/PRF foundation used by the symmetric constructions.

`dlp_group.py` builds safe-prime DLP groups and provides demo group parameters. DLP is used as the concrete OWF/OWP-style foundation for the Minicrypt and public-key parts.

The `src/common/` package contains support code for randomness, padding, byte conversion, modular arithmetic, CRT, timing-safe comparison, and reduction demos. These are helper utilities, not external crypto libraries.

## PA#0: Minicrypt Clique Web Explorer

Files:

- `pa00_web/backend/api.py`
- `pa00_web/frontend/src/App.jsx`
- `pa00_web/frontend/src/api/client.js`

The PDF requires an interactive React app with a three-tier layout:

- Top foundation selector: AES or DLP.
- Column 1 build panel: construct source primitive A from the selected foundation.
- Column 2 reduce panel: reduce source primitive A to target primitive B using A as a black box.
- Bottom proof panel: show the reduction chain and theorem summary.

The backend implements:

- `/build_foundation_to_primitive`
- `/reduce_primitive_to_target`
- `/reduction_path`
- `/proof_summary`
- `/clique_reductions`

The important architectural rule from the PDF is that Column 2 should consume the primitive handle produced by Column 1. This models reductions as black-box calls instead of letting every target primitive directly call AES or DLP.

## PA#1: OWF, OWP, and PRG

Files:

- `src/pa01_owf_prg/owf.py`
- `src/pa01_owf_prg/owp.py`

The PDF starts the Minicrypt chain with one-way functions and pseudorandom generators.

Implemented ideas:

- DLP-based OWF: `f(x) = g^x mod p`.
- DLP-based OWP on the cyclic subgroup.
- Hard-core-bit based PRG expansion.
- Demonstrations for OWF-to-PRG, PRG-as-OWF, OWP-to-PRG, and other bidirectional clique links.

This assignment provides the first concrete bridge from computational hardness to pseudorandomness.

## PA#2: PRF via GGM

File:

- `src/pa02_prf/ggm_prf.py`

The PDF requires the GGM construction: given a PRG, build a PRF by walking a binary tree according to the input bits.

Implemented ideas:

- `GGMPRF`: PRG-based tree PRF.
- `PRFFromAES`: AES used as a concrete PRF.
- `PRGFromPRF`: reverse direction demonstration, where `G(s) = F_s(0) || F_s(1)`.
- A distinguishing-game demo.

This assignment is the bridge from pseudorandom generators to keyed functions.

## PA#3: CPA-Secure Symmetric Encryption

File:

- `src/pa03_cpa_enc/cpa_enc.py`

The PDF requires CPA-secure encryption from a PRF. The implementation uses a random nonce/counter and PRF-derived keystream.

Main interface:

- `Enc(k, m) -> (r, c)`
- `Dec(k, r, c) -> m`

The key property is randomized encryption: encrypting the same plaintext twice should produce different ciphertexts.

## PA#4: Modes of Operation

File:

- `src/pa04_modes/modes.py`

The PDF asks for standard block-cipher modes using the project's own AES implementation.

Implemented modes:

- CBC
- OFB
- CTR
- Parallel CTR demo

The file also includes demonstrations of mode-specific risks, such as IV/keystream reuse and bit-flipping behavior.

## PA#5: MACs

File:

- `src/pa05_mac/mac.py`

The PDF requires message authentication codes from earlier primitives.

Implemented ideas:

- PRF-MAC.
- CBC-MAC.
- EUF-CMA game demo.
- A naive MAC and length-extension attack demonstration.

There is an intentional HMAC stub in PA#5 because real HMAC is implemented later in PA#10, where the PDF places the HMAC bridge.

## PA#6: CCA-Secure Symmetric Encryption

File:

- `src/pa06_cca_enc/cca_enc.py`

The PDF requires CCA security by combining confidentiality with integrity. The implementation uses encrypt-then-MAC:

```text
ciphertext = PA#3 encryption
tag = PA#5 MAC(ciphertext)
```

Decryption verifies the tag before decrypting. Tampered ciphertexts return `None`, representing rejection.

## PA#7: Merkle-Damgard Transform

File:

- `src/pa07_merkle_damgard/merkle_damgard.py`

The PDF introduces hash construction from a compression function. The implementation provides a generic Merkle-Damgard class where the compression function is pluggable.

This allows later assignments to plug in the DLP compression function from PA#8 or HMAC-style compression from PA#10.

## PA#8: DLP-Based Collision-Resistant Hash

File:

- `src/pa08_dlp_hash/dlp_hash.py`

The PDF requires a DLP-based collision-resistant hash function. The implementation builds a DLP compression function and wraps it in the Merkle-Damgard transform from PA#7.

The important theoretical point is that a collision in this hash can be related to solving a discrete-log style relation.

## PA#9: Birthday Attack

File:

- `src/pa09_birthday/birthday.py`

The PDF asks for collision-finding experiments to demonstrate the birthday bound. The implementation includes:

- Dictionary-based birthday attack.
- Multiple-trial statistics.
- Floyd-style cycle/collision exploration.
- Context calculations for real hash output sizes.

The lesson is that an n-bit hash has an approximate collision security floor around `2^(n/2)` evaluations.

## PA#10: HMAC and Encrypt-then-HMAC

File:

- `src/pa10_hmac_eth/hmac_eth.py`

The PDF uses HMAC as the bridge between CRHF and MAC. This project implements HMAC using the repo's own DLP hash from PA#8, not `hashlib` or Python's `hmac`.

Implemented ideas:

- HMAC.
- HMAC verification.
- Encrypt-then-HMAC CCA encryption.
- Timing comparison demo.
- HMAC as compression / CRHF bridge demonstrations.

## PA#11: Diffie-Hellman Key Exchange

File:

- `src/pa11_dh/dh.py`

The PDF introduces public-key-style shared-key establishment using DLP. The implementation includes:

- Alice and Bob DH steps.
- Honest exchange.
- MITM attack demonstration.
- CDH hardness demo.

The security lesson is that unauthenticated DH is vulnerable to man-in-the-middle attacks.

## PA#12: RSA

File:

- `src/pa12_rsa/rsa.py`

The PDF requires textbook RSA and PKCS#1 v1.5-style padding demos.

Implemented ideas:

- RSA key generation using PA#13 prime generation.
- Textbook RSA encryption/decryption.
- Byte encryption helpers.
- PKCS#1 v1.5 padding and oracle demo.
- Determinism demo for textbook RSA.

Textbook RSA is intentionally shown as insecure without padding.

## PA#13: Miller-Rabin Primality Testing

File:

- `src/pa13_miller_rabin/miller_rabin.py`

The PDF requires probabilistic primality testing and prime generation.

Implemented ideas:

- Modular exponentiation wrapper.
- Miller-Rabin primality test.
- Prime generation.
- Safe-prime generation.
- Fermat test contrast using Carmichael number 561.

This assignment supports RSA and DLP group generation.

## PA#14: CRT and Hastad Broadcast Attack

File:

- `src/pa14_crt_attack/crt_attack.py`

The PDF asks for CRT-based RSA optimization and an attack on textbook RSA with small exponent.

Implemented ideas:

- CRT-based RSA decryption.
- CRT wrapper.
- Integer e-th root.
- Hastad broadcast attack.
- Speedup demo.

The attack shows why deterministic textbook RSA is not semantically secure.

## PA#15: Digital Signatures

File:

- `src/pa15_signatures/signatures.py`

The PDF requires hash-then-sign RSA signatures.

Implemented ideas:

- `Sign(sk, m)`.
- `Verify(vk, m, sigma)`.
- DLP-hash-before-RSA signing.
- Multiplicative forgery demo for raw RSA signatures.
- EUF-CMA style game demo.

The main lesson is that raw RSA signatures are algebraically forgeable, so messages must be hashed before signing.

## PA#16: ElGamal Public-Key Encryption

File:

- `src/pa16_elgamal/elgamal.py`

The PDF requires ElGamal encryption over the PA#11 DLP group.

Implemented ideas:

- ElGamal key generation.
- Group-element encryption/decryption.
- Byte/blob encryption helpers.
- Malleability attack demo.
- CPA game demo.

ElGamal is CPA-secure under suitable assumptions but malleable, so it is not CCA-secure by itself.

## PA#17: CCA-Secure PKC

File:

- `src/pa17_cca_pkc/cca_pkc.py`

The PDF requires combining public-key encryption with signatures so tampering is rejected before decryption.

Implemented construction:

```text
CE = ElGamal_Enc(pk_enc, m)
sigma = Sign(sk_sign, CE)
output = (CE, sigma)
```

Decryption verifies the signature first. If verification fails, it returns `None` without decrypting.

This blocks the malleability attack that works against plain ElGamal.

## PA#18: Oblivious Transfer

File:

- `src/pa18_ot/ot.py`

The PDF requires 1-out-of-2 OT using the project's own public-key cryptography.

Implemented API:

- `OTReceiverStep1(b) -> (pk0, pk1, state)`
- `OTSenderStep(pk0, pk1, m0, m1) -> (C0, C1)`
- `OTReceiverStep2(state, C0, C1) -> m_b`

The receiver learns only the selected message. The sender sees two public keys and should not learn which one corresponds to the receiver's choice.

## PA#19: Secure Gates

File:

- `src/pa19_secure_gates/secure_gates.py`

The PDF explains that secure AND plus free XOR/NOT is enough to build arbitrary boolean circuits.

Implemented gates:

- `AND(a, b)` using PA#18 OT.
- `XOR(a, b)` locally.
- `NOT(a)` locally.
- Truth-table testing.

The key dependency is:

```text
PA#19 AND -> PA#18 OT -> PA#16 ElGamal
```

## PA#20: General 2-Party MPC

File:

- `src/pa20_mpc/mpc.py`

The PDF's final assignment is secure evaluation of arbitrary boolean circuits from secure gates.

Implemented pieces:

- `Circuit` representation.
- `SecureEval(circuit, x_alice, y_bob)`.
- Equality circuit.
- Millionaire comparison circuit.
- Addition circuit.
- Demo that reports output correctness and AND-call counts.

The intended lineage is:

```text
PA20 SecureEval
  -> PA19 AND
  -> PA18 OT
  -> PA16 ElGamal
  -> DLP group / PA13 prime generation
```

This completes the PDF's stack from primitive assumptions to secure computation.

## Tests and Verification

The repo includes:

- `tests/unit/`: unit tests for foundations and assignment APIs.
- `tests/integration/`: dependency-lineage tests.
- `tests/adversarial/`: security-game and attack demos.
- `tests/check_imports.py`: static guard against forbidden crypto imports.
- `tests/benchmarks/`: benchmark scripts.
- `tests/demos/`: demo-result scripts.

Recommended checks after creating a virtual environment:

```bash
python tests/check_imports.py
pytest tests/unit/ -v
pytest tests/integration/ -v
pytest tests/adversarial/ -v
```

For PA#0:

```bash
uvicorn pa00_web.backend.api:app --reload --port 8000
cd pa00_web/frontend
npm install
npm run dev
```

## What This Submission Demonstrates

The repo demonstrates the assignment's main requirement: cryptographic objects are not treated as isolated black boxes from libraries. Instead, each layer is built from previous layers and includes tests or demos showing the required security notion, attack, or reduction.

In short:

- PA#1-#2 build the Minicrypt pseudorandomness core.
- PA#3-#6 build symmetric encryption and authentication.
- PA#7-#10 build hashing, collision experiments, and HMAC.
- PA#11-#17 build public-key cryptography and attacks/repairs.
- PA#18-#20 build OT, secure gates, and general MPC.
- PA#0 visualizes the reduction chain interactively.
