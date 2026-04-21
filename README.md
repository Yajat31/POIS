# CS8.401 — Principles of Information Security: Project Implementation

## Overview

A staged cryptographic dependency graph (PA#0–PA#20) built **entirely from scratch** — no external crypto libraries. Starts from one-way functions and builds upward through symmetric crypto, hashing, public-key crypto, oblivious transfer, secure gates, and 2-party MPC.

## Dependency Lineage

```
Foundations (AES-128, DLP safe-prime group)
     │
PA#13 Miller-Rabin (primality testing)
     │
     ├── PA#1 OWF/PRG (DLP-based)
     │    └── PA#2 PRF (GGM tree)
     │         ├── PA#3 CPA Encryption
     │         ├── PA#4 CBC/OFB/CTR Modes
     │         └── PA#5 MACs (PRF-MAC, CBC-MAC)
     │              └── PA#6 CCA Encryption (Encrypt-then-MAC)
     │
     ├── PA#7 Merkle-Damgård Framework
     │    └── PA#8 DLP Hash (CRHF)
     │         ├── PA#9 Birthday Attack
     │         └── PA#10 HMAC + Encrypt-then-HMAC
     │
     ├── PA#11 Diffie-Hellman Key Exchange
     │    └── PA#16 ElGamal Encryption
     │         └── PA#17 CCA-Secure PKC (Signcrypt)
     │
     ├── PA#12 RSA (Textbook + PKCS#1 v1.5)
     │    ├── PA#14 CRT + Håstad Attack
     │    └── PA#15 Digital Signatures
     │
     └── PA#18 Oblivious Transfer (Bellare-Micali)
          └── PA#19 Secure Gates (AND/XOR/NOT)
               └── PA#20 2-Party MPC (Boolean Circuits)

PA#0 Web App (React + FastAPI) — calls all of the above
```

## End-to-End Call Stack (PA#20 → PA#13)

```
PA20 SecureEval
  └─ PA19 AND(a, b)
       └─ PA18 OTReceiverStep1 / OTSenderStep / OTReceiverStep2
            └─ PA16 ElGamal Enc/Dec
                 └─ DLP group (safe prime via PA13 Miller-Rabin)
```

## Quick Start

### Python Backend

```bash
# Install dependencies (no crypto libs!)
pip install -r requirements.txt

# Run all unit tests
pytest tests/ -v

# Check no forbidden imports
python tests/check_imports.py

# Start PA#0 backend
uvicorn pa00_web.backend.api:app --reload --port 8000
```

### React Frontend

```bash
cd pa00_web/frontend
npm install
npm run dev
# → Opens at http://localhost:5173
```

## No-Library Rule

All cryptographic primitives are implemented from scratch:
- **No** PyCryptodome, cryptography, OpenSSL, rsa, nacl
- **Allowed**: `os.urandom`, `int` (arbitrary-precision), `struct`
- Enforced by: `python tests/check_imports.py`

## Assignment Index

| PA | Description | File |
|----|-------------|------|
| PA#0 | Minicrypt Clique Web Explorer | `pa00_web/` |
| PA#1 | OWF and PRG | `src/pa01_owf_prg/owf.py` |
| PA#2 | PRF via GGM | `src/pa02_prf/ggm_prf.py` |
| PA#3 | CPA Encryption | `src/pa03_cpa_enc/cpa_enc.py` |
| PA#4 | CBC/OFB/CTR Modes | `src/pa04_modes/modes.py` |
| PA#5 | MACs | `src/pa05_mac/mac.py` |
| PA#6 | CCA Encryption | `src/pa06_cca_enc/cca_enc.py` |
| PA#7 | Merkle-Damgård | `src/pa07_merkle_damgard/merkle_damgard.py` |
| PA#8 | DLP Hash (CRHF) | `src/pa08_dlp_hash/dlp_hash.py` |
| PA#9 | Birthday Attack | `src/pa09_birthday/birthday.py` |
| PA#10 | HMAC + EtH | `src/pa10_hmac_eth/hmac_eth.py` |
| PA#11 | Diffie-Hellman | `src/pa11_dh/dh.py` |
| PA#12 | RSA | `src/pa12_rsa/rsa.py` |
| PA#13 | Miller-Rabin | `src/pa13_miller_rabin/miller_rabin.py` |
| PA#14 | CRT + Håstad | `src/pa14_crt_attack/crt_attack.py` |
| PA#15 | Signatures | `src/pa15_signatures/signatures.py` |
| PA#16 | ElGamal | `src/pa16_elgamal/elgamal.py` |
| PA#17 | CCA-PKC | `src/pa17_cca_pkc/cca_pkc.py` |
| PA#18 | Oblivious Transfer | `src/pa18_ot/ot.py` |
| PA#19 | Secure Gates | `src/pa19_secure_gates/secure_gates.py` |
| PA#20 | 2-Party MPC | `src/pa20_mpc/mpc.py` |
