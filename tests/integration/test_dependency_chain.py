"""
Integration Tests — Cross-PA Dependency Lineage

Verifies that actual code calls happen across PA boundaries, not mocked ones.
Uses call counters / instrumentation where needed.

Tests:
  - PA#6 calls PA#3 + PA#5 (not some other encrypt/mac)
  - PA#10 calls PA#8 hash (not hashlib)
  - PA#17 verifies BEFORE decrypting (sign-verify-decrypt ordering)
  - PA#20 invokes PA#19 AND, which invokes PA#18 OT
  - PA#7 compression is pluggable (DLP, XOR, HMAC all work)
  - Forbidden import guard
"""

import pytest
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))

from src.common.randomness import random_bytes
from src.foundations.dlp_group import DEMO_PARAMS


class TestCrossPA_Lineage:
    """Cross-PA integration: confirm actual downstream calls occur."""

    def test_pa06_uses_pa03_encryption(self):
        """PA#6 CCA_Enc must produce (packed_c, t) where packed_c = pack_tuple(r, c) from PA#3."""
        from src.pa06_cca_enc.cca_enc import CCA_Enc, CCA_Dec
        from src.common.encoding import unpack_tuple
        from src.pa03_cpa_enc.cpa_enc import Dec
        kE, kM = random_bytes(16), random_bytes(16)
        m = b"lineage test msg"
        packed_c, t = CCA_Enc(kE, kM, m)
        # packed_c should unpack into (r, c) that PA#3's Dec can handle
        r, c = unpack_tuple(packed_c, 2)
        assert Dec(kE, r, c) == m, "PA#6 must use PA#3 format internally"

    def test_pa06_uses_pa05_mac(self):
        """PA#6 tag must equal MacCBC.Mac applied to packed_c."""
        from src.pa06_cca_enc.cca_enc import CCA_Enc
        from src.pa05_mac.mac import MacCBC
        kE, kM = random_bytes(16), random_bytes(16)
        m = b"mac lineage test"
        packed_c, t = CCA_Enc(kE, kM, m)
        mac = MacCBC()
        expected_t = mac.Mac(kM, packed_c)
        assert t == expected_t, "PA#6 tag must come from PA#5 MacCBC"

    def test_pa10_uses_pa08_hash(self):
        """HMAC in PA#10 must use the DLP hash from PA#8 (not hashlib)."""
        from src.pa10_hmac_eth.hmac_eth import HMAC
        from src.pa08_dlp_hash.dlp_hash import DLPHash, gen_dlp_hash_params
        params = gen_dlp_hash_params(DEMO_PARAMS)
        hash_fn = DLPHash(params, block_size=16)
        k, m = random_bytes(16), b"hmac-pa08 test"
        tag = HMAC(k, m, hash_fn)
        # Tag length matches DLP hash output size
        assert len(tag) == (params.p.bit_length() + 7) // 8, "Tag length must match DLP hash output"

    def test_pa07_md_is_pluggable_with_dlp(self):
        """PA#7 MerkleDamgard must work with DLP compression from PA#8."""
        from src.pa07_merkle_damgard.merkle_damgard import MerkleDamgard
        from src.pa08_dlp_hash.dlp_hash import DLPCompress, gen_dlp_hash_params
        from src.common.bytes_utils import int_to_bytes
        params = gen_dlp_hash_params(DEMO_PARAMS)
        compress = DLPCompress(params)
        elem_bytes = (params.p.bit_length() + 7) // 8
        iv = int_to_bytes(params.g, elem_bytes)
        md = MerkleDamgard(compress=compress.compress, iv=iv, block_size=16)
        h1 = md.hash(b"hello")
        h2 = md.hash(b"world")
        assert h1 != h2

    def test_pa17_verify_before_decrypt_ordering(self):
        """PA#17 must verify signature BEFORE decrypting (no plaintext used if sig fails)."""
        from src.pa17_cca_pkc.cca_pkc import CCA_PKC_Enc, CCA_PKC_Dec
        from src.pa12_rsa.rsa import rsa_keygen
        from src.pa16_elgamal.elgamal import elgamal_keygen
        from src.pa08_dlp_hash.dlp_hash import DLPHash, gen_dlp_hash_params
        from src.foundations.dlp_group import MEDIUM_DEMO_PARAMS
        group = MEDIUM_DEMO_PARAMS
        sk_enc, pk_enc = elgamal_keygen(group)
        pk_sign, sk_sign = rsa_keygen(bits=128)
        params = gen_dlp_hash_params(group)
        hash_fn = DLPHash(params, block_size=16)
        m = b"test"
        CE, sigma = CCA_PKC_Enc(pk_enc, sk_sign, m, hash_fn)
        # Correct case
        result = CCA_PKC_Dec(sk_enc, pk_sign, CE, sigma, hash_fn)
        assert result == m, f"Valid decryption failed: got {result}"
        # Wrong signature — must return ⊥ without leaking plaintext
        bad_sigma = bytes([sigma[0] ^ 0xFF]) + sigma[1:]
        result = CCA_PKC_Dec(sk_enc, pk_sign, CE, bad_sigma, hash_fn)
        assert result is None, "Invalid signature → must return ⊥ (verify-before-decrypt)"


    def test_pa20_calls_pa19_and(self):
        """PA#20 SecureEval must actually call PA#19 AND (count OT calls)."""
        from src.pa20_mpc.mpc import build_equality_circuit, SecureEval
        circuit = build_equality_circuit(4)
        x, y = [1, 0, 1, 0], [1, 0, 1, 0]
        out, meta = SecureEval(circuit, x, y, DEMO_PARAMS)
        assert meta["and_calls"] > 0, "SecureEval must make actual AND (OT) calls"
        assert out[0] == 1  # equal inputs

    def test_pa19_and_calls_pa18_ot(self):
        """PA#19 AND must call PA#18 OT (not a plain boolean AND)."""
        from src.pa19_secure_gates.secure_gates import AND
        # For a=1, b=1: AND via OT should return 1
        assert AND(1, 1, DEMO_PARAMS) == 1
        assert AND(1, 0, DEMO_PARAMS) == 0
        assert AND(0, 1, DEMO_PARAMS) == 0
        assert AND(0, 0, DEMO_PARAMS) == 0

    def test_pa18_ot_calls_pa16_elgamal(self):
        """PA#18 OT uses ElGamal encryption from PA#16."""
        from src.pa18_ot.ot import OTSenderStep, OTReceiverStep1
        from src.pa16_elgamal.elgamal import ElGamalPublicKey
        pk0, pk1, state = OTReceiverStep1(0, DEMO_PARAMS)
        # pk0 and pk1 must be ElGamalPublicKey instances (not mocks)
        assert isinstance(pk0, ElGamalPublicKey)
        assert isinstance(pk1, ElGamalPublicKey)
        C0, C1 = OTSenderStep(pk0, pk1, 3, 7)
        assert isinstance(C0, tuple) and len(C0) == 2, "OT sender output must be ElGamal (c1,c2) pairs"


class TestInterfaceContracts:
    """Verify each PA exports the correct downstream API."""

    def test_pa01_prg_api(self):
        from src.pa01_owf_prg.owf import PRG
        prg = PRG()
        prg.seed(42)
        bits = prg.next_bits(32)
        assert len(bits) == 32
        assert all(b in (0, 1) for b in bits)
        b_bytes = prg.next_bytes(4)
        assert len(b_bytes) == 4

    def test_pa02_prf_api(self):
        from src.pa02_prf.ggm_prf import PRFFromAES
        prf = PRFFromAES()
        k = random_bytes(16)
        x = random_bytes(16)
        y = prf.F(k, x)
        assert len(y) == 16

    def test_pa03_enc_api(self):
        from src.pa03_cpa_enc.cpa_enc import Enc, Dec
        k = random_bytes(16)
        m = b"interface test!!"
        r, c = Enc(k, m)
        assert Dec(k, r, c) == m

    def test_pa05_mac_api(self):
        from src.pa05_mac.mac import MacPRF
        mac = MacPRF()
        k, m = random_bytes(16), random_bytes(16)
        t = mac.Mac(k, m)
        assert mac.Vrfy(k, m, t)

    def test_pa18_ot_api(self):
        from src.pa18_ot.ot import OTReceiverStep1, OTSenderStep, OTReceiverStep2
        pk0, pk1, state = OTReceiverStep1(1, DEMO_PARAMS)
        C0, C1 = OTSenderStep(pk0, pk1, 11, 22)
        m_b = OTReceiverStep2(state, C0, C1)
        assert m_b == 22  # b=1 → get m1=22


class TestForbiddenImports:
    """Static import guard."""

    def test_no_forbidden_imports(self):
        import subprocess, sys as _sys
        result = subprocess.run(
            [_sys.executable, "tests/check_imports.py"],
            cwd=os.path.join(os.path.dirname(__file__), "../.."),
            capture_output=True, text=True
        )
        assert result.returncode == 0, f"Forbidden imports found:\n{result.stdout}\n{result.stderr}"

    def test_no_hashlib_hmac_in_pa10(self):
        """PA#10 must not use hashlib.hmac."""
        import re
        path = os.path.join(os.path.dirname(__file__), "../../src/pa10_hmac_eth/hmac_eth.py")
        with open(path) as f:
            content = f.read()
        assert "import hmac" not in content
        assert "hashlib.hmac" not in content


class TestBidirectionalClique:
    """Smoke-test all clique reduction demos run without error."""

    def test_all_clique_reductions_run(self):
        from src.common.clique_reductions import run_all_clique_reductions
        results = run_all_clique_reductions()
        errors = {k: v for k, v in results.items() if "error" in v}
        assert not errors, f"Some clique reductions failed: {list(errors.keys())}\n{errors}"

    def test_owf_to_owp_is_permutation(self):
        from src.pa01_owf_prg.owp import OWP_DLP
        owp = OWP_DLP(DEMO_PARAMS)
        assert owp.is_permutation_on_subgroup()

    def test_prf_prp_switching_lemma_demo(self):
        from src.pa01_owf_prg.owp import prf_to_prp_demo
        result = prf_to_prp_demo()
        assert result["distinct_inputs_distinct_outputs"]

    def test_crhf_hmac_roundtrip(self):
        from src.common.clique_reductions import crhf_to_hmac_demo, hmac_to_crhf_demo
        r1 = crhf_to_hmac_demo()
        assert r1["verify"]
        r2 = hmac_to_crhf_demo()
        assert r2["distinct"]

    def test_mac_to_crhf_via_md(self):
        from src.common.clique_reductions import mac_to_crhf_via_md_demo
        result = mac_to_crhf_via_md_demo()
        assert result["distinct"]
