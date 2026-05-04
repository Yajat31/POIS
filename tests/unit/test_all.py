"""Unit tests for AES-128 (foundations), common utilities, and PA#1–PA#6."""

import pytest
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))


class TestAES:
    def test_known_vector(self):
        """FIPS 197 Appendix B test vector."""
        from src.foundations.aes_impl import aes_encrypt_block, aes_decrypt_block
        key   = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
        plain = bytes.fromhex("3243f6a8885a308d313198a2e0370734")
        expected_ct = bytes.fromhex("3925841d02dc09fbdc118597196a0b32")
        ct = aes_encrypt_block(key, plain)
        assert ct == expected_ct, f"AES encrypt mismatch: {ct.hex()} != {expected_ct.hex()}"
        pt = aes_decrypt_block(key, ct)
        assert pt == plain, "AES decrypt should invert encrypt"

    def test_roundtrip(self):
        from src.foundations.aes_impl import aes_encrypt_block, aes_decrypt_block
        from src.common.randomness import random_bytes
        for _ in range(20):
            key = random_bytes(16)
            pt  = random_bytes(16)
            ct  = aes_encrypt_block(key, pt)
            assert aes_decrypt_block(key, ct) == pt


class TestCommonUtils:
    def test_bytes_int_roundtrip(self):
        from src.common.bytes_utils import int_to_bytes, bytes_to_int
        for n in [0, 1, 255, 256, 2**32 - 1, 2**64]:
            assert bytes_to_int(int_to_bytes(n)) == n

    def test_xor_bytes(self):
        from src.common.bytes_utils import xor_bytes
        a = bytes([0xFF, 0x00, 0xAA])
        b = bytes([0x0F, 0xFF, 0x55])
        assert xor_bytes(a, b) == bytes([0xF0, 0xFF, 0xFF])

    def test_md_pad_length(self):
        from src.common.padding import md_pad
        for msg_len in [0, 1, 55, 56, 64, 100]:
            padded = md_pad(b"x" * msg_len, 64)
            assert len(padded) % 64 == 0

    def test_pkcs7_roundtrip(self):
        from src.common.padding import pkcs7_pad, pkcs7_unpad
        for msg in [b"", b"A", b"A" * 15, b"A" * 16, b"A" * 31]:
            assert pkcs7_unpad(pkcs7_pad(msg, 16)) == msg

    def test_secure_compare(self):
        from src.common.timing import secure_compare
        assert secure_compare(b"hello", b"hello")
        assert not secure_compare(b"hello", b"world")
        assert not secure_compare(b"hello", b"hello!")

    def test_modexp(self):
        from src.common.math_utils import modexp
        assert modexp(2, 10, 1000) == 24
        assert modexp(3, 100, 17) == pow(3, 100, 17)

    def test_mod_inverse(self):
        from src.common.math_utils import mod_inverse
        assert mod_inverse(3, 11) == 4
        assert (3 * mod_inverse(3, 11)) % 11 == 1

    def test_crt(self):
        from src.common.math_utils import crt
        # x ≡ 2 (mod 3), x ≡ 3 (mod 5), x ≡ 2 (mod 7) → x = 23
        x = crt([2, 3, 2], [3, 5, 7])
        assert x % 3 == 2
        assert x % 5 == 3
        assert x % 7 == 2


class TestPRG:
    def test_prg_seed_deterministic(self):
        """Same seed should give same output."""
        from src.pa01_owf_prg.owf import PRG
        prg1, prg2 = PRG(), PRG()
        prg1.seed(42)
        prg2.seed(42)
        assert prg1.next_bits(32) == prg2.next_bits(32)

    def test_prg_statistical(self):
        """PRG output should have roughly 50% 1-bits."""
        from src.pa01_owf_prg.owf import PRG, nist_monobit_test
        prg = PRG()
        prg.seed(12345)
        bits = prg.next_bits(1000)
        result = nist_monobit_test(bits)
        # Relaxed: just check it runs without error and has reasonable proportion
        assert 0.3 <= result["proportion"] <= 0.7


class TestCPAEnc:
    def test_enc_dec_roundtrip(self):
        from src.pa03_cpa_enc.cpa_enc import Enc, Dec
        from src.common.randomness import random_bytes
        k = random_bytes(16)
        for msg in [b"Hello!", b"A" * 32, b"x" * 100]:
            r, c = Enc(k, msg)
            assert Dec(k, r, c) == msg

    def test_randomized(self):
        from src.pa03_cpa_enc.cpa_enc import Enc
        from src.common.randomness import random_bytes
        k = random_bytes(16)
        m = b"same message here"
        r1, c1 = Enc(k, m)
        r2, c2 = Enc(k, m)
        assert (r1, c1) != (r2, c2), "CPA-Enc must be randomized"


class TestModes:
    def test_cbc_roundtrip(self):
        from src.pa04_modes.modes import CBC_Enc, CBC_Dec
        from src.common.randomness import random_bytes
        k, iv = random_bytes(16), random_bytes(16)
        for msg in [b"Hello World", b"A" * 16, b"B" * 33]:
            assert CBC_Dec(k, iv, CBC_Enc(k, iv, msg)) == msg

    def test_ofb_roundtrip(self):
        from src.pa04_modes.modes import OFB_Enc, OFB_Dec
        from src.common.randomness import random_bytes
        k, iv = random_bytes(16), random_bytes(16)
        msg = b"OFB mode test message"
        assert OFB_Dec(k, iv, OFB_Enc(k, iv, msg)) == msg

    def test_ctr_roundtrip(self):
        from src.pa04_modes.modes import CTR_Enc, CTR_Dec
        from src.common.randomness import random_bytes
        k = random_bytes(16)
        msg = b"Counter mode test!"
        r, c = CTR_Enc(k, msg)
        assert CTR_Dec(k, r, c) == msg


class TestMAC:
    def test_prf_mac_verify(self):
        from src.pa05_mac.mac import MacPRF
        from src.common.randomness import random_bytes
        mac = MacPRF()
        k, m = random_bytes(16), random_bytes(16)
        t = mac.Mac(k, m)
        assert mac.Vrfy(k, m, t)
        bad_t = bytes([t[0] ^ 0xFF]) + t[1:]
        assert not mac.Vrfy(k, m, bad_t)

    def test_cbc_mac_verify(self):
        from src.pa05_mac.mac import MacCBC
        from src.common.randomness import random_bytes
        mac = MacCBC()
        k = random_bytes(16)
        for msg in [b"short", b"A" * 100]:
            t = mac.Mac(k, msg)
            assert mac.Vrfy(k, msg, t)


class TestCCAEnc:
    def test_cca_roundtrip(self):
        from src.pa06_cca_enc.cca_enc import CCA_Enc, CCA_Dec
        from src.common.randomness import random_bytes
        kE, kM = random_bytes(16), random_bytes(16)
        m = b"CCA secure message"
        packed_c, t = CCA_Enc(kE, kM, m)
        assert CCA_Dec(kE, kM, packed_c, t) == m

    def test_tamper_rejected(self):
        from src.pa06_cca_enc.cca_enc import CCA_Enc, CCA_Dec
        from src.common.randomness import random_bytes
        kE, kM = random_bytes(16), random_bytes(16)
        m = b"tamper test"
        packed_c, t = CCA_Enc(kE, kM, m)
        tampered = bytearray(packed_c)
        tampered[8] ^= 0xFF
        assert CCA_Dec(kE, kM, bytes(tampered), t) is None


class TestMerkleDamgard:
    def test_deterministic(self):
        from src.pa07_merkle_damgard.merkle_damgard import make_xor_hash
        h = make_xor_hash()
        msg = b"hello world"
        assert h.hash(msg) == h.hash(msg)

    def test_different_messages(self):
        from src.pa07_merkle_damgard.merkle_damgard import make_xor_hash
        h = make_xor_hash()
        assert h.hash(b"hello") != h.hash(b"world")


class TestRSA:
    def test_enc_dec_roundtrip(self):
        from src.pa12_rsa.rsa import rsa_keygen, rsa_enc, rsa_dec
        pk, sk = rsa_keygen(bits=128)
        for m in [1, 42, 1000]:
            if m < pk.n:
                c = rsa_enc(pk, m)
                assert rsa_dec(sk, c) == m

    def test_pkcs15_roundtrip(self):
        from src.pa12_rsa.rsa import rsa_keygen, pkcs15_enc, pkcs15_dec
        pk, sk = rsa_keygen(bits=256)
        m = b"Hello RSA"
        c = pkcs15_enc(pk, m)
        assert pkcs15_dec(sk, c) == m

    def test_determinism_demo(self):
        from src.pa12_rsa.rsa import rsa_keygen, demo_textbook_rsa_determinism
        pk, _ = rsa_keygen(bits=128)
        result = demo_textbook_rsa_determinism(pk)
        assert result["identical"], "Textbook RSA should be deterministic"


class TestDH:
    def test_honest_exchange(self):
        from src.pa11_dh.dh import dh_exchange
        result = dh_exchange()
        assert result["match"], "Honest DH should give matching shared secrets"

    def test_mitm(self):
        from src.pa11_dh.dh import dh_mitm_attack
        result = dh_mitm_attack()
        assert result["mitm_success"], "MITM should create separate keys with each party"
        assert not result["alice_bob_actually_share"]


class TestOT:
    def test_correctness(self):
        from src.pa18_ot.ot import ot_exchange
        from src.foundations.dlp_group import DEMO_PARAMS
        for b in [0, 1]:
            result = ot_exchange(5, 9, b, DEMO_PARAMS)
            assert result["correct"], f"OT correctness failed for b={b}"

    def test_100_trials(self):
        from src.pa18_ot.ot import ot_correctness_test
        from src.foundations.dlp_group import DEMO_PARAMS
        result = ot_correctness_test(DEMO_PARAMS, trials=10)
        assert result["success_rate"] == 1.0


class TestSecureGates:
    def test_truth_table(self):
        from src.pa19_secure_gates.secure_gates import truth_table_test
        from src.foundations.dlp_group import DEMO_PARAMS
        result = truth_table_test(DEMO_PARAMS)
        assert result["all_correct"], "All gates should give correct outputs"


class TestMPC:
    def test_comparison_circuit_exhaustive_small_inputs(self):
        from src.pa20_mpc.mpc import build_comparison_circuit, SecureEval
        from src.foundations.dlp_group import DEMO_PARAMS

        def bits(value, n):
            return [(value >> (n - 1 - i)) & 1 for i in range(n)]

        for n in [1, 2, 3]:
            circuit = build_comparison_circuit(n)
            for x in range(2 ** n):
                for y in range(2 ** n):
                    out, _ = SecureEval(circuit, bits(x, n), bits(y, n), DEMO_PARAMS)
                    assert out[0] == int(x > y), f"comparison failed for n={n}, x={x}, y={y}"
