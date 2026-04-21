"""
aes_impl.py — AES-128 from scratch.

Implements the complete AES-128 cipher per FIPS 197 without any library calls.
Provides:
  - aes_encrypt_block(key: bytes, block: bytes) -> bytes   (16-byte key, 16-byte block)
  - aes_decrypt_block(key: bytes, block: bytes) -> bytes

Used as the block-cipher plug-in for:
  - PA#2 (PRFFromAES)
  - PA#4 (CBC, OFB, CTR modes)
"""

# ─────────────────────────────────────────────────────────────
#  AES S-Box and Inverse S-Box (FIPS 197, §5.1.1)
# ─────────────────────────────────────────────────────────────

_SBOX = [
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
]

_INV_SBOX = [0] * 256
for _i, _v in enumerate(_SBOX):
    _INV_SBOX[_v] = _i

# Round constants (FIPS 197 §5.2)
_RCON = [
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36,
]


# ─────────────────────────────────────────────────────────────
#  GF(2^8) multiply — xtime and general multiply
# ─────────────────────────────────────────────────────────────

def _xtime(a: int) -> int:
    """Multiply by x (0x02) in GF(2^8) mod 0x11B."""
    return ((a << 1) ^ 0x1B) & 0xFF if (a & 0x80) else (a << 1) & 0xFF


def _gf_mul(a: int, b: int) -> int:
    """Multiply two bytes in GF(2^8)."""
    result = 0
    for _ in range(8):
        if b & 1:
            result ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        b >>= 1
    return result


# ─────────────────────────────────────────────────────────────
#  Key Expansion (FIPS 197 §5.2)
# ─────────────────────────────────────────────────────────────

def _key_expansion(key: bytes) -> list[list[int]]:
    """Expand a 16-byte AES-128 key into 11 round keys (each 16 bytes)."""
    assert len(key) == 16, "AES-128 requires exactly 16 bytes"
    # W is 44 words of 4 bytes each
    W = [list(key[i * 4 : i * 4 + 4]) for i in range(4)]
    for i in range(4, 44):
        temp = list(W[i - 1])
        if i % 4 == 0:
            # RotWord
            temp = temp[1:] + temp[:1]
            # SubWord
            temp = [_SBOX[b] for b in temp]
            # XOR with Rcon
            temp[0] ^= _RCON[i // 4 - 1]
        W.append([W[i - 4][j] ^ temp[j] for j in range(4)])
    # Group into 11 round keys (each = 4 words = 16 bytes)
    round_keys = []
    for r in range(11):
        rk = []
        for w in range(4):
            rk.extend(W[r * 4 + w])
        round_keys.append(rk)
    return round_keys


# ─────────────────────────────────────────────────────────────
#  State helpers (4x4 byte array, column-major)
# ─────────────────────────────────────────────────────────────

def _bytes_to_state(block: bytes) -> list[list[int]]:
    """Convert 16-byte block to 4x4 state matrix (column-major)."""
    s = [[0] * 4 for _ in range(4)]
    for i in range(16):
        s[i % 4][i // 4] = block[i]
    return s


def _state_to_bytes(s: list[list[int]]) -> bytes:
    """Convert 4x4 state matrix to 16-byte block (column-major)."""
    out = bytearray(16)
    for i in range(16):
        out[i] = s[i % 4][i // 4]
    return bytes(out)


def _add_round_key(state: list[list[int]], rk: list[int]) -> None:
    """XOR state with round key (in-place)."""
    for col in range(4):
        for row in range(4):
            state[row][col] ^= rk[col * 4 + row]


# ─────────────────────────────────────────────────────────────
#  SubBytes, ShiftRows, MixColumns (encrypt direction)
# ─────────────────────────────────────────────────────────────

def _sub_bytes(state: list[list[int]]) -> None:
    for r in range(4):
        for c in range(4):
            state[r][c] = _SBOX[state[r][c]]


def _shift_rows(state: list[list[int]]) -> None:
    for r in range(1, 4):
        state[r] = state[r][r:] + state[r][:r]


def _mix_columns(state: list[list[int]]) -> None:
    for c in range(4):
        s0, s1, s2, s3 = state[0][c], state[1][c], state[2][c], state[3][c]
        state[0][c] = _gf_mul(0x02, s0) ^ _gf_mul(0x03, s1) ^ s2 ^ s3
        state[1][c] = s0 ^ _gf_mul(0x02, s1) ^ _gf_mul(0x03, s2) ^ s3
        state[2][c] = s0 ^ s1 ^ _gf_mul(0x02, s2) ^ _gf_mul(0x03, s3)
        state[3][c] = _gf_mul(0x03, s0) ^ s1 ^ s2 ^ _gf_mul(0x02, s3)


# ─────────────────────────────────────────────────────────────
#  Inverse operations (decrypt direction)
# ─────────────────────────────────────────────────────────────

def _inv_sub_bytes(state: list[list[int]]) -> None:
    for r in range(4):
        for c in range(4):
            state[r][c] = _INV_SBOX[state[r][c]]


def _inv_shift_rows(state: list[list[int]]) -> None:
    for r in range(1, 4):
        state[r] = state[r][4 - r :] + state[r][: 4 - r]


def _inv_mix_columns(state: list[list[int]]) -> None:
    for c in range(4):
        s0, s1, s2, s3 = state[0][c], state[1][c], state[2][c], state[3][c]
        state[0][c] = _gf_mul(0x0E, s0) ^ _gf_mul(0x0B, s1) ^ _gf_mul(0x0D, s2) ^ _gf_mul(0x09, s3)
        state[1][c] = _gf_mul(0x09, s0) ^ _gf_mul(0x0E, s1) ^ _gf_mul(0x0B, s2) ^ _gf_mul(0x0D, s3)
        state[2][c] = _gf_mul(0x0D, s0) ^ _gf_mul(0x09, s1) ^ _gf_mul(0x0E, s2) ^ _gf_mul(0x0B, s3)
        state[3][c] = _gf_mul(0x0B, s0) ^ _gf_mul(0x0D, s1) ^ _gf_mul(0x09, s2) ^ _gf_mul(0x0E, s3)


# ─────────────────────────────────────────────────────────────
#  Public API
# ─────────────────────────────────────────────────────────────

def aes_encrypt_block(key: bytes, block: bytes) -> bytes:
    """Encrypt a single 16-byte block with a 16-byte AES-128 key."""
    if len(key) != 16:
        raise ValueError("AES-128 requires a 16-byte key")
    if len(block) != 16:
        raise ValueError("AES-128 operates on 16-byte blocks")

    round_keys = _key_expansion(key)
    state = _bytes_to_state(block)

    # Initial round key addition
    _add_round_key(state, round_keys[0])

    # Rounds 1–9
    for r in range(1, 10):
        _sub_bytes(state)
        _shift_rows(state)
        _mix_columns(state)
        _add_round_key(state, round_keys[r])

    # Final round (no MixColumns)
    _sub_bytes(state)
    _shift_rows(state)
    _add_round_key(state, round_keys[10])

    return _state_to_bytes(state)


def aes_decrypt_block(key: bytes, block: bytes) -> bytes:
    """Decrypt a single 16-byte block with a 16-byte AES-128 key."""
    if len(key) != 16:
        raise ValueError("AES-128 requires a 16-byte key")
    if len(block) != 16:
        raise ValueError("AES-128 operates on 16-byte blocks")

    round_keys = _key_expansion(key)
    state = _bytes_to_state(block)

    # Initial (inverse final round)
    _add_round_key(state, round_keys[10])

    # Rounds 9–1
    for r in range(9, 0, -1):
        _inv_shift_rows(state)
        _inv_sub_bytes(state)
        _add_round_key(state, round_keys[r])
        _inv_mix_columns(state)

    # Final inverse round
    _inv_shift_rows(state)
    _inv_sub_bytes(state)
    _add_round_key(state, round_keys[0])

    return _state_to_bytes(state)
