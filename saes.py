# -*- coding: utf-8 -*-
"""
saes.py
========
Implementasi manual algoritma Simplified AES (S-AES) — TANPA library kriptografi.

Referensi akademik:
    Musa, M. A., Schaefer, E. F., & Wedig, S. (2003).
    "A Simplified AES Algorithm and Its Linear and Differential Cryptanalyses."
    Cryptologia, 27(2), 148-177.

Parameter S-AES yang digunakan:
    - Ukuran blok  : 16 bit (plaintext / ciphertext)
    - Ukuran key   : 16 bit
    - Field        : GF(2^4)
    - Polinomial irreducible : x^4 + x + 1  (0b10011 / 0x13)
    - RCON1 = 0x80 (10000000)
    - RCON2 = 0x30 (00110000)

Semua fungsi wajib (RotWord, SubWord, SubNibble, InvSubNibble, ShiftRows,
InvShiftRows, MixColumns, InvMixColumns, AddRoundKey, GFAdd, GFMul, Encrypt,
Decrypt) diimplementasikan murni dengan operasi bit/list Python biasa.
"""

from copy import deepcopy

# --------------------------------------------------------------------------
# 1. KONSTANTA S-AES
# --------------------------------------------------------------------------

# S-Box standar S-AES, diindeks [baris][kolom] dengan baris = 2 bit tinggi,
# kolom = 2 bit rendah dari nibble 4-bit.
SBOX = [
    [0x9, 0x4, 0xA, 0xB],
    [0xD, 0x1, 0x8, 0x5],
    [0x6, 0x2, 0x0, 0x3],
    [0xC, 0xE, 0xF, 0x7],
]

# Inverse S-Box standar S-AES
INV_SBOX = [
    [0xA, 0x5, 0x9, 0xB],
    [0x1, 0x7, 0x8, 0xF],
    [0x6, 0x0, 0x2, 0x3],
    [0xC, 0x4, 0xD, 0xE],
]

RCON1 = 0x80  # 1000 0000
RCON2 = 0x30  # 0011 0000

# Polinomial irreducible x^4 + x + 1 -> jika terjadi overflow pada perkalian
# GF(2^4), maka hasil di-XOR dengan 0b0011 (karena x^4 ekuivalen dengan x+1)
IRREDUCIBLE_REDUCE = 0x3


# --------------------------------------------------------------------------
# 2. OPERASI DASAR GF(2^4)
# --------------------------------------------------------------------------

def gf_add(a: int, b: int) -> int:
    """Penjumlahan pada GF(2^4) == operasi XOR biasa."""
    return (a ^ b) & 0xF


def gf_mult(a: int, b: int) -> int:
    """Perkalian dua nibble (4-bit) pada GF(2^4) mod x^4+x+1 (versi cepat)."""
    a &= 0xF
    b &= 0xF
    p = 0
    for _ in range(4):
        if b & 1:
            p ^= a
        carry = a & 0x8
        a = (a << 1) & 0xF
        if carry:
            a ^= IRREDUCIBLE_REDUCE
        b >>= 1
    return p & 0xF


def gf_mult_verbose(a: int, b: int, label_a="a", label_b="b"):
    """
    Sama seperti gf_mult tetapi mengembalikan (hasil, daftar_langkah)
    untuk keperluan visualisasi step-by-step di web (metode 'russian
    peasant multiplication' yang dipakai untuk perkalian GF(2^4)).
    """
    a &= 0xF
    b &= 0xF
    orig_a, orig_b = a, b
    steps = []
    p = 0
    steps.append(
        f"Kalikan {label_a}={orig_a:04b}\u2082 ({orig_a}) dengan "
        f"{label_b}={orig_b:04b}\u2082 ({orig_b}) pada GF(2\u2074), "
        f"modulus x\u2074+x+1"
    )
    for i in range(4):
        if b & 1:
            new_p = p ^ a
            steps.append(
                f"  Langkah {i+1}: bit-{i} dari b = 1 \u2192 "
                f"p = p \u2295 a = {p:04b} \u2295 {a:04b} = {new_p:04b}"
            )
            p = new_p
        else:
            steps.append(
                f"  Langkah {i+1}: bit-{i} dari b = 0 \u2192 p tetap {p:04b}"
            )
        carry = a & 0x8
        shifted = (a << 1) & 0xF
        if carry:
            reduced = shifted ^ IRREDUCIBLE_REDUCE
            steps.append(
                f"            a digeser kiri \u2192 {shifted:04b}, "
                f"overflow bit-4 terjadi \u2192 XOR dengan 0011 (x+1) "
                f"\u2192 a = {reduced:04b}"
            )
            a = reduced
        else:
            steps.append(f"            a digeser kiri \u2192 a = {shifted:04b} (tanpa overflow)")
            a = shifted
        b >>= 1
    steps.append(f"Hasil akhir: {orig_a:04b} \u00d7 {orig_b:04b} = {p:04b}\u2082 = {p} (0x{p:X})")
    return p & 0xF, steps


# --------------------------------------------------------------------------
# 3. FUNGSI S-BOX / NIBBLE
# --------------------------------------------------------------------------

def sub_nibble_value(n: int, inverse: bool = False) -> int:
    """Substitusi satu nibble menggunakan S-Box (atau Inverse S-Box)."""
    n &= 0xF
    row = (n >> 2) & 0x3
    col = n & 0x3
    table = INV_SBOX if inverse else SBOX
    return table[row][col]


def sub_nibble(n: int) -> int:
    """SubNibble() — substitusi satu nibble memakai S-Box."""
    return sub_nibble_value(n, inverse=False)


def inv_sub_nibble(n: int) -> int:
    """InvSubNibble() — substitusi satu nibble memakai Inverse S-Box."""
    return sub_nibble_value(n, inverse=True)


# --------------------------------------------------------------------------
# 4. KEY EXPANSION HELPERS (beroperasi pada byte 8-bit = 2 nibble)
# --------------------------------------------------------------------------

def split_byte(byte: int):
    """Pisahkan byte 8-bit menjadi (nibble_tinggi, nibble_rendah)."""
    byte &= 0xFF
    return (byte >> 4) & 0xF, byte & 0xF


def join_nibbles(high: int, low: int) -> int:
    return ((high & 0xF) << 4) | (low & 0xF)


def rot_word(byte: int) -> int:
    """RotWord() — menukar posisi nibble tinggi & rendah pada satu word 8-bit."""
    high, low = split_byte(byte)
    return join_nibbles(low, high)


def sub_word(byte: int) -> int:
    """SubWord() — SubNibble() diterapkan ke masing-masing nibble word 8-bit."""
    high, low = split_byte(byte)
    return join_nibbles(sub_nibble(high), sub_nibble(low))


# --------------------------------------------------------------------------
# 5. STATE MATRIX HELPERS
#
# 16-bit blok dipecah menjadi 4 nibble n0 n1 n2 n3 (dari MSB ke LSB) lalu
# disusun sebagai matriks state 2x2 (kolom-mayor, sama seperti AES asli):
#
#       n0  n2            s0  s2
#       n1  n3    -->     s1  s3
#
# --------------------------------------------------------------------------

def bits_to_nibbles(bits16: str):
    n0 = int(bits16[0:4], 2)
    n1 = int(bits16[4:8], 2)
    n2 = int(bits16[8:12], 2)
    n3 = int(bits16[12:16], 2)
    return n0, n1, n2, n3


def nibbles_to_bits(n0, n1, n2, n3) -> str:
    return f"{n0:04b}{n1:04b}{n2:04b}{n3:04b}"


def state_from_nibbles(n0, n1, n2, n3):
    return [[n0, n2], [n1, n3]]


def nibbles_from_state(state):
    n0, n2 = state[0][0], state[0][1]
    n1, n3 = state[1][0], state[1][1]
    return n0, n1, n2, n3


def state_from_bits16(bits16: str):
    return state_from_nibbles(*bits_to_nibbles(bits16))


def state_to_bits16(state) -> str:
    return nibbles_to_bits(*nibbles_from_state(state))


def state_to_int(state) -> int:
    return int(state_to_bits16(state), 2)


def key16_to_state(key_int_16: int):
    bits = f"{key_int_16:016b}"
    return state_from_bits16(bits)


# --------------------------------------------------------------------------
# 6. TRANSFORMASI STATE
# --------------------------------------------------------------------------

def sub_nibbles(state, inverse: bool = False):
    """SubNibbles() / InvSubNibbles() — substitusi seluruh nibble di state."""
    func = inv_sub_nibble if inverse else sub_nibble
    return [[func(state[r][c]) for c in range(2)] for r in range(2)]


def shift_rows(state):
    """
    ShiftRows() — menukar posisi dua nibble pada baris kedua (baris index 1).
    Operasi ini bersifat self-inverse, sehingga InvShiftRows == ShiftRows.
    """
    return [
        [state[0][0], state[0][1]],
        [state[1][1], state[1][0]],
    ]


# Alias eksplisit agar sesuai requirement (InvShiftRows wajib ada terpisah)
def inv_shift_rows(state):
    """InvShiftRows() — identik dengan ShiftRows() karena self-inverse."""
    return shift_rows(state)


def mix_columns(state):
    """
    MixColumns() — mengalikan setiap kolom state dengan matriks konstan:
            | 1  4 |
            | 4  1 |
    pada GF(2^4).
    """
    s0, s1 = state[0][0], state[1][0]   # kolom 0
    s2, s3 = state[0][1], state[1][1]   # kolom 1

    new_s0 = gf_add(s0, gf_mult(4, s1))
    new_s1 = gf_add(gf_mult(4, s0), s1)
    new_s2 = gf_add(s2, gf_mult(4, s3))
    new_s3 = gf_add(gf_mult(4, s2), s3)

    return [[new_s0, new_s2], [new_s1, new_s3]]


def inv_mix_columns(state):
    """
    InvMixColumns() — mengalikan setiap kolom state dengan matriks invers:
            | 9  2 |
            | 2  9 |
    pada GF(2^4).
    """
    s0, s1 = state[0][0], state[1][0]
    s2, s3 = state[0][1], state[1][1]

    new_s0 = gf_add(gf_mult(9, s0), gf_mult(2, s1))
    new_s1 = gf_add(gf_mult(2, s0), gf_mult(9, s1))
    new_s2 = gf_add(gf_mult(9, s2), gf_mult(2, s3))
    new_s3 = gf_add(gf_mult(2, s2), gf_mult(9, s3))

    return [[new_s0, new_s2], [new_s1, new_s3]]


def add_round_key(state, round_key_state):
    """AddRoundKey() — XOR antar dua state 2x2."""
    return [
        [gf_add(state[r][c], round_key_state[r][c]) for c in range(2)]
        for r in range(2)
    ]


# --------------------------------------------------------------------------
# 7. KEY EXPANSION (menghasilkan K0, K1, K2 + trace lengkap)
# --------------------------------------------------------------------------

def key_expansion(key16: str):
    """
    KeyExpansion() — menghasilkan tiga round key 16-bit (K0, K1, K2)
    dari key awal 16-bit, beserta trace tiap langkah untuk visualisasi.
    """
    key_int = int(key16, 2)
    w0 = (key_int >> 8) & 0xFF
    w1 = key_int & 0xFF

    # --- g(w1) untuk menghasilkan w2 ---
    rw1 = rot_word(w1)
    sw1 = sub_word(rw1)
    g1 = sw1 ^ RCON1
    w2 = w0 ^ g1
    w3 = w2 ^ w1

    # --- g(w3) untuk menghasilkan w4 ---
    rw3 = rot_word(w3)
    sw3 = sub_word(rw3)
    g2 = sw3 ^ RCON2
    w4 = w2 ^ g2
    w5 = w4 ^ w3

    K0 = (w0 << 8) | w1
    K1 = (w2 << 8) | w3
    K2 = (w4 << 8) | w5

    trace = {
        "w0": w0, "w1": w1,
        "rotword_w1": rw1, "subword_w1": sw1, "rcon1": RCON1, "g1": g1,
        "w2": w2, "w3": w3,
        "rotword_w3": rw3, "subword_w3": sw3, "rcon2": RCON2, "g2": g2,
        "w4": w4, "w5": w5,
        "K0": K0, "K1": K1, "K2": K2,
    }
    return K0, K1, K2, trace


# --------------------------------------------------------------------------
# 8. ENCRYPT / DECRYPT DENGAN TRACE LENGKAP UNTUK VISUALISASI
# --------------------------------------------------------------------------

def _snap(state):
    """Ambil salinan (snapshot) independen dari state agar aman disimpan di trace."""
    return deepcopy(state)


def encrypt(plaintext16: str, key16: str) -> dict:
    """
    Encrypt() — melakukan enkripsi S-AES penuh dan mengembalikan dict berisi
    ciphertext + seluruh trace langkah (untuk ditampilkan step-by-step di web).
    """
    K0, K1, K2, ke_trace = key_expansion(key16)
    K0_state = key16_to_state(K0)
    K1_state = key16_to_state(K1)
    K2_state = key16_to_state(K2)

    state0 = state_from_bits16(plaintext16)

    # ---- Initial AddRoundKey ----
    ark0_before = _snap(state0)
    state_after_ark0 = add_round_key(state0, K0_state)

    # ---- ROUND 1 ----
    r1_input = _snap(state_after_ark0)

    r1_sub_before = _snap(r1_input)
    r1_sub_after = sub_nibbles(r1_input)

    r1_shift_before = _snap(r1_sub_after)
    r1_shift_after = shift_rows(r1_sub_after)

    r1_mix_before = _snap(r1_shift_after)
    r1_mix_after = mix_columns(r1_shift_after)

    # detail perkalian GF untuk MixColumns Round 1
    s0, s1 = r1_mix_before[0][0], r1_mix_before[1][0]
    s2, s3 = r1_mix_before[0][1], r1_mix_before[1][1]
    gf_details_r1 = []
    _, st = gf_mult_verbose(4, s1, "4", "s1"); gf_details_r1.append({"title": "4 \u00d7 s1 (kolom 0, untuk s0')", "steps": st})
    _, st = gf_mult_verbose(4, s0, "4", "s0"); gf_details_r1.append({"title": "4 \u00d7 s0 (kolom 0, untuk s1')", "steps": st})
    _, st = gf_mult_verbose(4, s3, "4", "s3"); gf_details_r1.append({"title": "4 \u00d7 s3 (kolom 1, untuk s2')", "steps": st})
    _, st = gf_mult_verbose(4, s2, "4", "s2"); gf_details_r1.append({"title": "4 \u00d7 s2 (kolom 1, untuk s3')", "steps": st})

    r1_ark_before = _snap(r1_mix_after)
    r1_ark_after = add_round_key(r1_mix_after, K1_state)

    # ---- ROUND 2 (tanpa MixColumns) ----
    r2_input = _snap(r1_ark_after)

    r2_sub_before = _snap(r2_input)
    r2_sub_after = sub_nibbles(r2_input)

    r2_shift_before = _snap(r2_sub_after)
    r2_shift_after = shift_rows(r2_sub_after)

    r2_ark_before = _snap(r2_shift_after)
    r2_ark_after = add_round_key(r2_shift_after, K2_state)

    ciphertext_state = r2_ark_after
    ciphertext_bits = state_to_bits16(ciphertext_state)
    ciphertext_hex = f"{int(ciphertext_bits, 2):04X}"

    return {
        "plaintext_bits": plaintext16,
        "plaintext_hex": f"{int(plaintext16, 2):04X}",
        "key_bits": key16,
        "key_hex": f"{int(key16, 2):04X}",
        "key_expansion": ke_trace,
        "K0": K0, "K1": K1, "K2": K2,
        "K0_state": K0_state, "K1_state": K1_state, "K2_state": K2_state,
        "initial_state": state0,
        "add_round_key_0": {"before": ark0_before, "key": K0_state, "after": state_after_ark0},
        "round1": {
            "input": r1_input,
            "sub_nibbles": {"before": r1_sub_before, "after": r1_sub_after},
            "shift_rows": {"before": r1_shift_before, "after": r1_shift_after},
            "mix_columns": {"before": r1_mix_before, "after": r1_mix_after, "gf_details": gf_details_r1},
            "add_round_key": {"before": r1_ark_before, "key": K1_state, "after": r1_ark_after},
        },
        "round2": {
            "input": r2_input,
            "sub_nibbles": {"before": r2_sub_before, "after": r2_sub_after},
            "shift_rows": {"before": r2_shift_before, "after": r2_shift_after},
            "add_round_key": {"before": r2_ark_before, "key": K2_state, "after": r2_ark_after},
        },
        "ciphertext_state": ciphertext_state,
        "ciphertext_bits": ciphertext_bits,
        "ciphertext_hex": ciphertext_hex,
    }


def decrypt(ciphertext16: str, key16: str) -> dict:
    """
    Decrypt() — melakukan dekripsi S-AES penuh (proses invers) dan
    mengembalikan dict berisi plaintext + seluruh trace langkah.
    """
    K0, K1, K2, ke_trace = key_expansion(key16)
    K0_state = key16_to_state(K0)
    K1_state = key16_to_state(K1)
    K2_state = key16_to_state(K2)

    state_c = state_from_bits16(ciphertext16)

    # ---- AddRoundKey(K2) ----
    ark2_before = _snap(state_c)
    state_after_ark2 = add_round_key(state_c, K2_state)

    # ---- InvShiftRows ----
    ishift1_before = _snap(state_after_ark2)
    state_after_ishift1 = inv_shift_rows(state_after_ark2)

    # ---- InvSubNibbles ----
    isub1_before = _snap(state_after_ishift1)
    state_after_isub1 = sub_nibbles(state_after_ishift1, inverse=True)

    # ---- AddRoundKey(K1) ----
    ark1_before = _snap(state_after_isub1)
    state_after_ark1 = add_round_key(state_after_isub1, K1_state)

    # ---- InvMixColumns ----
    imix_before = _snap(state_after_ark1)
    state_after_imix = inv_mix_columns(state_after_ark1)

    s0, s1 = imix_before[0][0], imix_before[1][0]
    s2, s3 = imix_before[0][1], imix_before[1][1]
    gf_details_dec = []
    _, st = gf_mult_verbose(9, s0, "9", "s0"); gf_details_dec.append({"title": "9 \u00d7 s0 (kolom 0, untuk s0')", "steps": st})
    _, st = gf_mult_verbose(2, s1, "2", "s1"); gf_details_dec.append({"title": "2 \u00d7 s1 (kolom 0, untuk s0')", "steps": st})
    _, st = gf_mult_verbose(2, s0, "2", "s0"); gf_details_dec.append({"title": "2 \u00d7 s0 (kolom 0, untuk s1')", "steps": st})
    _, st = gf_mult_verbose(9, s1, "9", "s1"); gf_details_dec.append({"title": "9 \u00d7 s1 (kolom 0, untuk s1')", "steps": st})
    _, st = gf_mult_verbose(9, s2, "9", "s2"); gf_details_dec.append({"title": "9 \u00d7 s2 (kolom 1, untuk s2')", "steps": st})
    _, st = gf_mult_verbose(2, s3, "2", "s3"); gf_details_dec.append({"title": "2 \u00d7 s3 (kolom 1, untuk s2')", "steps": st})
    _, st = gf_mult_verbose(2, s2, "2", "s2"); gf_details_dec.append({"title": "2 \u00d7 s2 (kolom 1, untuk s3')", "steps": st})
    _, st = gf_mult_verbose(9, s3, "9", "s3"); gf_details_dec.append({"title": "9 \u00d7 s3 (kolom 1, untuk s3')", "steps": st})

    # ---- InvShiftRows ----
    ishift2_before = _snap(state_after_imix)
    state_after_ishift2 = inv_shift_rows(state_after_imix)

    # ---- InvSubNibbles ----
    isub2_before = _snap(state_after_ishift2)
    state_after_isub2 = sub_nibbles(state_after_ishift2, inverse=True)

    # ---- AddRoundKey(K0) ----
    ark0_before = _snap(state_after_isub2)
    state_after_ark0 = add_round_key(state_after_isub2, K0_state)

    plaintext_state = state_after_ark0
    plaintext_bits = state_to_bits16(plaintext_state)
    plaintext_hex = f"{int(plaintext_bits, 2):04X}"

    return {
        "ciphertext_bits": ciphertext16,
        "ciphertext_hex": f"{int(ciphertext16, 2):04X}",
        "key_bits": key16,
        "key_hex": f"{int(key16, 2):04X}",
        "key_expansion": ke_trace,
        "K0": K0, "K1": K1, "K2": K2,
        "K0_state": K0_state, "K1_state": K1_state, "K2_state": K2_state,
        "add_round_key_2": {"before": ark2_before, "key": K2_state, "after": state_after_ark2},
        "inv_shift_rows_1": {"before": ishift1_before, "after": state_after_ishift1},
        "inv_sub_nibbles_1": {"before": isub1_before, "after": state_after_isub1},
        "add_round_key_1": {"before": ark1_before, "key": K1_state, "after": state_after_ark1},
        "inv_mix_columns": {"before": imix_before, "after": state_after_imix, "gf_details": gf_details_dec},
        "inv_shift_rows_2": {"before": ishift2_before, "after": state_after_ishift2},
        "inv_sub_nibbles_2": {"before": isub2_before, "after": state_after_isub2},
        "add_round_key_0": {"before": ark0_before, "key": K0_state, "after": state_after_ark0},
        "plaintext_state": plaintext_state,
        "plaintext_bits": plaintext_bits,
        "plaintext_hex": plaintext_hex,
    }


# --------------------------------------------------------------------------
# 9. VALIDASI INPUT
# --------------------------------------------------------------------------

def is_valid_binary16(text: str) -> bool:
    """Validasi: hanya berisi karakter 0/1 dan panjang tepat 16 bit."""
    if text is None:
        return False
    text = text.strip()
    if len(text) != 16:
        return False
    return all(c in "01" for c in text)
