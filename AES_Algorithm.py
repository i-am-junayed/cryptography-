"""
AES (Advanced Encryption Standard) — implemented FROM SCRATCH in pure Python
No cryptographic libraries used anywhere (no `cryptography`, no `pycryptodome`,
no `hashlib`, nothing) — every table and every transformation is written out
by hand, exactly like the DES script this assignment builds on.

- AES (original name: Rijndael) was constructed in 2001 by Vincent Rijmen
  and Joan Daemen, and is still the state-of-the-art symmetric cipher.
- AES is a PRIVATE-KEY (symmetric) cryptosystem with three possible key
  lengths: 128, 192, and 256 bits.
- AES is a block cipher, but — unlike DES — it has NOTHING to do with the
  Feistel structure. It stores plaintext, key, and ciphertext as a 4x4
  MATRIX of bytes (the "state"), and every round works on the WHOLE
  128-bit block at once (no left/right half split).

This file implements the 128-bit-key variant:
    Plaintext block : 128 bits  (4 words of 32 bits each)
    Key size        : 128 bits  (4 words)
    Number of rounds : 10
    Number of subkeys: 10  (K1 .. K10, generated from the key schedule)
    + the ORIGINAL 128-bit key itself (K0) is used ONCE, before round 1,
      exactly as the slide states: "we have to use the original 128 bit
      long key before applying the round-function"
    Ciphertext block: 128 bits

------------------------------------------------------------------------
ROUND STRUCTURE (per the flow diagram)
------------------------------------------------------------------------
    128-bit plaintext block
         |
    ADD ROUND KEY   <----- K0  (the ORIGINAL key, used before any round function)
         | 128 bits
    ================== "ROUND FUNCTION" (repeated for rounds 1 to 9) ==================
         S-BOX (substitute bytes)
         | 128 bits
         SHIFT ROWS (left shift)
         | 128 bits
         MIX COLUMNS
         | 128 bits
         ADD ROUND KEY   <----- K_i  (a DIFFERENT subkey every round,
         |                             generated from the original key)
    ===================================================================================
    FINAL ROUND (round 10):
         S-BOX
         SHIFT ROWS
         ADD ROUND KEY   <----- K10
         *** THE LAST ROUND DOES NOT USE THE MIX COLUMNS OPERATION ***
         |
    128-bit ciphertext block

Author: Md Junayed Hossain | ID: 2511935
Course: CS 550 - Cryptography & Network Security

"""

# =====================================================================
# STEP 0: The AES S-box and Inverse S-box
# =====================================================================
# Standard AES substitution table from FIPS-197 (this is the "S-BOX
# (substitute bytes)" box in the flow diagram). It is built from the
# multiplicative inverse in GF(2^8) followed by a fixed affine
# transformation; we use the precomputed 256-entry table directly.

sbox = [
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
]

# Inverse S-box: swap position <-> value from the table above
inv_sbox = [0] * 256
for i, val in enumerate(sbox):
    inv_sbox[val] = i

# Round constants used in key expansion (one per round)
rcon = [0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1B,0x36]


# =====================================================================
# STEP 1: GF(2^8) arithmetic — needed for MIX COLUMNS / its inverse
# =====================================================================
# AES treats each byte as an element of GF(2^8) with reduction
# polynomial x^8+x^4+x^3+x+1 (0x11B). "xtime" multiplies a byte by {02}
# in this field; "gmul" does general multiplication via repeated xtime
# + XOR ("peasant multiplication").

def xtime(a):
    a <<= 1
    if a & 0x100:
        a ^= 0x11B
    return a & 0xFF

def gmul(a, b):
    product = 0
    for _ in range(8):
        if b & 1:
            product ^= a
        high_bit_set = a & 0x80
        a = (a << 1) & 0xFF
        if high_bit_set:
            a ^= 0x1B
        b >>= 1
    return product


# =====================================================================
# STEP 2: Key Expansion  ->  K0 [w0..w3], K1 [w4..w7], ... , K10 [w40..w43]
# =====================================================================
# This matches the slide's notation exactly: K0 is the original key
# (words w0..w3), K1 is the next subkey (words w4..w7), and so on, all
# the way up to K10 -> 11 subkeys total (K0 + 10 generated subkeys, one
# per round) built from a single 128-bit key using RotWord + SubWord + Rcon.

def key_expansion(key_bytes, verbose=False):
    Nk = 4    # key length in 32-bit words (128 bits / 32 = 4 words)
    Nr = 10   # number of rounds for a 128-bit key
    Nb = 4    # state size in words (always 4 for AES)

    # w[0..3] = the original key itself, split into 4 words -> this IS K0
    w = [list(key_bytes[4 * i: 4 * i + 4]) for i in range(Nk)]

    for i in range(Nk, Nb * (Nr + 1)):
        temp = list(w[i - 1])

        if i % Nk == 0:
            temp = temp[1:] + temp[:1]              # RotWord
            temp = [sbox[b] for b in temp]          # SubWord
            temp[0] ^= rcon[i // Nk - 1]             # XOR in the round constant

        w.append([w[i - Nk][j] ^ temp[j] for j in range(4)])

    # Group every 4 words into one subkey: K0[w0..w3], K1[w4..w7], ...
    K = []
    for r in range(Nr + 1):
        k_r = []
        for i in range(4):
            k_r += w[r * 4 + i]
        K.append(k_r)
        if verbose:
            tag = "K0  (the ORIGINAL key)" if r == 0 else f"K{r:<2d}"
            print(f"  {tag} [w{4*r}..w{4*r+3}] = {bytes(k_r).hex().upper()}")

    return K


# =====================================================================
# STEP 3: State helpers — plaintext/key/ciphertext stored as a 4x4
# matrix ("it stores the values in matrix form"), filled COLUMN by column
# =====================================================================
def bytes_to_state(block):
    state = [[0] * 4 for _ in range(4)]
    for i in range(16):
        state[i % 4][i // 4] = block[i]
    return state

def state_to_bytes(state):
    return [state[i % 4][i // 4] for i in range(16)]


# =====================================================================
# STEP 4: The AES round transformations (and their inverses)
# =====================================================================
def sub_bytes(state):
    """S-BOX (substitute bytes): the only non-linear step in AES."""
    for r in range(4):
        for c in range(4):
            state[r][c] = sbox[state[r][c]]

def inv_sub_bytes(state):
    for r in range(4):
        for c in range(4):
            state[r][c] = inv_sbox[state[r][c]]


def shift_rows(state):
    """SHIFT ROWS (left shift): row r shifted left by r positions."""
    for r in range(1, 4):
        state[r] = state[r][r:] + state[r][:r]

def inv_shift_rows(state):
    for r in range(1, 4):
        state[r] = state[r][-r:] + state[r][:-r]


def mix_columns(state):
    """MIX COLUMNS: each column multiplied by a fixed GF(2^8) polynomial."""
    for c in range(4):
        col = [state[r][c] for r in range(4)]
        state[0][c] = gmul(col[0], 2) ^ gmul(col[1], 3) ^ col[2]          ^ col[3]
        state[1][c] = col[0]          ^ gmul(col[1], 2) ^ gmul(col[2], 3) ^ col[3]
        state[2][c] = col[0]          ^ col[1]          ^ gmul(col[2], 2) ^ gmul(col[3], 3)
        state[3][c] = gmul(col[0], 3) ^ col[1]          ^ col[2]          ^ gmul(col[3], 2)

def inv_mix_columns(state):
    for c in range(4):
        col = [state[r][c] for r in range(4)]
        state[0][c] = gmul(col[0],14) ^ gmul(col[1],11) ^ gmul(col[2],13) ^ gmul(col[3], 9)
        state[1][c] = gmul(col[0], 9) ^ gmul(col[1],14) ^ gmul(col[2],11) ^ gmul(col[3],13)
        state[2][c] = gmul(col[0],13) ^ gmul(col[1], 9) ^ gmul(col[2],14) ^ gmul(col[3],11)
        state[3][c] = gmul(col[0],11) ^ gmul(col[1],13) ^ gmul(col[2], 9) ^ gmul(col[3],14)


def add_round_key(state, subkey):
    """ADD ROUND KEY: XOR the 128-bit state with a 128-bit subkey K_i."""
    k_state = bytes_to_state(subkey)
    for r in range(4):
        for c in range(4):
            state[r][c] ^= k_state[r][c]


def _show(label, state):
    print(f"  {label:<28s} (128 bits): {bytes(state_to_bytes(state)).hex().upper()}")


# =====================================================================
# STEP 5: Single-block (128-bit) AES-128 encryption / decryption
# following the flow diagram exactly
# =====================================================================
def aes_encrypt_block(plaintext_bytes, K, Nr=10, verbose=False):
    state = bytes_to_state(plaintext_bytes)

    # ADD ROUND KEY <- K0 (the ORIGINAL key), used BEFORE the round function
    add_round_key(state, K[0])
    if verbose:
        _show("AddRoundKey (K0, original key)", state)

    # ROUND FUNCTION, repeated for rounds 1..Nr-1:
    #   S-BOX -> SHIFT ROWS -> MIX COLUMNS -> ADD ROUND KEY (K_i)
    for rnd in range(1, Nr):
        sub_bytes(state)
        if verbose: _show(f"[R{rnd}] SubBytes", state)
        shift_rows(state)
        if verbose: _show(f"[R{rnd}] ShiftRows", state)
        mix_columns(state)
        if verbose: _show(f"[R{rnd}] MixColumns", state)
        add_round_key(state, K[rnd])
        if verbose: _show(f"[R{rnd}] AddRoundKey (K{rnd})", state)

    # FINAL ROUND (round Nr): S-BOX -> SHIFT ROWS -> ADD ROUND KEY
    # *** NO MIX COLUMNS IN THE LAST ROUND ***
    sub_bytes(state)
    if verbose: _show(f"[FINAL R{Nr}] SubBytes", state)
    shift_rows(state)
    if verbose: _show(f"[FINAL R{Nr}] ShiftRows", state)
    add_round_key(state, K[Nr])
    if verbose: _show(f"[FINAL R{Nr}] AddRoundKey (K{Nr}) - no MixColumns", state)

    return state_to_bytes(state)


def aes_decrypt_block(ciphertext_bytes, K, Nr=10, verbose=False):
    """Exact mirror image of encryption, applying every step in reverse."""
    state = bytes_to_state(ciphertext_bytes)

    # Undo the final round first: ADD ROUND KEY(K10) -> InvShiftRows -> InvSubBytes
    add_round_key(state, K[Nr])
    inv_shift_rows(state)
    inv_sub_bytes(state)
    if verbose: _show(f"[Undo FINAL R{Nr}]", state)

    # Undo rounds Nr-1 .. 1 in reverse order
    for rnd in range(Nr - 1, 0, -1):
        add_round_key(state, K[rnd])
        inv_mix_columns(state)
        inv_shift_rows(state)
        inv_sub_bytes(state)
        if verbose: _show(f"[Undo R{rnd}]", state)

    # Finally undo the very first AddRoundKey <- K0 (the original key)
    add_round_key(state, K[0])
    if verbose: _show("Undo AddRoundKey (K0, original key)", state)

    return state_to_bytes(state)


# =====================================================================
# STEP 6: PKCS#7 padding, so messages of ANY length can be encrypted
# (ECB mode: apply the single-block cipher above to each 128-bit block)
# =====================================================================
def pkcs7_pad(data, block_size=16):
    pad_len = block_size - (len(data) % block_size)
    return data + [pad_len] * pad_len

def pkcs7_unpad(data):
    pad_len = data[-1]
    return data[:-pad_len]


def aes_encrypt(plaintext_bytes, key_bytes, verbose=False):
    K = key_expansion(key_bytes)
    padded = pkcs7_pad(list(plaintext_bytes))
    ciphertext = []
    for i in range(0, len(padded), 16):
        block = padded[i:i + 16]
        if verbose:
            print(f"\n--- Encrypting 128-bit block {i // 16 + 1} ---")
        ciphertext += aes_encrypt_block(block, K, verbose=verbose)
    return ciphertext


def aes_decrypt(ciphertext_bytes, key_bytes, verbose=False):
    K = key_expansion(key_bytes)
    plaintext_padded = []
    for i in range(0, len(ciphertext_bytes), 16):
        block = ciphertext_bytes[i:i + 16]
        if verbose:
            print(f"\n--- Decrypting 128-bit block {i // 16 + 1} ---")
        plaintext_padded += aes_decrypt_block(block, K, verbose=verbose)
    return pkcs7_unpad(plaintext_padded)


# =====================================================================
# Small hex <-> byte-list helpers
# =====================================================================
def hex_to_bytes(hex_str):
    return list(bytes.fromhex(hex_str))

def bytes_to_hex(byte_list):
    return bytes(byte_list).hex().upper()


# =====================================================================
# DEMO / SELF-TEST
# =====================================================================
if __name__ == "__main__":

    print("=" * 78)
    print("PART A: Verify against the official FIPS-197 test vector")
    print("=" * 78)
    key_hex_fips = "000102030405060708090A0B0C0D0E0F"
    plaintext_hex_fips = "00112233445566778899AABBCCDDEEFF"
    expected_cipher_fips = "69C4E0D86A7B0430D8CDB78070B4C55A"

    key_bytes_fips = hex_to_bytes(key_hex_fips)
    pt_bytes_fips = hex_to_bytes(plaintext_hex_fips)
    K_fips = key_expansion(key_bytes_fips)

    ct_bytes_fips = aes_encrypt_block(pt_bytes_fips, K_fips)
    ct_hex_fips = bytes_to_hex(ct_bytes_fips)

    print("Key:                ", key_hex_fips)
    print("Plaintext block:    ", plaintext_hex_fips)
    print("Computed ciphertext:", ct_hex_fips)
    print("Expected ciphertext:", expected_cipher_fips)
    print("MATCH!" if ct_hex_fips == expected_cipher_fips else "MISMATCH!")

    dt_bytes_fips = aes_decrypt_block(ct_bytes_fips, K_fips)
    print("Decrypted back to:  ", bytes_to_hex(dt_bytes_fips))
    print()

    print("=" * 78)
    print("PART B: Key schedule -> K0 [w0..w3] ... K10 [w40..w43]")
    print("=" * 78)
    key_hex_demo = "ABC231031402EFAB2233445566778899"
    key_bytes_demo = hex_to_bytes(key_hex_demo)
    K_demo = key_expansion(key_bytes_demo, verbose=True)
    print()

    print("=" * 78)
    print("PART C: Full round-by-round trace of ONE 128-bit block, following")
    print("        the flow diagram: AddRoundKey(K0) -> [round function]x9 ->")
    print("        final round (no MixColumns) -> ciphertext")
    print("=" * 78)
    sample_block_hex = "00112233445566778899AABBCCDDEEFF"
    sample_block = hex_to_bytes(sample_block_hex)
    print(f"Plaintext block (128 bits): {sample_block_hex}")
    cipher_block = aes_encrypt_block(sample_block, K_demo, verbose=True)
    print(f"\nCiphertext block (128 bits): {bytes_to_hex(cipher_block)}")
    print()

    print("=" * 78)
    print("PART D: Encrypt/decrypt a real text message (any length, via")
    print("        PKCS#7 padding + block-by-block ECB, all from scratch)")
    print("=" * 78)
    plaintext = "Argentina is taking the 2026 World Cup trophy home!"
    print("Plaintext:", plaintext)
    print("Key (hex):", key_hex_demo)

    plaintext_bytes = list(plaintext.encode("utf-8"))
    ciphertext_bytes = aes_encrypt(plaintext_bytes, key_bytes_demo)
    ciphertext_hex = bytes_to_hex(ciphertext_bytes)
    print("Ciphertext (hex):", ciphertext_hex)

    decrypted_bytes = aes_decrypt(ciphertext_bytes, key_bytes_demo)
    decrypted_text = bytes(decrypted_bytes).decode("utf-8")
    print("Decrypted text:  ", decrypted_text)

    assert decrypted_text == plaintext, "Round-trip failed!"
    print("\nSuccess: decrypted text exactly matches the original plaintext.")
