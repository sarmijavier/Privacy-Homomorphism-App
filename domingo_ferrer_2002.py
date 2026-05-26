import secrets
import math

# Internal arithmetic utilities
def _ext_gcd(a: int, b: int) -> tuple[int, int, int]:
    """Extended Euclidean algorithm.  Returns (gcd, x, y) with a·x + b·y = gcd."""
    if a == 0:
        return b, 0, 1
    g, x, y = _ext_gcd(b % a, a)
    return g, y - (b // a) * x, x


def mod_inv(a: int, m: int) -> int:
    """Return a⁻¹ mod m.  Raises ValueError if gcd(a, m) ≠ 1."""
    g, x, _ = _ext_gcd(a % m, m)
    if g != 1:
        raise ValueError(f"mod_inv: gcd({a}, {m}) = {g} ≠ 1 — no inverse exists")
    return x % m


def miller_rabin(n: int, rounds: int = 40) -> bool:
    """
    Probabilistic primality test (Miller-Rabin, 40 rounds).
    Error probability ≤ 4^{-40} ≈ 10^{-24}.
    """
    if n < 2:
        return False
    small = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]
    if n in small:
        return True
    if any(n % p == 0 for p in small):
        return False
    # write n-1 = 2^r · d
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2
    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def generate_large_prime(num_decimal_digits: int = 200) -> int:
    """
    Generate a random prime with exactly `num_decimal_digits` decimal digits.
    Uses cryptographically secure randomness (secrets module).
    """
    lo = 10 ** (num_decimal_digits - 1)
    hi = 10 **  num_decimal_digits - 1
    while True:
        c = (secrets.randbelow(hi - lo) + lo) | 1   # force odd
        if miller_rabin(c):
            return c

# Key generation
def keygen(
    num_decimal_digits: int = 200,
    m_prime_digits: int = 10,
    d: int = 3,
    verbose: bool = True,
) -> dict:
    if verbose:
        print(f"[keygen] Generating keys with |m|={num_decimal_digits} and |m'|={m_prime_digits} ...")

    # ── m': secret cleartext modulus (small) ─────────────────────────────────
    m_prime = generate_large_prime(m_prime_digits)

    # ── q: large prime factor to construct m ─────────────────────────────────
    q_digits = num_decimal_digits - m_prime_digits
    q = generate_large_prime(q_digits)

    # ── m: composite public modulus, strictly a multiple of m' ───────────────
    m = m_prime * q

    if verbose:
        print(f"[keygen] m' = {m_prime} ({m_prime.bit_length()} bits, {len(str(m_prime))} decimal digits)")
        print(f"[keygen] m  = {str(m)[:48]}... ({m.bit_length()} bits, {len(str(m))} decimal digits)")

    # ── r: random invertible element of Z_m ──────────────────────────────────
    r = secrets.randbelow(m - 2) + 2
    while math.gcd(r, m) != 1:
        r = secrets.randbelow(m - 2) + 2

    # ── precompute powers for efficiency ─────────────────────────────────────
    r_inv = mod_inv(r, m)
    r_pows     = [pow(r,     j, m) for j in range(1, d + 1)]      
    
    max_deg = 4 * d
    r_inv_pows = [pow(r_inv, j, m) for j in range(1, max_deg + 1)]  

    # ── security parameter s = log_{m'}(m) ───────────────────────────────────
    s = math.log(m) / math.log(m_prime)

    if verbose:
        print(f"[keygen] d = {d},  security parameter s = log_{{m'}}(m) = {s:.4f}")

    return {
        "m":          m,
        "d":          d,
        "r":          r,
        "m_prime":    m_prime,
        "s":          s,
        "r_inv":      r_inv,
        "r_pows":     r_pows,
        "r_inv_pows": r_inv_pows,
    }

# Encryption

def encrypt(a: int, key: dict) -> dict[int, int]:
    m       = key["m"]
    d       = key["d"]
    m_prime = key["m_prime"]
    r_pows  = key["r_pows"]

    a = a % m_prime  # normalise into Z_{m'}

    # ── random split ─────────────────────────────────────────────────────────
    parts = [secrets.randbelow(m) for _ in range(d - 1)]
    # Base calculation restricted to [0, m_prime - 1]
    last_base = (a - sum(parts)) % m_prime
    
    # Scale up randomly within Z_m to prevent data leakage
    k_max = (m - 1 - last_base) // m_prime
    k = secrets.randbelow(k_max + 1)
    last = last_base + k * m_prime
    parts.append(last)

    # ── multiply each part by the corresponding power of r ───────────────────
    ciphertext = {}
    for j, (aj, rj) in enumerate(zip(parts, r_pows), start=1):
        ciphertext[j] = (aj * rj) % m           # c_j = a_j · r^j mod m

    return ciphertext

# Decryption

def decrypt(ciphertext: dict[int, int], key: dict) -> int:
    m          = key["m"]
    m_prime    = key["m_prime"]
    r_inv_pows = key["r_inv_pows"]   # index j-1 gives r^{-j}

    # Extend precomputed powers on-the-fly if a very deep multiplication tree
    # has produced a degree higher than 4d.
    r_inv = key["r_inv"]
    max_precomputed = len(r_inv_pows)

    total = 0
    for j, cj in ciphertext.items():
        # Retrieve or compute r^{-j}
        if j <= max_precomputed:
            r_inv_j = r_inv_pows[j - 1]
        else:
            r_inv_j = pow(r_inv, j, m)          # fallback: compute on-the-fly
        aj    = (cj * r_inv_j) % m
        total = (total + aj) % m

    return total % m_prime

# Homomorphic operations  (no key required)

def homo_add(c1: dict, c2: dict, m: int) -> dict:
    degrees = set(c1) | set(c2)
    return {j: (c1.get(j, 0) + c2.get(j, 0)) % m for j in degrees}


def homo_sub(c1: dict, c2: dict, m: int) -> dict:
    degrees = set(c1) | set(c2)
    return {j: (c1.get(j, 0) - c2.get(j, 0)) % m for j in degrees}


def homo_scalar_mul(k: int, c: dict, m: int) -> dict:
    return {j: (k * cj) % m for j, cj in c.items()}


def homo_mul(c1: dict, c2: dict, m: int) -> dict:
    result: dict[int, int] = {}
    for i, ci in c1.items():
        for j, cj in c2.items():
            deg = i + j
            result[deg] = (result.get(deg, 0) + ci * cj) % m
    return result


def homo_linear_combination(
    coeffs: list[int],
    ciphertexts: list[dict],
    m: int,
) -> dict:
    """
    Homomorphic linear combination:  Σ k_i · C(a_i)  →  C(Σ k_i · a_i).

    Uses only scalar multiplications and additions (r-degree stays at d).
    After decryption the result equals (Σ k_i · a_i) mod m'.
    """
    if len(coeffs) != len(ciphertexts):
        raise ValueError("coeffs and ciphertexts must have the same length")
    result: dict[int, int] = {}
    for k, c in zip(coeffs, ciphertexts):
        kc     = homo_scalar_mul(k, c, m)
        result = homo_add(result, kc, m)
    return result

# Security analysis  (Theorem 7 and Corollary 13)

def security_analysis(m: int, m_prime: int, s: float, n_known: int) -> None:
    print("\n" + "─" * 65)
    print("Security Analysis  (Domingo-Ferrer 2002, Theorem 7 / Corollary 13)")
    print("─" * 65)

    digits_m       = len(str(m))
    digits_m_prime = len(str(m_prime))

    print(f"  |m|  = {digits_m} decimal digits   ({m.bit_length()} bits)")
    print(f"  |m'| = {digits_m_prime} decimal digits")
    print(f"  s    = log_{{m'}}(m) = {s:.6f}   (security parameter)")
    print(f"  n    = {n_known}   (number of known plaintext-ciphertext pairs)")
    print()

    if s <= n_known:
        print("  ⚠  WARNING: s ≤ n — security NOT guaranteed.")
        print("     The adversary may have enough information to determine the key.")
        print("     → Increase s by choosing a larger m or a smaller m'.")
        return

    # Expected number of keys consistent with n known pairs (Theorem 7):
    #   E[#consistent keys] ≈ max( (6/π²) · (m')^{s-n}, 1 )
    log10_consistent = (s - n_known) * math.log10(m_prime) + math.log10(6 / math.pi**2)
    print(f"  Expected # of keys consistent with {n_known} known pair(s):")
    if log10_consistent > 300:
        print(f"    ≈ 10^{log10_consistent:.1f}   (astronomically large)")
    else:
        print(f"    ≈ {10**log10_consistent:.3e}")

    # Probability of random key guessing (Corollary 13):
    #   P_guess ≤ π²·(m')^{n-s} / 6
    log10_prob = (n_known - s) * math.log10(m_prime) + math.log10(math.pi**2 / 6)
    print(f"\n  P(random key guess succeeds) ≤ 10^{log10_prob:.2f}")
    if log10_prob < -20:
        print("  → Negligible: far below any practical security threshold.")
    elif log10_prob < -10:
        print("  → Very small, but consider increasing s for long-term security.")
    else:
        print("  → ⚠  Non-negligible — increase s or reduce n.")

    # Table from Section 4 of the paper (a few reference rows):
    print()
    print("  Reference table (from paper, Table 1):")
    print(f"  {'n':>4}  {'s':>4}  {'|m′|':>6}  {'|m|':>6}  {'P_guess':>20}")
    print(f"  {'-'*4}  {'-'*4}  {'-'*6}  {'-'*6}  {'-'*20}")
    for row_n, row_s, row_lm_prime, row_lm in [
        (5,  5, 20, 100), (5,  6, 20, 120),
        (10, 11, 20, 220), (50, 51, 5, 255), (50, 53, 5, 265),
    ]:
        log_p = (row_n - row_s) * row_lm_prime + math.log10(math.pi**2 / 6)
        p_str = f"≈ 10^{log_p:.1f}" if log_p < -2 else "≈ 1"
        print(f"  {row_n:>4}  {row_s:>4}  {row_lm_prime:>6}  {row_lm:>6}  {p_str:>20}")

    print("─" * 65)

# Validation: reproduce the Section 3 numerical example exactly
def _paper_example() -> None:
    m = 28; d = 2; r = 3; m_prime = 7
    key = {
        "m": m, "d": d, "r": r, "m_prime": m_prime,
        "r_inv": mod_inv(r, m),
        "r_pows":     [pow(r,           j, m) for j in range(1, 2*d + 1)],
        "r_inv_pows": [pow(mod_inv(r,m),j, m) for j in range(1, 8*d + 1)],
    }

    # The paper fixes the random splits for illustration:
    def _encrypt_with_fixed_split(a1, a2):
        return {1: (a1 * r) % m, 2: (a2 * r**2) % m}

    C = {
        -1: _encrypt_with_fixed_split(2, 4),   # Ek(-1) = (6, 8)
         3: _encrypt_with_fixed_split(2, 1),   # Ek(3)  = (6, 9)
         1: _encrypt_with_fixed_split(4, 4),   # Ek(1)  = (12,8)
         2: _encrypt_with_fixed_split(3, 6),   # Ek(2)  = (9, 26)
    }

    print("─" * 55)
    print("Section 3 paper example  (x1+x2+x3)·x4 = 0.6")
    print("─" * 55)
    for val, c in C.items():
        print(f"  Ek({val:2d}) = {c}")

    # Unclassified level: additions
    sum3 = homo_add(homo_add(C[-1], C[3], m), C[1], m)
    print(f"\n  Ek(-1)+Ek(3)+Ek(1) = {sum3}   expected {{1:24, 2:25}}")

    # Unclassified level: multiplication
    prod = homo_mul(sum3, C[2], m)
    print(f"  product             = {prod}   expected {{2:20, 3:9, 4:6}}")

    # Classified level: decrypt (denominator = 10·1 = 10)
    numerator = decrypt(prod, key)
    print(f"\n  Decrypted numerator = {numerator}   expected 6")
    print(f"  Final result        = {numerator}/10 = {numerator/10}   expected 0.6")
    assert numerator == 6, "Paper example mismatch!"
    print("  ✓ Exact match with paper")

# Demo / self-test
def demo(digits: int = 200, d: int = 3) -> None:
    print("═" * 65)
    print("Domingo-Ferrer (2002) Privacy Homomorphism — Demo")
    print("═" * 65 + "\n")

    _paper_example()
    print()

    # ── Keygen ────────────────────────────────────────────────────────────────
    print(f"\nKeygen with {digits}-digit modulus, d={d} …")
    key = keygen(num_decimal_digits=digits, d=d, verbose=True)
    m       = key["m"]
    m_prime = key["m_prime"]

    # Use two small plaintexts
    a, b, k = 123456, 234567, 7
    print(f"\nPlaintexts: a = {a},  b = {b},  scalar k = {k}")

    # ── Encrypt ───────────────────────────────────────────────────────────────
    Ca = encrypt(a, key)
    Cb = encrypt(b, key)
    first_comp = str(list(Ca.values())[0])
    print(f"\nC(a) has {len(Ca)} components; first component = {first_comp[:30]}…")

    # ── Test: addition ────────────────────────────────────────────────────────
    C_add   = homo_add(Ca, Cb, m)
    dec_add = decrypt(C_add, key)
    exp_add = (a + b) % m_prime
    print(f"\n[+] a + b     = {exp_add}")
    print(f"    decrypted = {dec_add}   OK={dec_add == exp_add}")
    assert dec_add == exp_add, "Addition failed"

    # ── Test: subtraction ────────────────────────────────────────────────────
    C_sub   = homo_sub(Ca, Cb, m)
    dec_sub = decrypt(C_sub, key)
    exp_sub = (a - b) % m_prime
    print(f"\n[-] a - b     = {exp_sub}")
    print(f"    decrypted = {dec_sub}   OK={dec_sub == exp_sub}")
    assert dec_sub == exp_sub, "Subtraction failed"

    # ── Test: scalar multiplication ───────────────────────────────────────────
    C_scl   = homo_scalar_mul(k, Ca, m)
    dec_scl = decrypt(C_scl, key)
    exp_scl = (k * a) % m_prime
    print(f"\n[×k] k·a     = {exp_scl}")
    print(f"     decrypted = {dec_scl}   OK={dec_scl == exp_scl}")
    assert dec_scl == exp_scl, "Scalar multiplication failed"

    # ── Test: full multiplication ─────────────────────────────────────────────
    C_mul   = homo_mul(Ca, Cb, m)
    dec_mul = decrypt(C_mul, key)
    exp_mul = (a * b) % m_prime
    print(f"\n[×] a · b     = {exp_mul}")
    print(f"    decrypted = {dec_mul}   OK={dec_mul == exp_mul}")
    assert dec_mul == exp_mul, "Multiplication failed"

    # ── Test: linear combination 2a + 3b ─────────────────────────────────────
    C_lc   = homo_linear_combination([2, 3], [Ca, Cb], m)
    dec_lc = decrypt(C_lc, key)
    exp_lc = (2 * a + 3 * b) % m_prime
    print(f"\n[lc] 2a + 3b  = {exp_lc}")
    print(f"     decrypted = {dec_lc}   OK={dec_lc == exp_lc}")
    assert dec_lc == exp_lc, "Linear combination failed"

    # ── Test: probabilistic encryption ───────────────────────────────────────
    Ca2 = encrypt(a, key)
    assert Ca != Ca2, "Same plaintext produced the same ciphertext (not probabilistic)!"
    print(f"\n[P] Same plaintext a={a} → two different ciphertexts ✓")

    # ── Security analysis ─────────────────────────────────────────────────────
    security_analysis(m=m, m_prime=m_prime, s=key["s"], n_known=5)

    print("\n" + "═" * 65)
    print("All tests passed.  ✓")
    print("═" * 65)


if __name__ == "__main__":
    demo(digits=200, d=3)
