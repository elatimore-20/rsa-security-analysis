import math
import time
from rsa import (
    generate_keys,
    encrypt,
    decrypt,
    mod_inverse,
    is_prime,
    gcd,
    extended_gcd,
    encrypt_with_padding,
)


# =========================
# Helper Functions
# =========================
def generate_close_prime_pair(start_value=50000):
    p = start_value
    while not is_prime(p):
        p += 1

    q = p + 2
    while not is_prime(q):
        q += 1

    return p, q


def chinese_remainder_theorem(c1, c2, c3, n1, n2, n3):
    N = n1 * n2 * n3

    N1 = N // n1
    N2 = N // n2
    N3 = N // n3

    inv1 = pow(N1, -1, n1)
    inv2 = pow(N2, -1, n2)
    inv3 = pow(N3, -1, n3)

    result = (c1 * N1 * inv1 + c2 * N2 * inv2 + c3 * N3 * inv3) % N
    return result


def integer_cube_root(n):
    low = 0
    high = n

    while low <= high:
        mid = (low + high) // 2
        cube = mid ** 3

        if cube == n:
            return mid
        elif cube < n:
            low = mid + 1
        else:
            high = mid - 1

    return high


def is_perfect_square(x):
    y = math.isqrt(x)
    return y * y == x


def fermat_factor(n, max_iterations=None):
    a = math.isqrt(n)
    if a * a < n:
        a += 1

    iterations = 0

    while True:
        b2 = a * a - n
        if is_perfect_square(b2):
            b = math.isqrt(b2)
            p = a - b
            q = a + b
            return p, q, iterations

        a += 1
        iterations += 1

        if max_iterations is not None and iterations >= max_iterations:
            return None, None, iterations


# =========================
# Broadcast Attack
# =========================
def broadcast_attack_demo():
    print("\n=== Broadcast Attack Demo ===")

    message = "attack at dawn"
    print("Original message:", message)

    # Generate 3 different RSA public keys with low exponent e = 3
    pub1, _, _, _ = generate_keys(bits=512, e=3)
    pub2, _, _, _ = generate_keys(bits=512, e=3)
    pub3, _, _, _ = generate_keys(bits=512, e=3)

    _, n1 = pub1
    _, n2 = pub2
    _, n3 = pub3

    c1 = encrypt(message, pub1)
    c2 = encrypt(message, pub2)
    c3 = encrypt(message, pub3)

    print("Ciphertext 1:", c1)
    print("Ciphertext 2:", c2)
    print("Ciphertext 3:", c3)

    combined = chinese_remainder_theorem(c1, c2, c3, n1, n2, n3)
    recovered_int = integer_cube_root(combined)

    length = (recovered_int.bit_length() + 7) // 8
    recovered_message = recovered_int.to_bytes(length, byteorder="big").decode("utf-8")

    print("Recovered message:", recovered_message)
    print("Attack success:", recovered_message == message)
    print(
        "Interpretation: Because textbook RSA is deterministic and uses a low exponent, "
        "the same plaintext encrypted under different moduli can be recovered without factoring."
    )


def broadcast_attack_failure_demo():
    print("\n=== Broadcast Attack Failure Demo ===")

    # Long plaintext intended to stress the size condition
    message = (
        "attack at dawnattack at dawnattack at dawnattack at dawn"
    )
    print("Original message:", message)

    pub1, _, _, _ = generate_keys(bits=512, e=3)
    pub2, _, _, _ = generate_keys(bits=512, e=3)
    pub3, _, _, _ = generate_keys(bits=512, e=3)

    _, n1 = pub1
    _, n2 = pub2
    _, n3 = pub3

    try:
        c1 = encrypt(message, pub1)
        c2 = encrypt(message, pub2)
        c3 = encrypt(message, pub3)

        combined = chinese_remainder_theorem(c1, c2, c3, n1, n2, n3)
        recovered_int = integer_cube_root(combined)

        length = (recovered_int.bit_length() + 7) // 8
        recovered_message = recovered_int.to_bytes(length, byteorder="big").decode("utf-8", errors="ignore")

        print("Recovered message:", recovered_message)
        print("Attack success:", recovered_message == message)

        if recovered_message != message:
            print(
                "Interpretation: The attack did not recover the original message correctly. "
                "This can happen when the size condition needed for exact cube-root recovery is violated."
            )

    except ValueError as e:
        print("Attack failed before recovery.")
        print("Reason:", e)
        print(
            "Interpretation: RSA requires the plaintext integer to be smaller than the modulus. "
            "So this example shows input-size failure before a valid broadcast recovery can occur."
        )


def broadcast_attack_with_padding_demo():
    print("\n=== Broadcast Attack With Padding Demo ===")

    message = "attack at dawn"
    print("Original message:", message)

    pub1, _, _, _ = generate_keys(bits=512, e=3)
    pub2, _, _, _ = generate_keys(bits=512, e=3)
    pub3, _, _, _ = generate_keys(bits=512, e=3)

    c1 = encrypt_with_padding(message, pub1)
    c2 = encrypt_with_padding(message, pub2)
    c3 = encrypt_with_padding(message, pub3)

    print("Ciphertext 1:", c1)
    print("Ciphertext 2:", c2)
    print("Ciphertext 3:", c3)

    if c1 != c2 and c2 != c3 and c1 != c3:
        print(
            "Interpretation: Padding adds randomness, so the same plaintext produces "
            "different ciphertexts. This breaks the deterministic structure required "
            "for the broadcast attack."
        )
    else:
        print(
            "Interpretation: Some ciphertexts matched unexpectedly, but padding still "
            "changes the message representation and weakens the deterministic assumptions "
            "needed for broadcast recovery."
        )


# =========================
# Fermat Factorization
# =========================
def fermat_attack_demo():
    print("\n=== Fermat Factorization Demo ===")

    p, q = generate_close_prime_pair()
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537

    if gcd(e, phi) != 1:
        raise ValueError("e and phi are not coprime.")

    d = mod_inverse(e, phi)
    public_key = (e, n)

    message = "hi"
    ciphertext = encrypt(message, public_key)

    print("Original p:", p)
    print("Original q:", q)
    print("n:", n)
    print("Ciphertext:", ciphertext)

    start = time.perf_counter()
    recovered_p, recovered_q, iterations = fermat_factor(n)
    end = time.perf_counter()

    if recovered_p is None:
        print("Factorization failed unexpectedly.")
        return

    print("Recovered p:", recovered_p)
    print("Recovered q:", recovered_q)
    print("Iterations:", iterations)
    print("Factorization time:", end - start, "seconds")

    recovered_phi = (recovered_p - 1) * (recovered_q - 1)
    recovered_d = mod_inverse(e, recovered_phi)
    recovered_private_key = (recovered_d, n)

    recovered_message = decrypt(ciphertext, recovered_private_key)
    print("Recovered message:", recovered_message)
    print(
        "Interpretation: When p and q are too close together, Fermat's method can "
        "factor the modulus quickly and recover the private key."
    )


def fermat_attack_failure_demo():
    print("\n=== Fermat Factorization Failure Demo ===")

    p = 50021
    q = 50000021

    while not is_prime(q):
        q += 1

    n = p * q

    print("Chosen p:", p)
    print("Chosen q:", q)
    print("Gap:", abs(q - p))
    print("n:", n)

    start = time.perf_counter()
    recovered_p, recovered_q, iterations = fermat_factor(n, max_iterations=2000)
    end = time.perf_counter()

    if recovered_p is None:
        print("Factorization not found within iteration limit.")
        print("Iterations attempted:", iterations)
        print(
            "Interpretation: Fermat factorization becomes impractical when the primes "
            "are far apart because the search space grows too large."
        )
    else:
        print("Unexpectedly factored n.")
        print("Recovered p:", recovered_p)
        print("Recovered q:", recovered_q)
        print("Iterations:", iterations)

    print("Elapsed time:", end - start, "seconds")


# =========================
# Common Modulus Attack
# =========================
def common_modulus_attack_demo():
    print("\n=== Common Modulus Attack Demo ===")

    p, q = generate_close_prime_pair()
    n = p * q
    phi = (p - 1) * (q - 1)

    # Find two valid public exponents that are coprime to phi and to each other
    e1 = 3
    while gcd(e1, phi) != 1:
        e1 += 2

    e2 = e1 + 2
    while gcd(e2, phi) != 1 or gcd(e1, e2) != 1:
        e2 += 2

    # Keep plaintext small enough to fit under modulus
    message = "ok"
    m = int.from_bytes(message.encode("utf-8"), byteorder="big")

    if m >= n:
        raise ValueError("Message is too large for this modulus.")

    c1 = pow(m, e1, n)
    c2 = pow(m, e2, n)

    # Solve a*e1 + b*e2 = 1
    g, a, b = extended_gcd(e1, e2)

    if g != 1:
        raise ValueError("e1 and e2 must be coprime.")

    # Handle negative coefficients
    if a < 0:
        c1_inv = mod_inverse(c1, n)
        part1 = pow(c1_inv, -a, n)
    else:
        part1 = pow(c1, a, n)

    if b < 0:
        c2_inv = mod_inverse(c2, n)
        part2 = pow(c2_inv, -b, n)
    else:
        part2 = pow(c2, b, n)

    recovered_m = (part1 * part2) % n
    length = (recovered_m.bit_length() + 7) // 8
    recovered_message = recovered_m.to_bytes(length, byteorder="big").decode("utf-8")

    print("Shared modulus n:", n)
    print("e1:", e1)
    print("e2:", e2)
    print("Ciphertext 1:", c1)
    print("Ciphertext 2:", c2)
    print("Recovered message:", recovered_message)
    print(
        "Interpretation: Reusing the same modulus across different public exponents "
        "can allow plaintext recovery without factoring the modulus."
    )


# =========================
# Main
# =========================
if __name__ == "__main__":
    broadcast_attack_demo()
    broadcast_attack_failure_demo()
    broadcast_attack_with_padding_demo()
    fermat_attack_demo()
    fermat_attack_failure_demo()
    common_modulus_attack_demo()
    