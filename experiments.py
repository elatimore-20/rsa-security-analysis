import math
import time
import matplotlib.pyplot as plt

from rsa import (
    is_prime,
    generate_keys,
    encrypt,
    encrypt_with_padding,
)


# =========================
# Helper functions
# =========================
def is_perfect_square(x):
    y = math.isqrt(x)
    return y * y == x


def fermat_factor(n):
    a = math.isqrt(n)
    if a * a < n:
        a += 1

    while True:
        b2 = a * a - n
        if is_perfect_square(b2):
            b = math.isqrt(b2)
            return a - b, a + b
        a += 1


def fermat_factor_with_limit(n, max_iterations=2000):
    a = math.isqrt(n)
    if a * a < n:
        a += 1

    for _ in range(max_iterations):
        b2 = a * a - n
        if is_perfect_square(b2):
            b = math.isqrt(b2)
            return a - b, a + b, True
        a += 1

    return None, None, False


def next_prime(n):
    while not is_prime(n):
        n += 1
    return n


def generate_close_prime_pair_with_gap(start, gap):
    p = next_prime(start)
    q = next_prime(p + gap)
    return p, q


def chinese_remainder_theorem(c1, c2, c3, n1, n2, n3):
    N = n1 * n2 * n3

    N1 = N // n1
    N2 = N // n2
    N3 = N // n3

    inv1 = pow(N1, -1, n1)
    inv2 = pow(N2, -1, n2)
    inv3 = pow(N3, -1, n3)

    return (c1 * N1 * inv1 + c2 * N2 * inv2 + c3 * N3 * inv3) % N


def integer_cube_root(n):
    low, high = 0, n
    while low <= high:
        mid = (low + high) // 2
        if mid**3 == n:
            return mid
        elif mid**3 < n:
            low = mid + 1
        else:
            high = mid - 1
    return high


# =========================
# Graph 1: Fermat Gap vs Time
# =========================
def fermat_gap_experiment():
    gaps = [2, 10, 50, 100, 500, 1000, 5000]
    avg_times = []

    print("\n=== Fermat Gap Experiment ===")

    for gap in gaps:
        p, q = generate_close_prime_pair_with_gap(50000, gap)
        n = p * q

        total_time = 0
        trials = 30

        for _ in range(trials):
            start = time.perf_counter()
            fermat_factor(n)
            end = time.perf_counter()
            total_time += (end - start)

        avg_time = total_time / trials
        avg_times.append(avg_time)

        print(f"Gap: {abs(q-p):6d} | Avg Time: {avg_time:.8f} sec")

    plt.figure()
    plt.plot(gaps, avg_times, marker='o')
    plt.title("Prime Gap vs Fermat Factorization Time")
    plt.xlabel("Gap Between Primes")
    plt.ylabel("Avg Time (seconds)")
    plt.grid(True)
    plt.savefig("fermat_gap_vs_time.png")


# =========================
# Graph 2: Key Size vs Generation Time (FIXED)
# =========================
def key_size_generation_experiment():
    key_sizes = [256, 512, 768, 1024]
    avg_times = []

    print("\n=== RSA Key Generation Time Experiment ===")

    for bits in key_sizes:
        total_time = 0
        trials = 10

        for _ in range(trials):
            start = time.perf_counter()
            generate_keys(bits=bits)
            end = time.perf_counter()
            total_time += (end - start)

        avg_time = total_time / trials
        avg_times.append(avg_time)

        print(f"Key Size: {bits:4d} bits | Avg Time: {avg_time:.8f} sec")

    plt.figure()
    plt.plot(key_sizes, avg_times, marker='o')
    plt.title("RSA Key Size vs Key Generation Time")
    plt.xlabel("Key Size (bits)")
    plt.ylabel("Avg Time (seconds)")
    plt.grid(True)
    plt.savefig("keysize_vs_generation_time.png")


# =========================
# Graph 3: Fermat Success vs Gap
# =========================
def fermat_success_experiment():
    gaps = [2, 10, 50, 100, 500, 1000, 5000, 20000, 50000]
    success_vals = []

    print("\n=== Fermat Attack Success Experiment ===")

    for gap in gaps:
        p, q = generate_close_prime_pair_with_gap(50000, gap)
        n = p * q

        _, _, success = fermat_factor_with_limit(n, max_iterations=2000)
        success_vals.append(1 if success else 0)

        print(f"Gap: {abs(q-p):6d} | Result: {'Success' if success else 'Fail'}")

    plt.figure()
    plt.plot(gaps, success_vals, marker='o')
    plt.title("Fermat Attack Success vs Prime Gap")
    plt.xlabel("Gap Between Primes")
    plt.ylabel("Success (1=Yes, 0=No)")
    plt.yticks([0, 1])
    plt.grid(True)
    plt.savefig("fermat_success_vs_gap.png")


# =========================
# Graph 4: Broadcast Outcomes
# =========================
def broadcast_outcome_experiment():
    scenarios = ["No Padding", "With Padding", "Too Large"]
    results = []

    print("\n=== Broadcast Attack Outcome Experiment ===")

    # No Padding
    try:
        msg = "attack at dawn"
        pub1, _, _, _ = generate_keys(bits=512, e=3)
        pub2, _, _, _ = generate_keys(bits=512, e=3)
        pub3, _, _, _ = generate_keys(bits=512, e=3)

        _, n1 = pub1
        _, n2 = pub2
        _, n3 = pub3

        c1 = encrypt(msg, pub1)
        c2 = encrypt(msg, pub2)
        c3 = encrypt(msg, pub3)

        combined = chinese_remainder_theorem(c1, c2, c3, n1, n2, n3)
        root = integer_cube_root(combined)

        length = (root.bit_length() + 7) // 8
        recovered = root.to_bytes(length, "big").decode("utf-8")

        success = 1 if recovered == msg else 0
    except:
        success = 0

    results.append(success)
    print(f"No Padding: {'Success' if success else 'Fail'}")

    # With Padding
    try:
        msg = "attack at dawn"
        pub = generate_keys(bits=768, e=3)[0]

        c1 = encrypt_with_padding(msg, pub)
        c2 = encrypt_with_padding(msg, pub)

        success = 0 if c1 != c2 else 1
    except:
        success = 0

    results.append(success)
    print(f"With Padding: {'Success' if success else 'Fail'}")

    # Too Large
    try:
        msg = "this is a long message" * 10
        pub = generate_keys(bits=512, e=3)[0]
        encrypt(msg, pub)
        success = 1
    except:
        success = 0

    results.append(success)
    print(f"Too Large: {'Success' if success else 'Fail'}")

    plt.figure()
    plt.bar(scenarios, results)
    plt.title("Broadcast Attack Outcome by Scenario")
    plt.ylabel("Success (1=Yes, 0=No)")
    plt.yticks([0, 1])
    plt.grid(axis='y')
    plt.savefig("broadcast_outcome_by_scenario.png")


# =========================
# Run all
# =========================
if __name__ == "__main__":
    fermat_gap_experiment()
    key_size_generation_experiment()
    fermat_success_experiment()
    broadcast_outcome_experiment()