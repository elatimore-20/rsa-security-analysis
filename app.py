import math
import time
from pathlib import Path

import streamlit as st

from rsa import (
    generate_keys,
    encrypt,
    decrypt,
    encrypt_with_padding,
    mod_inverse,
    is_prime,
    gcd,
    extended_gcd,
)


# =========================
# Helper functions
# =========================
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


def next_prime(n):
    while not is_prime(n):
        n += 1
    return n


def generate_close_prime_pair(start_value=50000):
    p = next_prime(start_value)
    q = next_prime(p + 2)
    return p, q


# =========================
# Streamlit UI
# =========================
st.set_page_config(page_title="RSA Security Analysis App", layout="wide")

st.title("RSA Security Analysis App")
st.write(
    "Interactive demo for RSA implementation, cryptanalytic attacks, "
    "and experimental results."
)

global_message = st.text_input(
    "Enter one message to use across the demos",
    value="attack at dawn"
)

short_message = global_message[:2] if len(global_message) >= 2 else global_message
long_failure_message = global_message * 8 if global_message else "attack at dawn" * 8

tab1, tab2, tab3, tab4 = st.tabs(
    ["RSA Demo", "Attack Demos", "Graphs", "Security Takeaways"]
)

# =========================
# TAB 1: RSA Demo
# =========================
with tab1:
    st.header("RSA Demo")

    col1, col2 = st.columns(2)

    with col1:
        bits = st.selectbox("Key size", [256, 512, 768, 1024], index=1)
        message = global_message
        st.write(f"**Shared message:** {message}")

    with col2:
        st.write("Generate keys, encrypt a message, and decrypt it back.")

    if st.button("Run RSA Demo"):
        try:
            public_key, private_key, p, q = generate_keys(bits=bits)
            ciphertext = encrypt(message, public_key)
            recovered_message = decrypt(ciphertext, private_key)

            st.subheader("Results")
            st.write(f"**p:** {p}")
            st.write(f"**q:** {q}")
            st.write(f"**Public key (e, n):** {public_key}")
            st.write(f"**Private key (d, n):** {private_key}")
            st.write(f"**Ciphertext:** {ciphertext}")
            st.write(f"**Recovered message:** {recovered_message}")

        except Exception as e:
            st.error(f"RSA demo failed: {e}")

# =========================
# TAB 2: Attack Demos
# =========================
with tab2:
    st.header("Attack Demos")
    st.caption(
        "The same shared message is used across the demos when possible. "
        "For small-modulus attack cases, a shortened version is used so the plaintext fits within the RSA modulus."
    )

    attack_choice = st.selectbox(
        "Choose an attack demo",
        [
            "Broadcast Attack",
            "Broadcast Attack Failure",
            "Broadcast Attack With Padding",
            "Fermat Factorization",
            "Fermat Failure Case",
            "Common Modulus Attack",
        ],
    )

    if st.button("Run Selected Attack"):
        try:
            if attack_choice == "Broadcast Attack":
                message = global_message

                pub1, _, _, _ = generate_keys(bits=512, e=3)
                pub2, _, _, _ = generate_keys(bits=512, e=3)
                pub3, _, _, _ = generate_keys(bits=512, e=3)

                _, n1 = pub1
                _, n2 = pub2
                _, n3 = pub3

                c1 = encrypt(message, pub1)
                c2 = encrypt(message, pub2)
                c3 = encrypt(message, pub3)

                combined = chinese_remainder_theorem(c1, c2, c3, n1, n2, n3)
                recovered_int = integer_cube_root(combined)

                length = (recovered_int.bit_length() + 7) // 8
                recovered_message = recovered_int.to_bytes(length, byteorder="big").decode("utf-8")

                st.success("Broadcast attack completed.")
                st.write(f"**Shared message used:** {message}")
                st.write(f"**Ciphertext 1:** {c1}")
                st.write(f"**Ciphertext 2:** {c2}")
                st.write(f"**Ciphertext 3:** {c3}")
                st.write(f"**Recovered message:** {recovered_message}")
                st.write(
                    "**Interpretation:** Because textbook RSA is deterministic and uses "
                    "a low public exponent, the same plaintext can be recovered without the private key."
                )

            elif attack_choice == "Broadcast Attack Failure":
                message = long_failure_message

                pub1, _, _, _ = generate_keys(bits=512, e=3)
                pub2, _, _, _ = generate_keys(bits=512, e=3)
                pub3, _, _, _ = generate_keys(bits=512, e=3)

                try:
                    c1 = encrypt(message, pub1)
                    c2 = encrypt(message, pub2)
                    c3 = encrypt(message, pub3)

                    _, n1 = pub1
                    _, n2 = pub2
                    _, n3 = pub3

                    combined = chinese_remainder_theorem(c1, c2, c3, n1, n2, n3)
                    recovered_int = integer_cube_root(combined)
                    length = (recovered_int.bit_length() + 7) // 8
                    recovered_message = recovered_int.to_bytes(length, byteorder="big").decode("utf-8")

                    st.write(f"**Recovered message:** {recovered_message}")
                except Exception as e:
                    st.warning("Attack failed as expected.")
                    st.write(f"**Expanded message used:** {message}")
                    st.write(f"**Reason:** {e}")
                    st.write("**Explanation:** RSA requires the message integer to be smaller than n.")

            elif attack_choice == "Broadcast Attack With Padding":
                message = global_message

                pub1, _, _, _ = generate_keys(bits=768, e=3)
                pub2, _, _, _ = generate_keys(bits=768, e=3)
                pub3, _, _, _ = generate_keys(bits=768, e=3)

                c1 = encrypt_with_padding(message, pub1)
                c2 = encrypt_with_padding(message, pub2)
                c3 = encrypt_with_padding(message, pub3)

                st.success("Padded broadcast demo completed.")
                st.write(f"**Shared message used:** {message}")
                st.write(f"**Ciphertext 1:** {c1}")
                st.write(f"**Ciphertext 2:** {c2}")
                st.write(f"**Ciphertext 3:** {c3}")
                st.write(
                    "**Interpretation:** Random padding changes the ciphertext each time, "
                    "so the deterministic broadcast attack no longer applies cleanly."
                )

            elif attack_choice == "Fermat Factorization":
                p, q = generate_close_prime_pair()
                n = p * q
                phi = (p - 1) * (q - 1)
                e = 65537
                d = mod_inverse(e, phi)

                public_key = (e, n)

                message = short_message if short_message else "hi"
                ciphertext = encrypt(message, public_key)

                start = time.perf_counter()
                recovered_p, recovered_q, iterations = fermat_factor(n)
                end = time.perf_counter()

                recovered_phi = (recovered_p - 1) * (recovered_q - 1)
                recovered_d = mod_inverse(e, recovered_phi)
                recovered_message = decrypt(ciphertext, (recovered_d, n))

                st.success("Fermat attack completed.")
                st.write(f"**Shared short message used:** {message}")
                st.write(f"**Original p:** {p}")
                st.write(f"**Original q:** {q}")
                st.write(f"**Recovered p:** {recovered_p}")
                st.write(f"**Recovered q:** {recovered_q}")
                st.write(f"**Recovered message:** {recovered_message}")
                st.write(f"**Elapsed time:** {end - start:.8f} seconds")
                st.write(f"**Iterations:** {iterations}")
                st.write(
                    "**Interpretation:** When the primes are too close together, "
                    "Fermat factorization can recover the factors quickly."
                )

            elif attack_choice == "Fermat Failure Case":
                p = 50021
                q = 50000021
                while not is_prime(q):
                    q += 1

                n = p * q

                start = time.perf_counter()
                recovered_p, recovered_q, iterations = fermat_factor(n, max_iterations=2000)
                end = time.perf_counter()

                if recovered_p is None:
                    st.warning("Factorization not found within iteration limit.")
                    st.write(f"**Shared reference message:** {short_message if short_message else 'hi'}")
                    st.write(f"**Chosen p:** {p}")
                    st.write(f"**Chosen q:** {q}")
                    st.write(f"**Gap:** {abs(q - p)}")
                    st.write(f"**Elapsed time:** {end - start:.8f} seconds")
                    st.write(f"**Iterations attempted:** {iterations}")
                    st.write(
                        "**Interpretation:** Fermat becomes impractical when the primes are far apart."
                    )
                else:
                    st.write("Unexpected factorization success.")
                    st.write(f"Recovered p: {recovered_p}")
                    st.write(f"Recovered q: {recovered_q}")

            elif attack_choice == "Common Modulus Attack":
                p, q = generate_close_prime_pair()
                n = p * q
                phi = (p - 1) * (q - 1)

                e1 = 3
                while gcd(e1, phi) != 1:
                    e1 += 2

                e2 = e1 + 2
                while gcd(e2, phi) != 1 or gcd(e1, e2) != 1:
                    e2 += 2

                message = short_message if short_message else "ok"
                m = int.from_bytes(message.encode("utf-8"), byteorder="big")

                if m >= n:
                    raise ValueError("Message is too large for this modulus.")

                c1 = pow(m, e1, n)
                c2 = pow(m, e2, n)

                g, a, b = extended_gcd(e1, e2)

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

                st.success("Common modulus attack completed.")
                st.write(f"**Shared short message used:** {message}")
                st.write(f"**Shared modulus n:** {n}")
                st.write(f"**e1:** {e1}")
                st.write(f"**e2:** {e2}")
                st.write(f"**Ciphertext 1:** {c1}")
                st.write(f"**Ciphertext 2:** {c2}")
                st.write(f"**Recovered message:** {recovered_message}")
                st.write(
                    "**Interpretation:** Reusing the same modulus across different public exponents "
                    "can allow plaintext recovery without factoring the modulus."
                )

        except Exception as e:
            st.error(f"Attack demo failed: {e}")

# =========================
# TAB 3: Graphs
# =========================
# =========================
# TAB 3: Graphs
# =========================
with tab3:
    st.header("Experimental Results")
    st.write("These figures summarize the main experimental results from the RSA analysis.")

    fermat_time_graph = Path("fermat_gap_vs_time.png")
    fermat_success_graph = Path("fermat_success_vs_gap.png")
    keysize_graph = Path("keysize_vs_generation_time.png")
    broadcast_graph = Path("broadcast_outcome_by_scenario.png")

    if fermat_time_graph.exists():
        st.subheader("Prime Gap vs Fermat Factorization Time")
        st.image(str(fermat_time_graph), use_container_width=True)
        st.caption(
            "This graph shows that Fermat factorization is fast when the two primes are close together, "
            "but the time increases as the gap between the primes grows."
        )
    else:
        st.info("fermat_gap_vs_time.png not found. Run experiments.py first.")

    if fermat_success_graph.exists():
        st.subheader("Fermat Attack Success vs Prime Gap")
        st.image(str(fermat_success_graph), use_container_width=True)
        st.caption(
            "This graph shows that the Fermat attack succeeds when the prime gap is small, "
            "but its success drops as the primes move farther apart."
        )
    else:
        st.info("fermat_success_vs_gap.png not found. Run experiments.py first.")

    if keysize_graph.exists():
        st.subheader("RSA Key Size vs Key Generation Time")
        st.image(str(keysize_graph), use_container_width=True)
        st.caption(
            "This graph shows that larger RSA key sizes increase key generation time, "
            "highlighting the tradeoff between stronger security and higher computational cost."
        )
    else:
        st.info("keysize_vs_generation_time.png not found. Run experiments.py first.")

    if broadcast_graph.exists():
        st.subheader("Broadcast Attack Outcome by Scenario")
        st.image(str(broadcast_graph), use_container_width=True)
        st.caption(
            "This graph shows whether the broadcast attack succeeds or fails under different conditions. "
            "It succeeds without padding, but fails when padding is used or when the message does not fit the required conditions."
        )
    else:
        st.info("broadcast_outcome_by_scenario.png not found. Run experiments.py first.")

# =========================
# TAB 4: Security Takeaways
# =========================
with tab4:
    st.header("Security Takeaways")

    st.markdown("""
### Key Lessons
- **Textbook RSA is deterministic**, which makes low-exponent broadcast attacks possible.
- **Randomized padding changes ciphertext behavior**, making deterministic attacks much harder to apply.
- **Close primes weaken RSA**, since factorization attacks like Fermat’s method become practical.
- **Shared modulus reuse is dangerous**, because plaintext can be recovered without factoring the modulus.
- **RSA security depends heavily on implementation choices**, not just on mathematical theory.
""")

    st.markdown("""
### Threat Model
This project assumes the attacker has access to ciphertexts and public keys, but not private keys.
The attacks target misuse scenarios such as low public exponents, closely spaced primes,
and shared modulus configurations.
""")

    st.markdown("""
### Shared-Message Insight
Using the same plaintext across the demonstrations shows that the message itself is not what determines
security. The outcome changes because of the RSA configuration: deterministic encryption, padding,
prime spacing, and modulus reuse.
""")