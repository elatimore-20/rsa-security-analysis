import random, os


def gcd(a, b):
    while b:
        a, b = b, a % b
    return a


def extended_gcd(a, b):
    if a == 0:
        return b, 0, 1
    gcd_val, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd_val, x, y


def mod_inverse(e, phi):
    gcd_val, x, _ = extended_gcd(e, phi)
    if gcd_val != 1:
        raise ValueError("Modular inverse does not exist.")
    return x % phi


def is_prime(n, k=10):
    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0:
        return False

    # Write n - 1 as d * 2^r
    r = 0
    d = n - 1
    while d % 2 == 0:
        d //= 2
        r += 1

    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)

        if x == 1 or x == n - 1:
            continue

        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False

    return True


def generate_prime(bits):
    while True:
        candidate = random.getrandbits(bits)
        candidate |= (1 << (bits - 1)) | 1  # make sure it is odd and has correct bit length
        if is_prime(candidate):
            return candidate


def generate_keys(bits=512, e=65537):
    while True:
        p = generate_prime(bits // 2)
        q = generate_prime(bits // 2)
        while q == p:
            q = generate_prime(bits // 2)

        n = p * q
        phi = (p - 1) * (q - 1)

        if gcd(e, phi) == 1:
            d = mod_inverse(e, phi)

            public_key = (e, n)
            private_key = (d, n)

            return public_key, private_key, p, q


def encrypt(message, public_key):
    e, n = public_key
    message_bytes = message.encode("utf-8")
    message_int = int.from_bytes(message_bytes, byteorder="big")

    if message_int >= n:
        raise ValueError("Message is too large for this key size.")

    ciphertext = pow(message_int, e, n)
    return ciphertext


def decrypt(ciphertext, private_key):
    d, n = private_key
    message_int = pow(ciphertext, d, n)

    length = (message_int.bit_length() + 7) // 8
    message_bytes = message_int.to_bytes(length, byteorder="big")
    return message_bytes.decode("utf-8")

def encrypt_with_padding(message, public_key):
    e, n = public_key
    
    # Add simple random padding (NOT real OAEP, just demonstration)
    padding = os.urandom(8)  # 8 random bytes
    padded_message = padding + message.encode()

    message_int = int.from_bytes(padded_message, 'big')

    if message_int >= n:
        raise ValueError("Message too large")

    return pow(message_int, e, n)


if __name__ == "__main__":
    public_key, private_key, p, q = generate_keys(bits=512)

    print("\n--- RSA Key Info ---")
    print("p =", p)
    print("q =", q)
    print("Public key (e, n) =", public_key)
    print("Private key (d, n) =", private_key)

    message = "crypto project"
    print("\nOriginal message:", message)

    ciphertext = encrypt(message, public_key)
    print("Ciphertext:", ciphertext)

    recovered_message = decrypt(ciphertext, private_key)
    print("Decrypted message:", recovered_message)
    