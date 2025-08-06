import random
import sympy
try:
    from .utils import sieve_of_eratosthenes
except ImportError:
    from utils import sieve_of_eratosthenes

LIMIT = 100
PRIMES_TO_LIMIT = sieve_of_eratosthenes(LIMIT)

def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

# def mod_inverse(e, phi):
#     d = 0
#     x1, x2, y1 = 0, 1, 1
#     temp_phi = phi
#     while e > 0:
#         temp1, temp2 = temp_phi // e, temp_phi - (temp_phi // e) * e
#         temp_phi, e = e, temp2
#         x, y = x2 - temp1 * x1, d - temp1 * y1
#         x2, x1, d, y1 = x1, x, y1, y
#         if temp_phi == 1:
#             return d + phi
def mod_inverse(e, phi):
    """
    Calculates the modular multiplicative inverse of e modulo phi.
    Returns d such that (d * e) % phi == 1.
    """
    g, x, y = extended_gcd(e, phi)
    if g != 1:
        raise Exception('Modular inverse does not exist')
    return x % phi

def extended_gcd(a, b):
    """
    Extended Euclidean Algorithm.
    Returns a tuple (g, x, y) such that a*x + b*y = g = gcd(a, b).
    """
    if a == 0:
        return b, 0, 1
    else:
        g, x, y = extended_gcd(b % a, a)
        return g, y - (b // a) * x, x
    
def encrypt(public_key, plaintext):
    key, n = public_key
    cipher = [(ord(char) ** key) % n for char in plaintext]
    return cipher

def decrypt(private_key, ciphertext):
    key, n = private_key
    plain = [chr((char ** key) % n) for char in ciphertext]
    return ''.join(plain)

def is_prime(num):
    if num <= 1:
        return False
    if num in PRIMES_TO_LIMIT:
        return True
    for p in PRIMES_TO_LIMIT:
        if num % p == 0:
            return False
    for i in range(LIMIT, int(num**0.5) + 1):
        if num % i == 0:
            return False
    return True

def find_next_prime(n):
    next_num = n + 2 if n%2 == 1 else n + 1
    while True:
        if is_prime(next_num):
            return next_num
        next_num += 1

def generate_keys():
    i_p = random.randint(2, len(PRIMES_TO_LIMIT)-3)
    i_q = random.randint(i_p+1, len(PRIMES_TO_LIMIT)-2)
    i_e = random.randint(i_q+1, len(PRIMES_TO_LIMIT)-1)
    p = PRIMES_TO_LIMIT[i_p]#sympy.nextprime(random.randint(5, 100))
    q = PRIMES_TO_LIMIT[i_q]#sympy.nextprime(random.randint(p+1, 200))
    e = PRIMES_TO_LIMIT[i_e]#sympy.nextprime(q)
    n = p * q
    phi = (p - 1) * (q - 1)
    print(e, phi)
    d = mod_inverse(e, phi)
    print(d)
    public_key = (e, n)
    private_key = (d, n)
    return public_key, private_key

if __name__ == "__main__":
    p = 53
    q = 59
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 3
    d = mod_inverse(e, phi)

    public_key = (e, n)
    private_key = (d, n)

    message = "HELLO"
    encrypted_msg = encrypt(public_key, message)
    print("Encrypted message:", encrypted_msg)

    decrypted_msg = decrypt(private_key, encrypted_msg)
    print("Decrypted message:", decrypted_msg)