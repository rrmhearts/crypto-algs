from itertools import cycle
import random

def sieve_of_eratosthenes(limit):
    """
    Generates prime numbers up to a specified limit using the Sieve of Eratosthenes.

    Args:
        limit (int): The upper bound (inclusive) for prime number generation.

    Returns:
        list: A list containing all prime numbers up to the limit.
    """
    primes = [True] * (limit + 1)  # Initialize a boolean array, marking all numbers as potentially prime
    primes[0] = primes[1] = False  # 0 and 1 are not prime

    for num in range(2, int(limit**0.5) + 1):
        if primes[num]:  # If num is prime, mark its multiples as not prime
            for multiple in range(num * num, limit + 1, num):
                primes[multiple] = False

    # Collect all numbers that are still marked as True
    prime_numbers = [i for i, is_prime in enumerate(primes) if is_prime]
    return prime_numbers

def xor_bytes(byte_str1, byte_str2):
     byte_str1, byte_str2 = bytes(byte_str1), bytes(byte_str2)
     # Simplest concept of DES
     # Requires both strings to be the same length
     return bytes(a ^ b for a, b in zip(byte_str1, byte_str2))

def simple_encrypt(message, key):
    random_bytes = random.randbytes(len(message))
    message = xor_bytes(message, random_bytes) + random_bytes
    zipped = zip(message, cycle(key)) if len(message) > len(key) else zip(cycle(message), key)
    # XOR the message with the secret key
    return bytes(a ^ b for a, b in zipped)

def simple_decrypt(ciphertext, key):
    zipped = zip(ciphertext, cycle(key)) if len(ciphertext) > len(key) else zip(cycle(ciphertext), key)
    message_salt = bytes(a ^ b for a, b in zipped)
    half_n = int(len(message_salt)/2)
    return xor_bytes(message_salt[0:half_n], message_salt[half_n:])
