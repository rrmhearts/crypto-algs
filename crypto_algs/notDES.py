
from itertools import cycle
import random

try:
    from .rotate_string import rotate_string_left, split_and_swap_bytearray, mirror_swap_bytearray
except ImportError:
    from rotate_string import rotate_string_left, split_and_swap_bytearray, mirror_swap_bytearray

def shuffle_bits_in_byte(byte_val, permutation):
    if permutation is None:
        permutation = [7, 6, 5, 4, 3, 2, 1, 0]

    shuffled_byte = 0
    for i in range(8):
        original_bit = (byte_val >> i) & 1
        shuffled_byte |= (original_bit << permutation[i])
    return shuffled_byte

def des_like(message, key):
    # Slightly closer to the idea of DES (this is not DES)
    key += b'$3c' # make sure the key is longer than a couple characters.
    # Shuffle bits in each byte
    shuffled_byte_val = [shuffle_bits_in_byte(byte, permutation=None) for byte in message]
    # shuffled_indices = np.random.permutation(mess_len)
    # shuffled_list = [shuffled_byte_val[i] for i in shuffled_indices]
    message = bytes(shuffled_byte_val)

    # Cannot be a divisor
    while len(message) % len(key) == 0:
        key += b'$'

    # Zip with cycling the shorter string a even number of times
    for n in range(len(message)):
        # Rotate key so it is different but not longer than message
        k = rotate_string_left(key, n)#[:len(message)]
        # Repeat the message or the key so that they are equal length
        zipped = zip(message, cycle(k)) if len(message) > len(k) else zip(cycle(message), k)
        # XOR the message with the secret key
        message = bytes(a ^ b for a, b in zipped)
        # Swap ordering
        message = mirror_swap_bytearray(message)

    # inverse_shuffled_indices = np.argsort(shuffled_indices)
    # restored_list = [message[i] for i in inverse_shuffled_indices]
    return bytes(shuffle_bits_in_byte(byte, permutation=None) for byte in message)

def encrypt(message, key):
    # Add Salt
    random_bytes = random.randbytes(len(message))
    message = xor_bytes(message, random_bytes) + random_bytes
    return des_like(message, key)

def decrypt(ciphertext, key):
    plaintext = des_like(ciphertext, key)
    # Remove Salt, must be whole number
    half_n = int(len(plaintext)/2)
    plaintext = xor_bytes(plaintext[0:half_n], plaintext[half_n:])
    # If it was made even, remove last character _
    return plaintext #[:-1] if plaintext[-1] == ord('_') else plaintext
        
def xor_bytes(byte_str1, byte_str2):
     byte_str1, byte_str2 = bytes(byte_str1), bytes(byte_str2)
     # Simplest concept of DES
     # Requires both strings to be the same length
     return bytes(a ^ b for a, b in zip(byte_str1, byte_str2))

if __name__ == "__main__":
    message = b'We have a secret to tell you: hello world.'
    key =     b'secret'

    encoding = encrypt(message, key)
    decoded = decrypt(encoding, key)
    print("Original message:", message)
    print("Secret key: ", key)
    print("Encoded message: ", encoding)
    print("Decoded message: ", decoded)

    simple_enc = simple_encrypt(message, key)
    simple_dec = simple_decrypt(simple_enc, key)
    print("Simple Encoded message: ", simple_enc)
    print("Simple Decoded message: ", simple_dec)
