import os
import cryptography
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from typing import Literal, Optional

try:
    from .utils import xor_bytes
except ImportError:
    from utils import xor_bytes
class CryptoManager:
    """
    A manager for performing encryption and decryption using various algorithms
    and modes of operation from the `cryptography` library.

    This class handles key management, initialization vectors (IVs) or nonces,
    and padding automatically for different cryptographic configurations.
    """

    # Supported modes and their properties
    SUPPORTED_MODES = {
        'CBC': {'requires_iv': True, 'iv_length': 16},
        'CTR': {'requires_iv': True, 'iv_length': 8},
        'OFB': {'requires_iv': True, 'iv_length': 16},
        'CFB': {'requires_iv': True, 'iv_length': 16},
        'GCM': {'requires_iv': True, 'iv_length': 12, 'tag_length': 16}, # GCM is an AEAD mode
        'ECB': {'requires_iv': False} # Note: ECB is not recommended for general use
    }

    # Supported algorithms and their properties
    SUPPORTED_ALGORITHMS = {
        'AES': {'key_sizes': [128, 192, 256], 'block_size': 128},
        'TripleDES': {'key_sizes': [64, 128, 192], 'block_size': 64}
    }

    def __init__(
        self,
        algorithm_name: Literal['AES', 'TripleDES'] = 'AES',
        mode_name: Literal['CBC', 'CTR', 'OFB', 'CFB', 'GCM', 'ECB'] = 'CBC',
        key: Optional[bytes] = None,
        key_size_bits: int = 256
    ):
        """
        Initializes the CryptoManager with a specific algorithm, mode, and key.

        Args:
            algorithm_name (str): The encryption algorithm to use (e.g., 'AES').
            mode_name (str): The mode of operation (e.g., 'CBC').
            key (bytes, optional): The encryption key. If None, a new key is generated.
            key_size_bits (int): The desired key size in bits. Must be valid for the algorithm.
        """
        if algorithm_name not in self.SUPPORTED_ALGORITHMS:
            raise ValueError(f"Unsupported algorithm: {algorithm_name}. Supported: {list(self.SUPPORTED_ALGORITHMS.keys())}")
        if mode_name not in self.SUPPORTED_MODES:
            raise ValueError(f"Unsupported mode: {mode_name}. Supported: {list(self.SUPPORTED_MODES.keys())}")

        self.algorithm_name = algorithm_name
        self.mode_name = mode_name
        self.backend = default_backend()

        # Validate and set key size
        algo_info = self.SUPPORTED_ALGORITHMS[self.algorithm_name]
        if key_size_bits not in algo_info['key_sizes']:
            raise ValueError(f"Invalid key size for {algorithm_name}. Supported sizes: {algo_info['key_sizes']}")
        self.key_size_bytes = key_size_bits // 8

        # Set or generate the key
        if key:
            if len(key) != self.key_size_bytes:
                raise ValueError(f"Invalid key length ({len(key)}). Expected {self.key_size_bytes} bytes for {key_size_bits}-bit key.")
            self.key = key
        else:
            self.key = self.generate_key(self.key_size_bytes)

    @staticmethod
    def generate_key(key_size_bytes: int) -> bytes:
        """
        Generates a cryptographically secure random key.

        Args:
            key_size_bytes (int): The desired key size in bytes.

        Returns:
            bytes: A new random key.
        """
        return os.urandom(key_size_bytes)
        
    def _get_mode(self, iv_or_nonce: Optional[bytes] = None, tag: Optional[bytes] = None):
        """Internal helper to instantiate the correct mode object."""
        mode_info = self.SUPPORTED_MODES[self.mode_name]
        
        if self.mode_name == 'ECB':
            return modes.ECB()
        if self.mode_name in ['CBC', 'OFB', 'CFB']:
            if not iv_or_nonce or len(iv_or_nonce) != mode_info['iv_length']:
                raise ValueError(f"{self.mode_name} requires a {mode_info['iv_length']}-byte IV.")
            return getattr(modes, self.mode_name)(iv_or_nonce)
        if self.mode_name == 'CTR':
            if not iv_or_nonce or len(iv_or_nonce) != mode_info['iv_length']:
                raise ValueError(f"{self.mode_name} requires a {mode_info['iv_length']}-byte nonce.")
            return modes.CTR(iv_or_nonce)
        if self.mode_name == 'GCM':
            if not iv_or_nonce or len(iv_or_nonce) != mode_info['iv_length']:
                raise ValueError(f"{self.mode_name} requires a {mode_info['iv_length']}-byte IV.")
            return modes.GCM(iv_or_nonce, tag)
        
        raise NotImplementedError(f"Mode {self.mode_name} is not implemented.")

    def _get_algorithm(self):
        """Internal helper to instantiate the correct algorithm object."""
        if self.algorithm_name == 'AES':
            return algorithms.AES(self.key)
        if self.algorithm_name == 'TripleDES':
            return algorithms.TripleDES(self.key)
        
        raise NotImplementedError(f"Algorithm {self.algorithm_name} is not implemented.")

    def _handmaid(self, encdec, cipher, padded_data, mode, iv_or_nonce):
        response_text = iv_or_nonce if encdec == 'encrypt' else b''#.to_bytes(1, byteorder='big')
        # print(response_text)
        if 'CTR' in str(type(mode)):
            # assert(len(padded_data) % len(iv_or_nonce) == 0), "CTR mode requires data length to be a multiple of nonce length."
            for i in range(0, len(padded_data), len(iv_or_nonce)):
                integer_last_byte = int.from_bytes(iv_or_nonce[-2:], byteorder='big') + i
                last_2bytes = integer_last_byte.to_bytes(2, byteorder='big')
                iv_bytes = iv_or_nonce[:-2] + last_2bytes
                block = padded_data[i:i + len(iv_bytes)]
                # if encdec == 'encrypt':
                encryptor = cipher.encryptor()
                encrypted_iv = encryptor.update(iv_bytes) + encryptor.finalize()
                # elif encdec == 'decrypt':
                #     decryptor = cipher.decryptor()
                #     response_text += decryptor.update(ctr_block) + decryptor.finalize()
                ctr_block = xor_bytes(block, encrypted_iv[0:len(block)])
                response_text += ctr_block

        return response_text

    def encrypt(self, plaintext: bytes) -> bytes:
        """
        Encrypts plaintext. For modes requiring an IV/nonce, it is generated
        and prepended to the ciphertext.

        Args:
            plaintext (bytes): The data to encrypt.

        Returns:
            bytes: The encrypted data (ciphertext), prefixed with IV/nonce if applicable.
        """
        algorithm = self._get_algorithm()
        mode_info = self.SUPPORTED_MODES[self.mode_name]
        iv_or_nonce = None
        
        # --- Padding (for block modes that are not stream ciphers) ---
        if self.mode_name in ['ECB', 'CBC']:
            padder = padding.PKCS7(algorithm.block_size).padder()
            padded_data = padder.update(plaintext) + padder.finalize()
        else:
            padded_data = plaintext

        # --- IV/Nonce Generation ---
        if mode_info['requires_iv']:
            iv_or_nonce = os.urandom(mode_info['iv_length'])
        
        # --- Encryption ---
        try:
            cipher = Cipher(algorithm, self._get_mode(iv_or_nonce), backend=self.backend)
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        except cryptography.exceptions.UnsupportedAlgorithm:
            cipher = Cipher(algorithm, mode=modes.ECB())
            ciphertext :bytes = self._handmaid('encrypt', cipher, padded_data, self._get_mode(iv_or_nonce), iv_or_nonce=iv_or_nonce)
            return ciphertext
        # For GCM, the authentication tag is generated and must be stored
        if self.mode_name == 'GCM':
            return iv_or_nonce + encryptor.tag + ciphertext
        
        # For other IV-based modes, just prepend the IV
        if iv_or_nonce:
            return iv_or_nonce + ciphertext
        
        return ciphertext

    def decrypt(self, ciphertext: bytes) -> bytes:
        """
        Decrypts ciphertext. For modes requiring an IV/nonce, it is extracted
        from the beginning of the ciphertext.

        Args:
            ciphertext (bytes): The data to decrypt.

        Returns:
            bytes: The original decrypted data (plaintext).
        """
        algorithm = self._get_algorithm()
        mode_info = self.SUPPORTED_MODES[self.mode_name]
        
        iv_or_nonce = None
        tag = None

        # --- Extract IV/Nonce and Tag (if applicable) ---
        if mode_info['requires_iv']:
            iv_len = mode_info['iv_length']
            iv_or_nonce = ciphertext[:iv_len]
            
            if self.mode_name == 'GCM':
                tag_len = mode_info['tag_length']
                tag = ciphertext[iv_len : iv_len + tag_len]
                actual_ciphertext = ciphertext[iv_len + tag_len:]
            else:
                actual_ciphertext = ciphertext[iv_len:]
        else:
            actual_ciphertext = ciphertext

        # --- Decryption ---
        try:
            cipher = Cipher(algorithm, self._get_mode(iv_or_nonce, tag), backend=self.backend)
            decryptor = cipher.decryptor()
            padded_plaintext = decryptor.update(actual_ciphertext) + decryptor.finalize()
        except cryptography.exceptions.UnsupportedAlgorithm:
            cipher = Cipher(algorithm, mode=modes.ECB())
            padded_plaintext = self._handmaid('decrypt', cipher, actual_ciphertext, self._get_mode(iv_or_nonce), iv_or_nonce=iv_or_nonce)

        # --- Unpadding ---
        if self.mode_name in ['ECB', 'CBC']:
            unpadder = padding.PKCS7(algorithm.block_size).unpadder()
            plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
        else:
            plaintext = padded_plaintext
            
        return plaintext


# --- Example Usage ---
if __name__ == '__main__':
    # Original message
    my_message = b"This is a secret message that needs to be kept confidential."
    print(f"Original Message: {my_message}\n" + "-"*40)

    # --- Example 1: AES with CBC mode (a common and secure choice) ---
    print("### AES-256 in CBC Mode ###")
    # The manager will generate a secure key automatically
    aes_cbc_manager = CryptoManager(algorithm_name='AES', mode_name='CBC', key_size_bits=256)
    print(f"Generated Key (hex): {aes_cbc_manager.key.hex()}")
    
    encrypted_cbc = aes_cbc_manager.encrypt(my_message)
    print(f"Encrypted (hex): {encrypted_cbc.hex()}")
    
    decrypted_cbc = aes_cbc_manager.decrypt(encrypted_cbc)
    print(f"Decrypted: {decrypted_cbc.decode('utf-8')}")
    assert my_message == decrypted_cbc
    print("AES CBC Test: SUCCESS\n" + "-"*40)

    # --- Example 2: AES with GCM mode (Authenticated Encryption) ---
    print("### AES-128 in GCM Mode ###")
    # GCM provides both confidentiality and authenticity
    aes_gcm_manager = CryptoManager(algorithm_name='AES', mode_name='GCM', key_size_bits=128)
    
    encrypted_gcm = aes_gcm_manager.encrypt(my_message)
    print(f"Encrypted (hex): {encrypted_gcm.hex()}")
    
    decrypted_gcm = aes_gcm_manager.decrypt(encrypted_gcm)
    print(f"Decrypted: {decrypted_gcm.decode('utf-8')}")
    assert my_message == decrypted_gcm
    print("AES GCM Test: SUCCESS\n" + "-"*40)
    
    # --- Example 3: TripleDES with CTR mode (using a pre-defined key) ---
    print("### TripleDES-192 in CTR Mode ###")
    # Ensure the key length matches the specified key size (192 bits = 24 bytes)
    my_3des_key = CryptoManager.generate_key(24) # size in bytes
    tdes_ctr_manager = CryptoManager(algorithm_name='TripleDES', mode_name='CTR', key=my_3des_key, key_size_bits=192)
    
    encrypted_ctr = tdes_ctr_manager.encrypt(my_message)
    print(f"Encrypted (hex): {encrypted_ctr.hex()}")

    decrypted_ctr = tdes_ctr_manager.decrypt(encrypted_ctr)
    print(f"Decrypted: {decrypted_ctr.decode('utf-8')}")
    print(my_message, decrypted_ctr)
    assert my_message == decrypted_ctr
    print("TripleDES CTR Test: SUCCESS\n" + "-"*40)

