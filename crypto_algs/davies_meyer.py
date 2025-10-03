"""
Davies-Meyer Construction Hash Function
Demonstrates the Davies-Meyer construction and compares it with Merkle-Damgård.

Key Difference:
- Merkle-Damgård: Uses a compression function f(state, block) -> new_state
- Davies-Meyer: Uses a block cipher E(key, plaintext) in the form:
  H_i = E(M_i, H_{i-1}) XOR H_{i-1}
  
The Davies-Meyer construction converts a block cipher into a one-way compression function.
"""

import struct


class SimpleBlockCipher:
    """
    A simplified block cipher for demonstration purposes.
    Real implementations would use AES, DES, etc.
    """
    
    def __init__(self, block_size=16):
        self.block_size = block_size
    
    def _rotate_left(self, val, n, bits=8):
        """Rotate bits left."""
        n = n % bits
        return ((val << n) | (val >> (bits - n))) & ((1 << bits) - 1)
    
    def _feistel_round(self, left, right, round_key):
        """Simple Feistel network round."""
        # XOR with round key
        temp = right ^ round_key
        # Non-linear S-box (substitution)
        temp = ((temp * 31) + 17) & 0xFF
        # Rotation
        temp = self._rotate_left(temp, 3)
        # XOR with left half
        new_right = left ^ temp
        return right, new_right
    
    def encrypt(self, key, plaintext):
        """
        Encrypt plaintext using key.
        
        Args:
            key: Encryption key (bytes)
            plaintext: Data to encrypt (bytes)
            
        Returns:
            Ciphertext (bytes)
        """
        # Ensure inputs are the right size
        key = (key * ((self.block_size // len(key)) + 1))[:self.block_size]
        plaintext = (plaintext * ((self.block_size // len(plaintext)) + 1))[:self.block_size]
        
        # Convert to list for manipulation
        state = list(plaintext)
        key_bytes = list(key)
        
        # Multiple rounds of mixing
        num_rounds = 8
        for round_num in range(num_rounds):
            # Generate round key
            round_key = sum(key_bytes) ^ round_num
            
            # Process pairs of bytes with Feistel structure
            for i in range(0, len(state) - 1, 2):
                state[i], state[i + 1] = self._feistel_round(
                    state[i], state[i + 1], (round_key + i) & 0xFF
                )
            
            # Add key material
            for i in range(len(state)):
                state[i] = (state[i] ^ key_bytes[i]) & 0xFF
            
            # Permutation
            state = [state[(i * 5) % len(state)] for i in range(len(state))]
        
        return bytes(state)


class DaviesMeyerHash:
    """
    Hash function using Davies-Meyer construction.
    
    Construction: H_i = E_{M_i}(H_{i-1}) ⊕ H_{i-1}
    
    Where:
    - E is a block cipher
    - M_i is the message block (used as the key)
    - H_{i-1} is the previous hash state (used as plaintext)
    - ⊕ is XOR
    """
    
    def __init__(self, block_size=16):
        self.block_size = block_size
        self.cipher = SimpleBlockCipher(block_size)
        self.iv = self._generate_iv()
    
    def _generate_iv(self):
        """Generate initial value."""
        return bytes([0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF] * 
                     (self.block_size // 8))[:self.block_size]
    
    def _pad_message(self, message):
        """Pad message using Merkle-Damgård strengthening."""
        msg_len = len(message)
        message = bytearray(message)
        
        # Append 0x80
        message.append(0x80)
        
        # Pad with zeros
        padding_needed = (self.block_size - (len(message) + 8) % self.block_size) % self.block_size
        message.extend([0x00] * padding_needed)
        
        # Append length
        message.extend((msg_len * 8).to_bytes(8, byteorder='big'))
        
        return bytes(message)
    
    def _davies_meyer_compress(self, state, block):
        """
        Davies-Meyer compression function.
        
        H_i = E_{M_i}(H_{i-1}) ⊕ H_{i-1}
        
        Args:
            state: Previous hash state (H_{i-1})
            block: Message block (M_i)
            
        Returns:
            New hash state (H_i)
        """
        # Use message block as key, hash state as plaintext
        encrypted = self.cipher.encrypt(key=block, plaintext=state)
        
        # XOR with previous state (feed-forward)
        result = bytes(a ^ b for a, b in zip(encrypted, state))
        
        return result
    
    def hash(self, message):
        """Compute Davies-Meyer hash."""
        if isinstance(message, str):
            message = message.encode('utf-8')
        
        padded = self._pad_message(message)
        
        # Process each block
        state = self.iv
        for i in range(0, len(padded), self.block_size):
            block = padded[i:i + self.block_size]
            state = self._davies_meyer_compress(state, block)
        
        return state.hex()
    
    def hash_bytes(self, message):
        """Return hash as bytes."""
        if isinstance(message, str):
            message = message.encode('utf-8')
        
        padded = self._pad_message(message)
        state = self.iv
        
        for i in range(0, len(padded), self.block_size):
            block = padded[i:i + self.block_size]
            state = self._davies_meyer_compress(state, block)
        
        return state


class MerkleDamgardHash:
    """
    Standard Merkle-Damgård construction for comparison.
    
    Construction: H_i = f(H_{i-1}, M_i)
    
    Where f is a compression function that directly mixes state and message.
    """
    
    def __init__(self, block_size=16):
        self.block_size = block_size
        self.iv = bytes([0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF] * 
                       (self.block_size // 8))[:self.block_size]
    
    def _compression_function(self, state, block):
        """
        Direct compression function (not using a block cipher).
        Mixes state and message block directly.
        """
        result = bytearray(self.block_size)
        
        for i in range(self.block_size):
            state_byte = state[i]
            block_byte = block[i % len(block)]
            
            # Direct mixing operations
            mixed = (state_byte ^ block_byte) & 0xFF
            mixed = ((mixed << 3) | (mixed >> 5)) & 0xFF
            mixed = (mixed + state_byte + block_byte) & 0xFF
            
            result[i] = mixed
        
        # Additional rounds
        for i in range(self.block_size):
            prev = result[(i - 1) % self.block_size]
            curr = result[i]
            next_val = result[(i + 1) % self.block_size]
            result[i] = (curr ^ prev ^ next_val) & 0xFF
        
        return bytes(result)
    
    def _pad_message(self, message):
        """Pad message."""
        msg_len = len(message)
        message = bytearray(message)
        message.append(0x80)
        
        padding_needed = (self.block_size - (len(message) + 8) % self.block_size) % self.block_size
        message.extend([0x00] * padding_needed)
        message.extend((msg_len * 8).to_bytes(8, byteorder='big'))
        
        return bytes(message)
    
    def hash(self, message):
        """Compute Merkle-Damgård hash."""
        if isinstance(message, str):
            message = message.encode('utf-8')
        
        padded = self._pad_message(message)
        
        state = self.iv
        for i in range(0, len(padded), self.block_size):
            block = padded[i:i + self.block_size]
            state = self._compression_function(state, block)
        
        return state.hex()


def compare_constructions():
    """Compare Davies-Meyer and Merkle-Damgård constructions."""
    
    print("=" * 80)
    print("DAVIES-MEYER vs MERKLE-DAMGÅRD COMPARISON")
    print("=" * 80)
    print()
    
    # Create instances
    dm_hasher = DaviesMeyerHash(block_size=16)
    md_hasher = MerkleDamgardHash(block_size=16)
    
    test_messages = [
        "Hello, World!",
        "The quick brown fox",
        "",
        "a",
        "Short message",
        "A" * 100,
    ]
    
    print("KEY DIFFERENCES:")
    print("-" * 80)
    print("Davies-Meyer Construction:")
    print("  • Uses a block cipher: H_i = E_{M_i}(H_{i-1}) ⊕ H_{i-1}")
    print("  • Message block becomes the encryption KEY")
    print("  • Previous hash state becomes the PLAINTEXT")
    print("  • XOR with previous state (feed-forward) ensures one-wayness")
    print("  • Provably secure if block cipher is secure (ideal cipher model)")
    print()
    print("Merkle-Damgård Construction:")
    print("  • Uses a compression function: H_i = f(H_{i-1}, M_i)")
    print("  • Both state and message are inputs to compression function")
    print("  • No requirement for block cipher structure")
    print("  • Security depends on compression function properties")
    print("  • More flexible but requires careful compression function design")
    print()
    print("=" * 80)
    print()
    
    print("HASH OUTPUTS:")
    print("-" * 80)
    for msg in test_messages:
        dm_hash = dm_hasher.hash(msg)
        md_hash = md_hasher.hash(msg)
        
        display_msg = msg if len(msg) <= 40 else msg[:37] + "..."
        print(f"Message: {display_msg!r}")
        print(f"  Davies-Meyer: {dm_hash}")
        print(f"  Merkle-Damgård: {md_hash}")
        print()
    
    print("=" * 80)
    print("ARCHITECTURAL COMPARISON:")
    print("-" * 80)
    print()
    print("Davies-Meyer (Block Cipher Based):")
    print("  ┌─────────────────────────────────────┐")
    print("  │  Message Block M_i (used as KEY)   │")
    print("  └──────────────┬──────────────────────┘")
    print("                 │")
    print("                 ▼")
    print("  ┌──────────────────────────┐")
    print("  │   Block Cipher E         │")
    print("  │   E_{M_i}(H_{i-1})      │◄─── H_{i-1} (as plaintext)")
    print("  └──────────┬───────────────┘")
    print("             │")
    print("             ▼")
    print("  ┌──────────────────────────┐")
    print("  │   XOR with H_{i-1}       │◄─── H_{i-1} (feed-forward)")
    print("  └──────────┬───────────────┘")
    print("             │")
    print("             ▼")
    print("           H_i (output)")
    print()
    print("Merkle-Damgård (Direct Compression):")
    print("  ┌──────────┐   ┌──────────┐")
    print("  │ H_{i-1}  │   │   M_i    │")
    print("  └────┬─────┘   └────┬─────┘")
    print("       │              │")
    print("       └──────┬───────┘")
    print("              ▼")
    print("  ┌───────────────────────┐")
    print("  │ Compression Function  │")
    print("  │    f(H_{i-1}, M_i)   │")
    print("  └──────────┬────────────┘")
    print("             │")
    print("             ▼")
    print("           H_i (output)")
    print()
    print("=" * 80)
    
    print()
    print("SECURITY PROPERTIES:")
    print("-" * 80)
    print("Davies-Meyer:")
    print("  ✓ Collision resistance (if cipher is ideal)")
    print("  ✓ Preimage resistance (if cipher is ideal)")
    print("  ✓ Built from well-studied block ciphers (AES, DES)")
    print("  ✓ Security proof in ideal cipher model")
    print()
    print("Merkle-Damgård:")
    print("  ✓ Collision resistance (if compression function is)")
    print("  ✓ More flexible - any compression function works")
    print("  ✗ Vulnerable to length extension attacks (without finalization)")
    print("  ✓ Used in MD5, SHA-1, SHA-2 families")
    print()
    print("=" * 80)


if __name__ == "__main__":
    compare_constructions()