"""
Merkle-Damgård Construction Hash Function
A demonstration implementation of the Merkle-Damgård construction
using a simple compression function.
"""

class MerkleDamgardHash:
    """
    A hash function implementing the Merkle-Damgård construction.
    
    The Merkle-Damgård construction is a method of building collision-resistant
    cryptographic hash functions from collision-resistant one-way compression functions.
    
    Components:
    - Compression function: f(H_i-1, M_i) -> H_i
    - Padding scheme: Ensures message length is multiple of block size
    - Initial value (IV): Starting hash state
    """
    
    def __init__(self, block_size=64, output_size=32):
        """
        Initialize the Merkle-Damgård hash function.
        
        Args:
            block_size: Size of each message block in bytes (default: 64)
            output_size: Size of output hash in bytes (default: 32)
        """
        self.block_size = block_size
        self.output_size = output_size
        self.iv = self._generate_iv()
    
    def _generate_iv(self):
        """Generate initial value (IV) for the hash."""
        # Using a simple IV based on output size
        # In real implementations, this would be a fixed constant
        return bytes([0x67, 0x45, 0x23, 0x01] * (self.output_size // 4))[:self.output_size]
    
    def _compression_function(self, state, block):
        """
        Compression function: f(state, block) -> new_state
        
        This is a simplified compression function for demonstration.
        Real implementations (like SHA-256) use complex mixing operations.
        
        Args:
            state: Current hash state (bytes)
            block: Message block (bytes)
            
        Returns:
            New hash state (bytes)
        """
        # Simple mixing using XOR, rotation, and modular arithmetic
        result = bytearray(self.output_size)
        
        for i in range(self.output_size):
            # Mix state and block bytes
            state_byte = state[i % len(state)]
            block_byte = block[i % len(block)]
            
            # Simple mixing operations
            mixed = (state_byte ^ block_byte) & 0xFF
            mixed = ((mixed << 3) | (mixed >> 5)) & 0xFF  # Rotate
            mixed = (mixed + state_byte + block_byte) & 0xFF  # Add
            
            result[i] = mixed
        
        # Additional mixing round
        for i in range(self.output_size):
            prev = result[(i - 1) % self.output_size]
            curr = result[i]
            next_val = result[(i + 1) % self.output_size]
            result[i] = (curr ^ prev ^ next_val) & 0xFF
        
        return bytes(result)
    
    def _pad_message(self, message):
        """
        Pad the message according to Merkle-Damgård padding scheme.
        
        Padding format:
        - Append a '1' bit (0x80 byte)
        - Append zero bytes until length ≡ block_size - 8 (mod block_size)
        - Append original message length as 64-bit integer
        
        Args:
            message: Original message (bytes)
            
        Returns:
            Padded message (bytes)
        """
        msg_len = len(message)
        message = bytearray(message)
        
        # Append the '1' bit (0x80)
        message.append(0x80)
        
        # Calculate padding needed
        # We need: (current_length + padding + 8) % block_size == 0
        current_len = len(message)
        padding_needed = (self.block_size - (current_len + 8) % self.block_size) % self.block_size
        
        # Append zero bytes
        message.extend([0x00] * padding_needed)
        
        # Append original length as 64-bit big-endian integer
        message.extend((msg_len * 8).to_bytes(8, byteorder='big'))
        
        return bytes(message)
    
    def _split_into_blocks(self, padded_message):
        """
        Split padded message into fixed-size blocks.
        
        Args:
            padded_message: Padded message (bytes)
            
        Returns:
            List of message blocks
        """
        blocks = []
        for i in range(0, len(padded_message), self.block_size):
            blocks.append(padded_message[i:i + self.block_size])
        return blocks
    
    def hash(self, message):
        """
        Compute hash of message using Merkle-Damgård construction.
        
        Args:
            message: Input message (string or bytes)
            
        Returns:
            Hash digest as hexadecimal string
        """
        # Convert string to bytes if necessary
        if isinstance(message, str):
            message = message.encode('utf-8')
        
        # Step 1: Pad the message
        padded = self._pad_message(message)
        
        # Step 2: Split into blocks
        blocks = self._split_into_blocks(padded)
        
        # Step 3: Process blocks with compression function
        state = self.iv
        for block in blocks:
            state = self._compression_function(state, block)
        
        # Step 4: Return final hash as hex string
        return state.hex()
    
    def hash_bytes(self, message):
        """
        Compute hash and return as bytes instead of hex string.
        
        Args:
            message: Input message (string or bytes)
            
        Returns:
            Hash digest as bytes
        """
        if isinstance(message, str):
            message = message.encode('utf-8')
        
        padded = self._pad_message(message)
        blocks = self._split_into_blocks(padded)
        
        state = self.iv
        for block in blocks:
            state = self._compression_function(state, block)
        
        return state


# Demonstration and testing
if __name__ == "__main__":
    # Create hash function instance
    hasher = MerkleDamgardHash(block_size=64, output_size=32)
    
    # Test cases
    test_messages = [
        "Hello, World!",
        "The quick brown fox jumps over the lazy dog",
        "",  # Empty string
        "a",
        "abc",
        "message digest",
        "abcdefghijklmnopqrstuvwxyz",
        "A" * 1000,  # Long message
    ]
    
    print("Merkle-Damgård Hash Function Demonstration")
    print("=" * 70)
    print(f"Block size: {hasher.block_size} bytes")
    print(f"Output size: {hasher.output_size} bytes")
    print("=" * 70)
    print()
    
    for msg in test_messages:
        hash_value = hasher.hash(msg)
        display_msg = msg if len(msg) <= 50 else msg[:47] + "..."
        print(f"Message: {display_msg!r}")
        print(f"Hash:    {hash_value}")
        print()
    
    # Demonstrate collision resistance properties
    print("=" * 70)
    print("Avalanche Effect Demonstration (small input change)")
    print("=" * 70)
    msg1 = "Hello, World!"
    msg2 = "Hello, World?"  # Changed last character
    hash1 = hasher.hash(msg1)
    hash2 = hasher.hash(msg2)
    
    print(f"Message 1: {msg1!r}")
    print(f"Hash 1:    {hash1}")
    print()
    print(f"Message 2: {msg2!r}")
    print(f"Hash 2:    {hash2}")
    print()
    
    # Calculate bit difference
    bits_different = sum(bin(int(h1, 16) ^ int(h2, 16)).count('1') 
                         for h1, h2 in zip(hash1, hash2))
    print(f"Bits different: {bits_different} out of {hasher.output_size * 8}")