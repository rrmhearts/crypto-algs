# Cryptography Algorithms

[![Educational Purpose](https://img.shields.io/badge/purpose-educational-blue.svg)](https://github.com/rrmhearts/Kata)
[![Not for Production](https://img.shields.io/badge/production-unsafe-red.svg)](#)

> ⚠️ **Warning**: These implementations should **not** be used in practice. They were implemented solely for educational and enjoyment purposes. Please do not use them in an application or production environment.

## Overview

This repository contains educational implementations of various cryptographic algorithms and primitives. The code is written in a library style and originally was part of the [rrmhearts/Kata](https://github.com/rrmhearts/Kata) repository. As the cryptography-related files grew, they needed their own dedicated home.

## Components

### Hash Functions

#### [Davies-Meyer Construction](./crypto_algs/davies_meyer.py)
A hash function construction that converts a block cipher into a one-way compression function using the formula: `H_i = E_{M_i}(H_{i-1}) ⊕ H_{i-1}`, where the message block serves as the encryption key and the previous hash state serves as the plaintext. Provably secure in the ideal cipher model.

**Key Features:**
- Block cipher-based construction
- Feed-forward mechanism with XOR
- Theoretical security proofs
- Demonstration block cipher included

#### [Merkle-Damgård Construction](./crypto_algs/merkle_damgard.py)
The foundational design pattern used by many popular hash functions (MD5, SHA-1, SHA-2). It builds collision-resistant hash functions from collision-resistant compression functions using iterative processing of message blocks with proper padding.

**Key Features:**
- Generic compression function approach
- Merkle-Damgård padding with length encoding
- Iterative state processing
- Foundation for modern hash standards

### Ciphers & Encryption

#### [Caesar Cipher](./crypto_algs/caesar_cipher.py)
A simple substitution cipher that shifts letters by a fixed number of positions in the alphabet. One of the oldest and most widely known encryption techniques, dating back to Julius Caesar.

**Key Features:**
- Letter shifting algorithm
- Configurable shift amount
- Supports encryption and decryption

#### [Not DES](./crypto_algs/notDES.py)
An approximation of the Data Encryption Standard (DES) symmetric encryption algorithm. Implements Feistel network structure with simplified operations to demonstrate the core concepts of DES without full complexity.

**Key Features:**
- Feistel network structure
- Symmetric key encryption
- Block cipher demonstration
- Educational DES approximation

#### [RSA](./crypto_algs/rsa.py)
Implementation of the RSA (Rivest-Shamir-Adleman) public-key cryptosystem. Demonstrates asymmetric encryption using modular arithmetic and the mathematical properties of prime numbers.

**Key Features:**
- Public/private key pair generation
- Modular exponentiation
- Prime number utilization
- Asymmetric encryption/decryption

### Random Number Generation

#### [Mersenne Twister](./crypto_algs/mersenne_twister.py)
A pseudorandom number generator (PRNG) known for its long period (2^19937 - 1) and excellent statistical properties. Widely used in simulations and applications requiring randomness.

**Key Features:**
- Long period length
- Fast generation
- Good statistical distribution
- State-based generation

### Utilities

#### [Sieve of Eratosthenes](./crypto_algs/utils.py)
An ancient algorithm for finding all prime numbers up to a given limit. Essential for many cryptographic operations, particularly in RSA key generation and other number-theoretic applications.

**Key Features:**
- Efficient prime number generation
- Ancient algorithm (Greek mathematician Eratosthenes)
- Used in cryptographic key generation

#### [String Rotation Utilities](./crypto_algs/rotate_string.py)
Helper functions for rotating and manipulating strings, commonly used in various cipher implementations and text transformations.

**Key Features:**
- Left and right rotation
- Circular shift operations
- Utility functions for cipher implementations

## Project Structure

```
crypto_algs/
├── caesar_cipher.py       # Classical substitution cipher
├── davies_meyer.py        # Block cipher-based hash construction
├── merkle_damgard.py      # Compression function-based hash construction
├── mersenne_twister.py    # Pseudorandom number generator
├── notDES.py              # DES approximation (Feistel network)
├── rsa.py                 # Public-key cryptosystem
├── rotate_string.py       # String manipulation utilities
└── utils.py               # Sieve of Eratosthenes and helpers
```

## Educational Purpose

This repository serves as:
- **Learning Resource**: Understanding how cryptographic primitives work under the hood
- **Algorithm Study**: Exploring different approaches to encryption, hashing, and randomness
- **Implementation Practice**: Working with mathematical concepts in practical code
- **Comparative Analysis**: Seeing differences between constructions (e.g., Davies-Meyer vs Merkle-Damgård)

## Security Notice

These implementations are intentionally simplified for educational clarity and lack many critical security features present in production cryptographic libraries:

- ❌ No constant-time operations (vulnerable to timing attacks)
- ❌ No secure random number generation
- ❌ Simplified algorithms (may have unknown vulnerabilities)
- ❌ No peer review or security auditing
- ❌ May use weak or non-standard parameters

**For production use, always use:**
- Industry-standard libraries (OpenSSL, libsodium, PyCryptodome)
- Well-audited implementations
- Current cryptographic standards (AES, SHA-256, SHA-3, etc.)
- Proper key management systems

## Contributing

Contributions that improve the educational value of these implementations are welcome! Please ensure:
- Code remains clear and well-commented
- Educational purpose is maintained
- Security warnings are preserved
- New implementations include proper documentation

## License

MIT License

## References

- Serious Cryptography by Jean-Philippe Aumasson
- [NIST Cryptographic Standards](https://csrc.nist.gov/projects/cryptographic-standards-and-guidelines)

---

**Remember**: Real cryptography is hard. Use established libraries for any actual security needs!