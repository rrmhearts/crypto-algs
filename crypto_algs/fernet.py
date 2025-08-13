from cryptography.fernet import Fernet

# Generate a key (should be securely stored and managed)
key = Fernet.generate_key()
f = Fernet(key)

# Encrypt data
token = f.encrypt(b"my secret data")

# Decrypt data
decrypted_data = f.decrypt(token)

print(f"Original data: b'my secret data'")
print(f"Encrypted token: {token}")
print(f"Decrypted data: {decrypted_data}")