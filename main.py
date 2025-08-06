import crypto_algs
import crypto_algs.rsa as RSA
import crypto_algs.notDES as DES

mn = crypto_algs.MersenneTwister()

print("***Mersenne random test", mn.next(5) )

public_key, private_key = RSA.generate_keys()
print("*** RSA: pub, priv -->", public_key, private_key)
message = "HELLO"
encrypted_msg = RSA.encrypt(public_key, message)
print("Encrypted message:", encrypted_msg)

decrypted_msg = RSA.decrypt(private_key, encrypted_msg)
print("Decrypted message:", decrypted_msg)

print("*** DES Encryption")
message = b'We have a secret to tell you: hello world.'
key =     b'secret'

encoding = DES.encrypt(message, key)
decoded = DES.decrypt(encoding, key)
print("Original message:", message)
print("Secret key: ", key)
print("Encoded message: ", encoding)
print("Decoded message: ", decoded)