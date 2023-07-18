import hashlib
import os

key = os.urandom(16)  # Generate a random 128-bit key
iv = os.urandom(16)  # Generate a random 128-bit Initialization Vector (IV)

def encrypt(plaintext, key, iv):
    cipher = hashlib.new("aes", key)
    return cipher.encrypt(plaintext)

def decrypt(ciphertext, key, iv):
    cipher = hashlib.new("aes", key)
    return cipher.decrypt(ciphertext)

plaintext = b"hello world"
ciphertext = encrypt(plaintext, key, iv)
print("Ciphertext:", ciphertext)

decrypted_text = decrypt(ciphertext, key, iv)
print("Decrypted text:", decrypted_text)
