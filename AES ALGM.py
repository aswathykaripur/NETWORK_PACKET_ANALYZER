from Cryptodome.Cipher import AES
import os

key = os.urandom(16)  # Generate a random 128-bit key
iv = os.urandom(16)  # Generate a random 128-bit Initialization Vector (IV)

def encrypt(plaintext, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_plaintext = plaintext + (16 - len(plaintext) % 16) * b'\0'  # Pad the plaintext to a multiple of 16 bytes
    ciphertext = cipher.encrypt(padded_plaintext)
    return ciphertext

def decrypt(ciphertext, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_plaintext = cipher.decrypt(ciphertext)
    plaintext = padded_plaintext.rstrip(b'\0')  # Remove padding from the plaintext
    return plaintext

plaintext = b'This is a message to encrypt'
ciphertext = encrypt(plaintext, key, iv)
print('Encrypted message:', ciphertext)

decrypted_message = decrypt(ciphertext, key, iv)
print('Decrypted message:', decrypted_message.decode())
