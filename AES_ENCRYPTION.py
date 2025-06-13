from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import os


def Encrypt_AES_CBC_PlainText(plain_text: bytes, key):
    iv = Generate_AES_CBC_IV_128_Bit()

    padder = padding.PKCS7(128).padder()
    padded_plaintext = padder.update(plain_text) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Encrypt the padded plaintext
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

    final_cipher = iv + ciphertext
    return final_cipher


def Decrypt_AES_CBC_CipherText(cipher_text, key):
    iv = cipher_text[:16]
    cipher_text = cipher_text[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())

    decryptor = cipher.decryptor()

    decrypted_padded_text = decryptor.update(cipher_text) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    decrypted_text = unpadder.update(decrypted_padded_text) + unpadder.finalize()

    return decrypted_text


def Generate_AES_CBC_256_Bit_Key():
    return os.urandom(32)


def Generate_AES_CBC_IV_128_Bit():
    return os.urandom(16)
