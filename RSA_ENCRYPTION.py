import os.path

from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA

KEY_BITS = 2048


def Is_Exist_Rsa_Key(key_path):
    try:
        with open(key_path, "rb") as f:
            key = f.read()
            RSA.import_key(key)
        return True
    except Exception as e:
        return False


def Generate_And_Save_Rsa_Keys_In_Disk_PEM(public_path, private_path):
    global KEY_BITS
    if not Is_Exist_Rsa_Key(public_path) or not Is_Exist_Rsa_Key(private_path):
        key = RSA.generate(KEY_BITS)
        public_key = key.public_key()
        private_pem_key = key.export_key()
        public_pem_key = public_key.export_key()

        with open(public_path, "wb") as public_f:
            public_f.write(public_pem_key)

        with open(private_path, "wb") as private_f:
            private_f.write(private_pem_key)

    else:
        with open(private_path, "rb") as f:
            key_data = f.read()
            key = RSA.import_key(key_data)
            public_key = key.public_key()

    return key, public_key


def rsa_encrypt(message: bytes, public_key: RSA.RsaKey) -> bytes:
    cipher = PKCS1_OAEP.new(public_key)
    encrypted = cipher.encrypt(message)
    return encrypted


def rsa_decrypt(encrypted_message: bytes, private_key: RSA.RsaKey) -> bytes:
    cipher = PKCS1_OAEP.new(private_key)
    decrypted = cipher.decrypt(encrypted_message)
    return decrypted
