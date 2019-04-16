import os
import cryptography
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

def main():
    key = gen_aes_key()
    plaintext_bytes = b'Hi, Im Jeff'
    token = encrypt_aes(key, plaintext_bytes)
    decypted_msg = decrypt_aes(key, token)
    private, pub = gen_rsa_keypair()

    message = b'Im RSA'
    cipher = encrypt_rsa(pub, message)
    plaintext = decrypt_rsa(private, cipher)

    print('key', key)
    print('plaintext_bytes', type(plaintext_bytes))
    print('token', token)
    print ('decypted_msg', decypted_msg)
    print('-----RSA----')
    print(private, pub)
    print('message', message)
    print('cipher', cipher)
    print('plaintext', plaintext)



def gen_aes_key():
    '''
    Generates an AES key using the Fernet recipe layer
    :rtype: A URL-safe base64-encoded 32-byte key

    '''
    key = Fernet.generate_key()
    f = Fernet(key)
    return f

def encrypt_aes(key, plaintext_bytes):
    '''
    Encrypts message using AES
    :param bytes key: AES Fernet key
    :param bytes message: the message in bytes meant to be encrypted
    :rtype: bytes
    '''
    token = key.encrypt(plaintext_bytes)
    return token

def decrypt_aes(key, token):
    plaintext_bytes = key.decrypt(token)
    return plaintext_bytes

def gen_rsa_keypair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=1024,
        backend=default_backend()
        )
    public_key = private_key.public_key()

    return private_key, public_key

def encrypt_rsa(public_key, message):
    '''
    :rtype:
    '''
    ciphertext = public_key.encrypt(
    message,
    padding.OAEP(
         mgf=padding.MGF1(algorithm=hashes.SHA256()),
         algorithm=hashes.SHA256(),
         label=None
        )
    )
    return ciphertext

def decrypt_rsa(private_key, ciphertext):
    plaintext = private_key.decrypt(
    ciphertext,
    padding.OAEP(
         mgf=padding.MGF1(algorithm=hashes.SHA256()),
         algorithm=hashes.SHA256(),
         label=None
     )
    )
    return plaintext

def get_pem_format(private_key, public_key):
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
        )
    public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
         )
    return private_pem, public_pem


def encrypt(AES_key, public_key_pem, payload):
    '''
    aes_key_encrypt(payload) + rsa_encrypt(aes_key)
    '''
    if isinstance(public_key_pem, unicode):
        public_key_pem = public_key_pem.encode('UTF8')

    public_key = serialization.load_pem_public_key(public_key_pem, backend=default_backend())
    print(type(public_key))
    encrypted_payload = encrypt_aes(AES_key, payload)
    encrypted_aes_key = encrypt_rsa(public_key, AES_key)
    print(type(encrypted_aes_key))
    return encrypted_payload, encrypted_aes_key

def decrypt():
    return


if __name__ == '__main__':
    main()
