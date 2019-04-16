import os
import base64
import re
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

    encryptedKey = encrypt_rsa(pub,key)
    decryptedKey = decrypt_AESKey(private,encryptedKey)
    print("ARE THE KEYS THE SAME")
    print(decryptedKey == key)
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

    payload = b'dsafdsafdsafads  asdas  192.0.2.2'
    encryptedpayload = encrypt_aes(key, payload)
    IP,message = decrypt_payload(key,encryptedpayload)
    print("IP ADDRESS:")
    print(IP)
    print("MESSAGE:")
    print(message)



def gen_aes_key():
    '''
    Generates an AES key using the Fernet recipe layer
    :rtype: A URL-safe base64-encoded 32-byte key
    '''
    key = Fernet.generate_key()
    return key

def encrypt_aes(key, plaintext_bytes):
    '''
    Encrypts message using AES
    :param bytes key: AES Fernet key
    :param bytes message: the message in bytes meant to be encrypted
    :rtype: bytes
    '''
    token = Fernet(key).encrypt(plaintext_bytes)
    return token

def decrypt_aes(key, token):
    plaintext_bytes = Fernet(key).decrypt(token)
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

def decrypt_rsa(private_key_pem, ciphertext):
    private_key = load_private_pem(private_key_pem)
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

def load_private_pem(private_key_pem):
    '''
    Converts private_key.pem format to private_key object
    '''
    private_key = serialization.load_pem_private_key(
         private_key_pem,
         password=None,
         backend=default_backend()
         )
    return private_key


def encrypt(AES_key, public_key_pem, payload):
    '''
    aes_key_encrypt(payload) + rsa_encrypt(aes_key)
    '''
    print(public_key_pem)
    public_key = serialization.load_pem_public_key(public_key_pem, backend=default_backend())
    # print((public_key))
    print("PAYLOAD")
    print(type(payload))
    encrypted_payload = encrypt_aes(AES_key, payload)
    encrypted_aes_key = encrypt_rsa(public_key, AES_key)
    return encrypted_aes_key, encrypted_payload

def decrypt():
    return

def decrypt_payload(AES_key, payload):
    #return IP and Message as a tuple, both strings
    decrypted_payload = (decrypt_aes(AES_key, payload)).decode('UTF8')
    IP = re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', decrypted_payload).group()
    message = decrypted_payload.replace(IP,'')
    return IP,message


if __name__ == '__main__':
    main()
