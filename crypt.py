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
import ast

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
    '''
    :rtype: bytes
    '''
    plaintext_bytes = Fernet(key).decrypt(token)
    return plaintext_bytes

def gen_rsa_keypair():
    '''
    :rtype: keypair objects
    '''
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=1024,
        backend=default_backend()
        )
    public_key = private_key.public_key()
    return private_key, public_key

def encrypt_rsa(public_key, message):
    '''
    :rtype: str
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
    '''
    Decode ciphertext using RSA private key
    :param: bytes/rsa_object private_key
    :param: bytes/string ciphertext
    '''
    if not isinstance(ciphertext, bytes):
        raise Exception('Ciphertext should be of byte format, not ' , type(ciphertext))

    if not isinstance(private_key, rsa.RSAPrivateKey):
        private_key = load_private_pem(private_key)

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
    '''
    :ptype: private_key object, pubic_key object
    :rtype: private_key str, pubic_key str
    '''
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
    public_key = serialization.load_pem_public_key(public_key_pem, backend=default_backend())
    encrypted_payload = encrypt_aes(AES_key, payload)
    encrypted_aes_key = encrypt_rsa(public_key, AES_key)
    return encrypted_aes_key, encrypted_payload

def decrypt():
    return

def decrypt_payload(AES_key, payload):
    '''
    decrypt payload, try to match for valid url, else next relay node
    rtype: string destination_url, empty string
    rtype: string relay_node_ip, next layer of encrypted message
    '''
    decrypted_payload = (decrypt_aes(AES_key, payload)).decode('UTF8')
    ip_addr_match = re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', decrypted_payload)
    url_match = re.search(r'^((https?|ftp|smtp):\/\/)?(www.)?[a-z0-9]+\.[a-z]+(\/[a-zA-Z0-9#]+\/?)*$', decrypted_payload)
    localhost_match = re.search(r'localhost:\d{4}', decrypted_payload)
    destination = ''
    message = ''
    # print(decrypted_payload)
    if url_match is not None:
        destination = url_match.group()
        message = ''
    elif localhost_match is not None:
        destination = localhost_match.group()
        message = decrypted_payload.replace(destination,'')
    elif ip_addr_match is not None:
        destination = ip_addr_match.group()
        message = decrypted_payload.replace(destination,'')
    else:
        raise Exception('No match was found')

    return destination, message
