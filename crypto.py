import os
import base64
import Crypto
from Crypto.PublicKey import RSA

# Constants
BLOCK_SIZE = 16
PADDING = '{'

# Helper Functions
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * PADDING

def gen_rsa_key():
  """
  Generates an RSA key

  :rtype: tuple
  :return: a tuple with public key as the first value and private key as the second
  """
  new_key = RSA.generate(2048, e=65537)
  public_key = new_key.publickey().exportKey('PEM')
  private_key = new_key.exportKey('PEM')
  return (public_key, private_key)

def encrypt_rsa(key, msg):
  """
  Encrypts using RSA public key

  :param bytes key: RSA public key
  :param str msg: message to be encrypted

  :rtype: bytes
  :return: the encrypted message
  """
  public_key =  RSA.importKey(key)
  encrypted_message = public_key.encrypt(msg, 32)[0]
  return encrypted_message

def decrypt_rsa(key, msg):
  """
  Decrypts using RSA private key

  :param bytes key: RSA private key
  :param str msg: message to be decrypted

  :rtype: bytes
  :return: the decrypted message
  """
  private_key = RSA.importKey(key)
  decrypted_message = private_key.decrypt(msg)
  return decrypted_message
