import os
import base64
import Crypto
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES

# Constants
BLOCK_SIZE = 16
PADDING = '{'

# Helper Functions
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * PADDING
encode_aes = lambda c, s: base64.b64encode(c.encrypt(pad(s)))
decode_aes = lambda c, e: c.decrypt(base64.b64decode(e)).rstrip(PADDING)

def gen_aes_key():
  """
  Generates an AES key

  :rtype: bytes
  :return: base64 encoded AES key
  """
	secret = os.urandom(BLOCK_SIZE)
	return base64.b64encode(secret)

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

def encrypt_aes(key, msg):
  """
  Encrypts message using AES

  :param bytes key: AES symmetric private key
  :param str msg: plaintext to be encrypted

  :rtype: bytes
  :return: the encrypted message
  """
	cipher = AES.new(base64.b64decode(key))
	encrypted_message = encode_aes(cipher, msg)
	return encrypted_message


def decrypt_aes(key, msg):
  """
  Decrypts message using AES

  :param bytes key: AES symmetric private key
  :param str msg: ciphertext to be decrypted

  :rtype: bytes
  :return: the decrypted message
  """ 
	cipher = AES.new(base64.b64decode(key))
	decrypted_message = decode_aes(cipher, msg)
	return decrypted_message


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



def encrypt(aes_key, rsa_key, msg):
  """
  Encrypts using both AES and RSA

  :param bytes aes_key: AES symmetric private key
  :param bytes rsa_key: RSA public key
  :param str msg: message to be encrypted

  :rtype: tuple
  :return: tuple containing encrypted AES key, then encrypted message
  """
	encrypted_message = encrypt_aes(aes_key, msg)
	encrypted_key = encrypt_rsa(rsa_key, aes_key)
	return (encrypted_key, encrypted_message)


def decrypt(aes_key, rsa_key, msg):
  """
  Decrypts using both AES and RSA

  :param bytes aes_key: AES symmetric private key
  :param bytes rsa_key: RSA private key
  :param str msg: encrypted message

  :rtype: str
  :return: decrypted message
  """
	decrypted_key = decrypt_rsa(rsa_key, aes_key)
	decrypted_message = decrypt_aes(decrypted_key, msg)
	return decrypted_message

def easy_encrypt(rsa_key, msg):
  """
  Encrypts using both AES and RSA after generating the AES key itself

  :param bytes rsa_key: RSA private key
  :param str msg: encrypted message

  :rtype: tuple
  :return: tuple containing encrypted AES key, then encrypted message
  """
  return encrypt(gen_aes_key(), rsa_key, msg)