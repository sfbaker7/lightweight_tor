from cryptography.fernet import Fernet

def genSymKey():
    symKey = Fernet(Fernet.generate_key())
    return symKey

key1 = genSymKey()
key2 = genSymKey()

enc1 = key1.encrypt(b"my deep dark secret")
enc2 = key2.encrypt(enc1)
print(enc2)
pltext = key1.decrypt(key2.decrypt(enc2))
print(pltext)
