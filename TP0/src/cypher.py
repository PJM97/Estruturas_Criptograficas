import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import (Cipher,algorithms,modes)
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

Len_salt = 16
Len_hash = 32
Len_iv = 12
Len_tag = 16
Len_aead = 4

def deriveKey(secret,salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
        )
    return kdf.derive(secret)

def HMAC(ciphertext,key):
    h = hmac.HMAC(
        key,
        hashes.SHA256(),
        backend=default_backend()
        )
    h.update(ciphertext)
    return h.finalize()

def encrypt(key, plaintext, associated_data):
    iv = os.urandom(12)
    encryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv),
        backend=default_backend()
    ).encryptor()
    encryptor.authenticate_additional_data(associated_data)
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return (iv, ciphertext, encryptor.tag)

def decrypt(key, associated_data, iv, ciphertext, tag):
    decryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv, tag),
        backend=default_backend()
    ).decryptor()

    decryptor.authenticate_additional_data(associated_data)
    return decryptor.update(ciphertext) + decryptor.finalize()

def splitter(p):
    l1 = Len_salt
    l2 = l1 + Len_hash
    l3 = l2 + Len_iv
    l4 = l3 + Len_tag
    l5 = l4 + Len_aead
    return p[:Len_salt],p[l1:l2],p[l2:l3],p[l3:l4],p[l4:l5],p[l5:]

def pswdHandler(pswd,salt=os.urandom(16)):
    key  = deriveKey(pswd,salt)
    hsh  = HMAC(salt+key,key)
    aead = os.urandom(4)
    return (pswd,salt,key,hsh,aead)

def pack(pswd,ptxt):
    pswd,salt,key,hsh,aead = pswdHandler(pswd)
    iv,ctxt,tag = encrypt(key,ptxt,aead)
    return (salt+hsh+iv+tag+aead+ctxt)

def unpack(pswd,pacote):
    salt,hsh,iv,tag,aead,ctxt = splitter(pacote)
    pswd,salt1,key,hsh1,aead1 = pswdHandler(pswd,salt)
    if (hsh!=hsh1) : raise NameError("Invalid Key")
    try:
        ptxt = decrypt(key,aead,iv,ctxt,tag)
    except:
        raise NameError("Invalid Packet")
    return ptxt.decode()
