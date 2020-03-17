import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding,serialization,hashes
from cryptography.hazmat.primitives.asymmetric import dsa


def genSKey():
    return dsa.generate_private_key(
        key_size=1024,
        backend=default_backend()
    )


def save_public_key(pk, filename):
    pem = pk.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(filename, 'wb') as pem_out:
        pem_out.write(pem)


def getPublicKey(ficheiro):
    with open(ficheiro, "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )
    return public_key


def save_private_key(pk, filename):
    pem = pk.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption() #BestAvailableEncryption(b'mypassword')
    )
    with open(filename, 'wb') as pem_out:
        pem_out.write(pem)


def getPrivateKey(ficheiro):
    with open(ficheiro, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )
    return private_key


def sign(sKey,msg):
    return sKey.sign(
        msg,
        hashes.SHA256()
    )


def verify(pKey,msg,sig):
    try:
        pKey.verify(
        sig,
        msg,
        hashes.SHA256()
    )
        return True
    except:
        return False


def pKey2bytes(key):
    return key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )


def bytes2pKey(bts):
    return serialization.load_pem_public_key(
        bts,
        backend=default_backend()
    )


def sKey2bytes(key):
    return key.private_bytes(
       encoding=serialization.Encoding.PEM,
       format=serialization.PrivateFormat.PKCS8,
       encryption_algorithm=serialization.NoEncryption() #BestAvailableEncryption(b'mypassword')
    )


if(not os.path.exists("keys")):
    print("> mkdir keys")
    os.mkdir( "keys", 0o755 )

if(not(os.path.exists("keys/ServerPublic.pem") and os.path.exists("keys/ClientPublic.pem"))):
    serverK = genSKey()
    clientK = genSKey()

    save_public_key(serverK.public_key(),"keys/ServerPublic.pem")
    save_public_key(clientK.public_key(),"keys/ClientPublic.pem")
    save_private_key(serverK,"keys/ServerSecret.pem")
    save_private_key(clientK,"keys/ClientSecret.pem")


FS = b'||-----||'

def splitter(bt,fs=b'||-----||'):
    l=b''
    if(not fs in bt): return bt
    while(len(bt)>0 and not fs in bt[0:len(fs)]):
        l+=bt[0:1]
        bt=bt[1:]
    return l,splitter(bt[len(fs):])

