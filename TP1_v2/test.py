from cryptography.hazmat.primitives import padding,serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa

def pad(m):
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(m)
    padded_data +=padder.finalize()
    return padded_data

def unpad(m):
    unpadder = padding.PKCS7(128).unpadder()
    data = unpadder.update(m)
    return data + unpadder.finalize()


def pKey2bytes(key):
    return key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )


def sKey2bytes(key):
    return key.private_bytes(
       encoding=serialization.Encoding.PEM,
       format=serialization.PrivateFormat.PKCS8,
       encryption_algorithm=serialization.NoEncryption() #BestAvailableEncryption(b'mypassword')
    )


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
        PSS(
            mgf=MGF1(hashes.SHA256()),
            salt_length=PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )


def verify(pKey,msg,sig):
    try:
        pKey.verify(
        sig,
        msg,
        PSS(
            mgf=MGF1(hashes.SHA256()),
            salt_length=PSS.MAX_LENGTH
        ),
        hashes.SHA256())
        return True
    except:
        return False

serverK = None
clientK = None

import os.path
from os import path
if(not path.exists("keys")):
    print("> mkdir keys")
    os.mkdir( "keys", 0o755 )

if(not(path.exists("keys/ServerPublic.pem") and path.exists("keys/ClientPublic.pem"))):
    serverK = genSKey()
    clientK = genSKey()

    save_public_key(serverK.public_key(),"keys/ServerPublic.pem")
    save_public_key(clientK.public_key(),"keys/ClientPublic.pem")
    save_private_key(serverK,"keys/ServerSecret.pem")
    save_private_key(clientK,"keys/ClientSecret.pem")
    print("> genKeys")
else:
    print("> all good")

# print("\n\nServer:")
# serverK_load = getPrivateKey("keys/ServerSecret.pem")
# print(serverK,"\n",serverK_load,"\n",sKey2bytes(serverK),"\n",sKey2bytes(serverK_load))
# print("\nClient:")
# clientK_load = getPrivateKey("keys/ClientSecret.pem")
# print(clientK,"\n",clientK_load,"\n",sKey2bytes(clientK)==sKey2bytes(clientK_load))



# s = b"akdbkawDJk!-----BEGIN PUBLIC KEY-----@welele"
# r=b''
# print(type(s),type(r))
# r+=s[:3]
# print(r,s[0:1])

def funn(bt):
    x1 = b"-----BEGIN PUBLIC KEY-----"
    x2 = b"-----END PUBLIC KEY-----"
    l=b''
    while(len(bt)>len(x1) and not x1 in bt[0:len(x1)]):
        l+=(bt[0:1])
        bt = bt[1:]
    return l,bt

# a,b = funn(s)
# print(a,b)


# print(b"kd" in s[0:2])

s = b'welele||-----||paspas||-----||helloworldessss||-----||broa'

def splitter(bt,fs=b'||-----||'):
    l=b''
    if(not fs in bt): return bt
    while(len(bt)>0 and not fs in bt[0:len(fs)]):
        l+=bt[0:1]
        bt=bt[1:]
    return l,splitter(bt[len(fs):])


print(splitter(s))


