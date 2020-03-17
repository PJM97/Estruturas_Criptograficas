
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
# Generate some parameters. These can be reused.
parameters = dh.generate_parameters(generator=2, key_size=512,
                                     backend=default_backend())


def HMAC(plaintext,key,ciphertext=None):
    h = hmac.HMAC(
            key,
            hashes.SHA256(),
            backend=default_backend()
        )
    h.update(plaintext)
    if(ciphertext==None):return h.finalize()
    try:
        h.verify(ciphertext)
        return True
    except:
        return False


# key=os.urandom(1)
# nonce = os.urandom(16)
# cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None, backend=default_backend())
# ct = cipher.encryptor().update(b"a secret message")

# pt = cipher.decryptor().update(ct)

# print("CT:",ct,"PT:",pt)






m1=b"well1"
m2=b"well2"
k=b"123"

h1=HMAC(m1,k)

print(type(h1),h1)
print(type(None))
print(HMAC(m1,k,h1),HMAC(m2,k,h1),HMAC(m2,k,HMAC(m2,k)))



# f = open("keyy", "w")
# f.write("welele")
# f.close()




