from multiprocessing import Pipe, Process

class BiConn(object):
    def __init__(self,left,right,timeout=None):
        """
        left : a função que vai ligar ao lado esquerdo do Pipe
        right: a função que vai ligar ao outro lado
        timeout: (opcional) numero de segundos que aguarda pela terminação do processo
        """
        left_end, right_end = Pipe()
        self.timeout=timeout
        self.lproc = Process(target=left, args=(left_end,))       # os processos ligados ao Pipe
        self.rproc = Process(target=right, args=(right_end,))
        self.left  = lambda : left(left_end)                       # as funções ligadas já ao Pipe
        self.right = lambda : right(right_end)
    
    def auto(self, proc=None):
        if proc == None:             # corre os dois processos independentes
            self.lproc.start()
            self.rproc.start()  
            self.lproc.join(self.timeout)
            self.rproc.join(self.timeout)
        else:                        # corre só o processo passado como parâmetro
            proc.start(); proc.join()
    
    def manual(self):   #  corre as duas funções no contexto de um mesmo processo Python
        self.left()
        self.right()


from cryptography.hazmat.backends   import default_backend
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

default_algorithm = hashes.SHA256
# seleciona-se um dos vários algorimos implementados na package

def hashs(s):
    digest = hashes.Hash(default_algorithm(),backend=default_backend())
    digest.update(s)
    return digest.finalize()

# def mac(key,source, tag= None):
#     h = hmac.HMAC(key,default_algorithm(),default_backend())
#     h.update(source)
#     if tag == None:
#         return h.finalize() 
#     h.verify(tag)

def kdf(salt):
    return PBKDF2HMAC(
        algorithm=default_algorithm(),   # SHA256
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()        # openssl
        )   






from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh,dsa
from cryptography.hazmat.primitives import serialization,hashes
from getpass import getpass
from cryptography.exceptions import *

# Generate some parameters DH
parameters_dh = dh.generate_parameters(generator=2, key_size=1024,
                                     backend=default_backend())

# Generate some parameters DSA
parameters_dsa = dsa.generate_parameters(key_size=1024,backend=default_backend())



from BiConn import BiConn
from Auxs   import hashs
import getpass, os, io

def Dh(conn):
    # agreement
    pk = parameters_dh.generate_private_key()
    pub = pk.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo)
    
    
    conn.send(pub)
    
    # shared_key calculation
    peer_pub_key = serialization.load_pem_public_key(
            conn.recv(),
            backend=default_backend())
    shared_key   = pk.exchange(peer_pub_key)
    
    # confirmation
    my_tag = hashs(bytes(shared_key))
    conn.send(my_tag)
    peer_tag = conn.recv()
    if my_tag == peer_tag:
        print('OK DH')
    else:
        print('FAIL DH')
    
    
    private_key_dsa = parameters_dsa.generate_private_key()
    pub_dsa = private_key_dsa.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo)
    conn.send(pub_dsa)

    
    sig = private_key_dsa.sign(pub,hashes.SHA256())
    peer_pub_dsa = serialization.load_pem_public_key( 
        conn.recv(), 
        backend=default_backend())  
    conn.send((sig,pub))
    
    try:
        sig,pub = conn.recv()
        peer_pub_dsa.verify = (sig, pub, hashes.SHA256())
        print("DSA ok")
    except InvalidSignature:
        print("fail DSA")




BiConn(Dh,Dh).auto()

