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

