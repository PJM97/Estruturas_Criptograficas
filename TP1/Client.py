import asyncio
import socket
from aes import *
from dsa import *
from itertools import takewhile

conn_port = 8888
max_msg_size = 9999

def funn(bt):
    l=b''
    while(len(bt)>0 and bt[0]!=b'@'):
        l.join(bt[0])
        bt = bt[1:]
    return l,bt[1:]

class Client:
    def __init__(self, sckt=None):
        self.key = DHgenSKey()
        self.sckt = sckt
        self.msg_cnt = 0
        self.dsaSK = getPrivateKey("keys/ClientSecret.pem")
        self.dsaServerPK = getPublicKey("keys/ServerPublic.pem")


    def process(self, msg=b""):

        if(self.msg_cnt==0):
            self.msg_cnt+=1
            return pKey2bytes(DHgenPKey(self.key))
        if(self.msg_cnt==1):
            sig,k=splitter(msg)
            v = verify(
                self.dsaServerPK,
                pKey2bytes(DHgenPKey(self.key))+k,
                sig
            )

            if(v):
                print("> Signature Verification Successful")
            else:
                print("> Failed Signature Verification")
                return b' '
            shared_secret=DHgenSharedSecret(self.key,bytes2pKey(k))
            print('\nShared Secret: '+str(shared_secret))
        
        self.msg_cnt +=1
        print('\nInput message to send:')
        new_msg = str(input())
        ct  = encrypt(new_msg,shared_secret)
        mac = HMAC(ct,shared_secret)
        sig = sign(self.dsaSK,pKey2bytes(DHgenPKey(self.key))+k)
        msg = sig+FS+ct+FS+mac
        return msg if len(new_msg)>0 else b' '


@asyncio.coroutine
def tcp_echo_client(loop=None):
    if loop is None:
        loop = asyncio.get_event_loop()

    reader, writer = yield from asyncio.open_connection('127.0.0.1',
                                                        conn_port, loop=loop)

    addr = writer.get_extra_info('peername')
    client = Client(addr)
    msg = client.process()
    while msg:
        writer.write(msg)
        msg = yield from reader.read(max_msg_size)
        if msg :
            msg = client.process(msg)
        else:
            break
    writer.write(b'\n')
    writer.close()


def run_client():
    loop = asyncio.get_event_loop()
    loop.run_until_complete(tcp_echo_client())


run_client()
