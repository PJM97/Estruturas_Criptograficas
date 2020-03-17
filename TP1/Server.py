import asyncio
from aes import *
from dsa import *

conn_port = 8888
max_msg_size = 9999
loop = None

class ServerWorker(object):
    def __init__(self, cnt, addr=None):
        self.id = cnt
        self.addr = addr
        self.msg_cnt = 0
        self.shared_secret = None
        self.dhS_PK = None
        self.dhC_PK = None
        self.dsaSK = getPrivateKey("keys/ServerSecret.pem") 
        self.dsaClientPK = getPublicKey("keys/ClientPublic.pem")

    def process(self, msg):
        if(self.msg_cnt==0):
            self.msg_cnt += 1
            key=DHgenSKey()
            self.dhS_PK=pKey2bytes(DHgenPKey(key))
            self.dhC_PK=msg
            self.shared_secret=DHgenSharedSecret(key,bytes2pKey(self.dhC_PK))
            print('\nShared Secret: '+str(self.shared_secret))
            sig = sign(self.dsaSK, self.dhC_PK+self.dhS_PK)

            return sig+FS+self.dhS_PK

        if(msg==b' '):
            loop.stop()
            return None
        if(self.msg_cnt==1):
            [sig,ct,mac]=splitter(msg)
        else:
            [ct,mac]=splitter(msg)

        if(self.msg_cnt==1):
            vSig = verify(
                    self.dsaClientPK,
                    self.dhC_PK+self.dhS_PK,
                    sig
                )
            print()
            if(vSig):
                print("> Signature Verification Successful")
            else:
                print("> Failed Signature Verification")
                loop.stop()
                return None

            if(HMAC(ct,self.shared_secret,mac)):
                print("> HMAC Verification Successful")
            else:
                print("> Failed HMAC Verification")
                loop.stop()
                return None
        self.msg_cnt+=1
        old_msg = decrypt(ct,self.shared_secret)
        print("\nReceived:\n",ct,"\n",old_msg)

        return b'ok'
        

@asyncio.coroutine
def handle_echo(reader, writer):

    addr = writer.get_extra_info('peername')
    srvwrk = ServerWorker(0, addr)
    data = yield from reader.read(max_msg_size)
    while True:
        if not data: continue
        if data[:1]==b'\n': break
        data = srvwrk.process(data)
        if not data: break
        writer.write(data)
        yield from writer.drain()
        data = yield from reader.read(max_msg_size)
    writer.close()


def run_server():
    global loop
    loop = asyncio.get_event_loop()
    coro = asyncio.start_server(handle_echo, '127.0.0.1', conn_port, loop=loop)
    server = loop.run_until_complete(coro)
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass
    server.close()
    loop.run_until_complete(server.wait_closed())
    loop.close()

run_server()
