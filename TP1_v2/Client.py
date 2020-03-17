# Código baseado em https://docs.python.org/3.6/library/asyncio-stream.html#tcp-echo-client-using-streams
import asyncio
import socket
import os
from aes import *

conn_port = 8888
max_msg_size = 9999

key=genSKey()

class Client:
    """ Classe que implementa a funcionalidade de um CLIENTE. """
    def __init__(self, sckt=None):
        """ Construtor da classe. """
        self.sckt = sckt
        self.msg_cnt = 0


    def process(self, msg=b""):
        """ Processa uma mensagem (`bytestring`) enviada pelo SERVIDOR.
            Retorna a mensagem a transmitir como resposta (`None` para
            finalizar ligação) """
        global key

        if(self.msg_cnt>0):
            if(len(msg)>0 and self.msg_cnt>1):
                print('Received (%d): %r' % (self.msg_cnt -1 , decrypt(msg,key)))
            if(self.msg_cnt==1):
                # print('Recebi: '+msg.decode())
                key=genSharedSecret(key,bytes2key(msg))
                # print('\nShared Secret: '+str(key))
            
            self.msg_cnt +=1
            print('Input message to send (empty to finish)')
            new_msg = str(input())
            ct = encrypt(new_msg,key)
            return ct if len(new_msg)>0 else None
        else:
            self.msg_cnt+=1
            return key2bytes(genPKey(key))

#
#
# Funcionalidade Cliente/Servidor
#
# obs: não deverá ser necessário alterar o que se segue
#

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
    print('Socket closed!')
    writer.close()


def run_client():
    loop = asyncio.get_event_loop()
    loop.run_until_complete(tcp_echo_client())


run_client()
