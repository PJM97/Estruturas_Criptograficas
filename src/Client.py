import asyncio,socket,os,sys
from cypher import *

conn_port = 8888

def process():

    print('Introduza a password')
    pswd = input().encode('UTF-8')
    
    print('Escreva Mensagem')
    ptxt = input().encode('UTF-8')

    pacote = pack(pswd,ptxt)

    # print(type(pacote),len(pacote),pacote)
    return pacote

@asyncio.coroutine
def tcp_echo_client(loop=None):
    loop = asyncio.get_event_loop()
    writer = (yield from asyncio.open_connection(
        '127.0.0.1',conn_port, loop=loop))[1]
    writer.write(process())
    writer.close()

def run_client():
    loop = asyncio.get_event_loop()
    loop.run_until_complete(tcp_echo_client())

run_client()
