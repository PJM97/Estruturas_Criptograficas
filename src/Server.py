import asyncio
from cypher import *

conn_port = 8888
max_msg_size = 9999
loop = None

def process(pacote):
    print('Introduza a password')
    pswd = input().encode('UTF-8')

    # print("Recebi:",pacote)
    try:
        print("Unpack:",unpack(pswd,pacote))
    except NameError as x:
        print(x)


@asyncio.coroutine
def handle_echo(reader, writer):
    process((yield from reader.read(max_msg_size)))
    loop.stop()

def run_server():
    global loop
    loop = asyncio.get_event_loop()
    coro = asyncio.start_server(
        handle_echo, '127.0.0.1', conn_port, loop=loop)
    server = loop.run_until_complete(coro)
    try:
        loop.run_forever()
    except:
        pass
    server.close()
    loop.run_until_complete(server.wait_closed())
    loop.close()

run_server()
