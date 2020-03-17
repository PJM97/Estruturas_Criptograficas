# Código baseado em https://docs.python.org/3.6/library/asyncio-stream.html#tcp-echo-client-using-streams
import asyncio
from aes import *

clientes={}

conn_cnt = 0
conn_port = 8888
max_msg_size = 9999

class ServerWorker(object):
    """ Classe que implementa a funcionalidade do SERVIDOR. """
    def __init__(self, cnt, addr=None):
        """ Construtor da classe. """
        self.id = cnt
        self.addr = addr
        self.msg_cnt = 0


    def process(self, msg):
        """ Processa uma mensagem (`bytestring`) enviada pelo CLIENTE.
            Retorna a mensagem a transmitir como resposta (`None` para
            finalizar ligação) """

        try: # Se o Servidor já conhece o Cliente
            if(clientes[self.id]):
                self.msg_cnt += 1
                txt = msg
                
                #Para a terminação
                if(len(msg)==0):
                    print("["+self.id+"]")
                else:
                    print('%d : %r' % (self.id,msg))
                    # print('Msg Content: ',decrypt(msg,clientes[self.id]))
                    old_msg = decrypt(msg,clientes[self.id])
                    new_msg = encrypt(old_msg+' [R]',clientes[self.id])
                return new_msg if len(msg)>0 else None
            else:
                print("\nAlgo de Errado Não Está Certo!\n")
                return msg
        except: # Se o Servidor Não conhece o Cliente
            key=genSKey()
            # print("Init Cliente["+str(self.id)+"]: "+msg.decode())
            clientes[self.id]=genSharedSecret(key,bytes2key(msg))
            # print('\nShared Secret: '+str(clientes[self.id]))
            return key2bytes(genPKey(key))


#
#
# Funcionalidade Cliente/Servidor
#
# obs: não deverá ser necessário alterar o que se segue
#

@asyncio.coroutine
def handle_echo(reader, writer):
    global conn_cnt
    conn_cnt +=1
    addr = writer.get_extra_info('peername')
    srvwrk = ServerWorker(conn_cnt, addr)
    data = yield from reader.read(max_msg_size)
    while True:
        if not data: continue
        if data[:1]==b'\n': break
        data = srvwrk.process(data)
        if not data: break
        writer.write(data)
        yield from writer.drain()
        data = yield from reader.read(max_msg_size)
    print("[%d]" % srvwrk.id)
    writer.close()


def run_server():
    loop = asyncio.get_event_loop()
    coro = asyncio.start_server(handle_echo, '127.0.0.1', conn_port, loop=loop)
    server = loop.run_until_complete(coro)
    # Serve requests until Ctrl+C is pressed
    print('Serving on {}'.format(server.sockets[0].getsockname()))
    print('  (type ^C to finish)\n')
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass
    # Close the server
    server.close()
    loop.run_until_complete(server.wait_closed())
    loop.close()
    print('\nFINISHED!')


run_server()
