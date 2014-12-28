import sys
import argparse
import socket
import select
import logging
import signal #To kill the programs nicely
import hashlib
from Crypto.Cipher import AES
from Crypto.Hash import HMAC
from Crypto.Hash import SHA
from Crypto import Random
from Crypto.Random import random
import random

############
#GLOBAL VARS
DEFAULT_PORT = 9999
s = None
server_s = None
logger = logging.getLogger('main')
BLOCK = 16
PADDING = '{'
IV = Random.new().read(BLOCK)
mode = AES.MODE_CBC
first_message = True
###########

def parse_arguments():
  parser = argparse.ArgumentParser(description = 'A P2P IM service.')
  parser.add_argument('-c', dest='connect', metavar='HOSTNAME', type=str,
    help = 'Host to connect to')
  parser.add_argument('-s', dest='server', action='store_true',
    help = 'Run as server (on port 9999)')
  parser.add_argument('-p', dest='port', metavar='PORT', type=int, 
    default = DEFAULT_PORT,
    help = 'For testing purposes - allows use of different port')

  return parser.parse_args()

def print_how_to():
  print "This program must be run with exactly ONE of the following options"
  print "-c <HOSTNAME>  : to connect to <HOSTNAME> on tcp port 9999"
  print "-s             : to run a server listening on tcp port 9999"
	
args = parse_arguments()

if args.connect is None and args.server is False:
    print_how_to()
    quit()

if args.connect is not None and args.server is not False:
    print_how_to()
    quit()

if args.connect is not None:

	#DH variables
    p = (int)("0x00cc81ea8157352a9e9a318aac4e33ffba80fc8da3373fb44895109e4c3ff6cedcc55c02228fccbd551a504feb4346d2aef47053311ceaba95f6c540b967b9409e9f0502e598cfc71327c5a455e2e807bede1e0b7d23fbea054b951ca964eaecae7ba842ba1fc6818c453bf19eb9c5c86e723e69a210d4b72561cab97b3fb3060b",16)
    g = 2
    a = random.randint(0,p)
    A = pow(g,a,p)
    
    #connect to listening server
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((args.connect, 9999))
    
    #right after connecting, send A for DH key establishment
    client.send(str(A))
    #receive B 
    B = long(client.recv(1024))
    K = pow(B,a,p)
    key = hashlib.sha256(str(K)).digest()
    key = key[:16]#key is now 16 bytes
    encryptor=AES.new(key, mode,IV)
    inputs = [client, sys.stdin]

if args.server is not False:

    p = (int)("0x00cc81ea8157352a9e9a318aac4e33ffba80fc8da3373fb44895109e4c3ff6cedcc55c02228fccbd551a504feb4346d2aef47053311ceaba95f6c540b967b9409e9f0502e598cfc71327c5a455e2e807bede1e0b7d23fbea054b951ca964eaecae7ba842ba1fc6818c453bf19eb9c5c86e723e69a210d4b72561cab97b3fb3060b",16)
    g = 2
    a = random.randint(0,p)
    A = pow(g,a,p)
    
    #wait for other side to connect
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('', 9999))
    server.listen(1)
    client,address = server.accept()
    
    client.send(str(A))
    B = long(client.recv(1024))
    K = pow(B,a,p)
    key = hashlib.sha256(str(K)).digest()
    key = key[:16]#key is now 16 bytes
    encryptor=AES.new(key, mode,IV)
    inputs = [client, sys.stdin]


while True:
    #select function gets either command line arguments or messages from other socket
    readable, none, exceptions = select.select(inputs, [], inputs)
    
    for s in readable:
        #if select returns stdin send the message
        if s is sys.stdin:
            full_message=raw_input()
#             while len(full_message)>1000:
#             	message = full_message[:1000]
#             	full_message=full_message[1001:]
#             	mes_len = str(len(message))
#             	padded_mes_len = mes_len + 'x'*(16-len(mes_len) % 16)#pad message length string
#             	padded_message = message + 'x' * (16 - len(message) % 16)#pad message
#             	encrypted_message=encryptor.encrypt(padded_message)#message is encrypted
#             	client.send(IV + padded_mes_len + encrypted_message)
            	
            mes_len = str(len(full_message))
            padded_mes_len = mes_len + 'x'*(16-len(mes_len) % 16)#pad message length string
            padded_message = full_message + 'x' * (16 - len(full_message) % 16)#pad message
            encrypted_message=encryptor.encrypt(padded_message)#message is encrypted
            client.send(IV + padded_mes_len + encrypted_message)

        #else means it's an incoming message and print it
        else:
            data = s.recv(16,socket.MSG_WAITALL)#gets IV
            data2 = s.recv(16,socket.MSG_WAITALL)#gets message length with padding
            if data=="":
                #exit elegantly
                inputs.remove(s)
                s.shutdown(socket.SHUT_RDWR)
                s.close()
                client.close()
            else:
            	message_len = data2.strip('x')#get rid of padding
            	size = int(message_len)+(1024 - int(message_len) % 1024)
            	data3 = s.recv(size)#gets message+padding+mac
                #only the first message needs the IV
                if first_message:
                    IVin = data
                    decryptor=AES.new(key, mode, IVin)#create reusable decryptor
                    first_message = False
                message_len = data2.strip('x')#get rid of padding
                padded_encrypted_message_initial = data3
                padded_encrypted_message = padded_encrypted_message_initial[:(int(message_len)+(16 - int(message_len) % 16))]
                padded_decrypted_message = decryptor.decrypt(padded_encrypted_message)
                decrypted_message = padded_decrypted_message[:int(message_len)]
                print decrypted_message