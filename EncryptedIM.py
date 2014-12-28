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
  parser.add_argument('-confkey', dest='conf', metavar='CONFIDENTIALITY', type=str,
    help = 'Key for Encryption')
  parser.add_argument('-authkey ', dest='auth', metavar='AUTHENTICITY', type=str,
    help = 'Key for HMAC')
  parser.add_argument('-p', dest='port', metavar='PORT', type=int, 
    default = DEFAULT_PORT,
    help = 'For testing purposes - allows use of different port')

  return parser.parse_args()

def print_how_to():
  print "This program must be run with exactly ONE of the following options"
  print "-c <HOSTNAME>  : to connect to <HOSTNAME> on tcp port 9999"
  print "-s             : to run a server listening on tcp port 9999"
  print "-confkey <K1>  :Key 1"
  print "-authkey <K2>  :Key 2"

args = parse_arguments()

if args.connect is None and args.server is False:
    print_how_to()
    quit()

if args.connect is not None and args.server is not False:
    print_how_to()
    quit()
    
if args.conf is None:
    print_how_to()
    quit()
if args.auth is None:
    print_how_to()
    quit()

if args.connect is not None:
    #first passwords are saved and hashed into keys
    password1=args.conf
    password2=args.auth
    key1 = hashlib.sha256(password1).digest()
    key1 =key1[:16]#key1 is now 16 bytes
    key2 = hashlib.sha256(password2).digest()
    key2 =key2[:16]#key2 is now 16 bytes
    #encryptor for all sent messages
    encryptor=AES.new(key1, mode,IV)
    #connect to listening server
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((args.connect, 9999))
    inputs = [client, sys.stdin]

if args.server is not False:
    #first passwords are saved and hashed into keys
    password1=args.conf
    password2=args.auth
    key1 = hashlib.sha256(password1).digest()
    key1 =key1[:16]#key is now 16 bytes
    key2 = hashlib.sha256(password2).digest()
    key2 =key2[:16]#key2 is now 16 bytes
    #Encryptor used for all messages sent
    encryptor=AES.new(key1, mode, IV)

    #wait for other side to connect
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('', 9999))
    server.listen(1)
    client,address = server.accept()
    inputs = [client, sys.stdin]


while True:
    #select function gets either command line arguments or messages from other socket
    readable, none, exceptions = select.select(inputs, [], inputs)
    
    for s in readable:
        #if select returns stdin send the message
        if s is sys.stdin:
            message=raw_input()
            mes_len = str(len(message))
            padded_mes_len = mes_len + 'x'*(16-len(mes_len) % 16)#pad message length string
            padded_message = message + 'x' * (16 - len(message) % 16)#pad message
            encrypted_message=encryptor.encrypt(padded_message)#message is encrypted
            mac=HMAC.new(key2,message).digest()#create HMAC
            #send in order IV->message length->message->HMAC
            client.send(IV + padded_mes_len + encrypted_message + mac)
        #else means it's an incoming message and print it
        else:
            data = s.recv(16,socket.MSG_WAITALL)#gets IV
            data2 = s.recv(16,socket.MSG_WAITALL)#gets message length with padding
            data3 = s.recv(1024)#gets message+padding+mac
            if data=="":
                #exit elegantly
                inputs.remove(s)
                s.shutdown(socket.SHUT_RDWR)
                s.close()
                client.close()
            else:
                #only the first message needs the IV
                if first_message:
                    IVin = data
                    decryptor=AES.new(key1, mode, IVin)#create reusable decryptor
                    first_message = False
                message_len = data2.strip('x')#get rid of padding
                padded_encrypted_message_with_mac = data3
                padded_encrypted_message = padded_encrypted_message_with_mac[:(int(message_len)+(16 - int(message_len) % 16))]
                inHMAC = padded_encrypted_message_with_mac[int(message_len)+ ((16 - int(message_len) % 16)):]
                padded_decrypted_message = decryptor.decrypt(padded_encrypted_message)
                decrypted_message = padded_decrypted_message[:int(message_len)]
                checkHMAC = HMAC.new(key2,decrypted_message).digest()
                if inHMAC==checkHMAC:
                    print decrypted_message
                else:
                    print "HMAC unidentified. Ending session."
                    inputs.remove(s)
                    s.shutdown(socket.SHUT_RDWR)
                    s.close()
                    client.close()
                    quit()
        
