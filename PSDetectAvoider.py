import sys
import socket
import signal #To kill the programs nicely
import time
from random import shuffle

PORTSTOCHECK = 65535
numberOpen = 0


if len(sys.argv) < 2 or len(sys.argv) > 2:
	print "Invalid Arguments"
	quit()

host = sys.argv[1]
IP = socket.gethostbyname(host)

openPorts={}

ports = [i for i in range(PORTSTOCHECK)]
shuffle(ports)

start = time.clock()

for port in ports:
	try:
		checkSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		checkSocket.connect((IP,port))
		try:
			service = socket.getservbyport(port)
			openPorts[port]=service
			#print "Port " + str(port) + ' Is Open. Service: ' + service
			checkSocket.shutdown(socket.SHUT_RDWR)
		except:
			#print "Port " + str(port) + ' Is Open. Service: Unknown'
			openPorts[port]="Unknown"
			checkSocket.shutdown(socket.SHUT_RDWR)
		numberOpen+=1
		checkSocket.close()
	except socket.error:
		checkSocket.close()
		
end = time.clock()

for port in range(1, PORTSTOCHECK):
	if port in openPorts:
		print "Port " + str(port) + ' Is Open. Service: ' + openPorts[port]

timeElapsed = end-start;
print "Scan took " + str(timeElapsed) + " seconds"
print str(numberOpen) + " Ports Open"
scanRate = PORTSTOCHECK/timeElapsed
print "Scan Rate: " + str(scanRate) + " Ports/Second"