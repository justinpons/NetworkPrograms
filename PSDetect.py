import dpkt, pcap
import socket
import time
import sys

if len(sys.argv) < 2 or len(sys.argv) > 2:
	print "Invalid Arguments. Specify Interface to receive packets"
	quit()

interface = sys.argv[1]

pc = pcap.pcap(name=interface)
scanCount ={}
lastPort={}
start={}
end={}
timeScanned={}
scannerFound={}
#pc.setfilter('tcp portrange 1-35565')#all we need to check is tcp connection and any of the 2^16 ports
for ts, pkt in pc:
		print pkt
		eth = dpkt.ethernet.Ethernet(pkt)
		#all packet data we need
		IPsrc=eth.data.src
		TCPseq=eth.data.data.seq
		TCPdport=eth.data.data.dport
		TCPack=eth.data.data.ack
		
		if TCPseq > 0 and TCPack == 0:#checks if the packet is requesting connection b/c a connection request would have a random seq # and no ack #
			if IPsrc in scanCount:#if we've seen this IP try to connect before
				lastPort[IPsrc]+=1
				if TCPdport == lastPort[IPsrc]  and scannerFound[IPsrc]!=True:#checks if the port this IP address is scanning is the next consecutive port with the previous port it checked
					scanCount[IPsrc]+=1
					timeScanned[scanCount[IPsrc]]= time.clock()
					if scanCount[IPsrc] >=15:#if this IP address has scanned 15 consecutive ports
						end = timeScanned[scanCount[IPsrc]]
						before = scanCount[IPsrc]-14 #get timestamp 15 checks ago
						start = timeScanned[before]
						timetoScan = end-start
						if timetoScan < 5:
							print "Scanner Detected. The scanner originated from host: " + socket.inet_ntoa(IPsrc)
							#scannerFound[IPsrc]=True
							exit()#in class, Prof Sherr said we can exit the program if the program detects a scanner. this seems more elegant to me.
				else:#if the scanner didn't try to connect with consecutive ports, the count for this IP address goes back to 1
					scanCount[IPsrc]=1
					lastPort[IPsrc]=TCPdport
					timeScanned[scanCount[IPsrc]]= time.clock()
		 	else:
		 		scanCount[IPsrc]=1
		 		lastPort[IPsrc] = TCPdport
		 		scannerFound[IPsrc] = False
		 		timeScanned[scanCount[IPsrc]]= time.clock()
		 		