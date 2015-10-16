import socket
import sys
from scapy.all import *
from Crypto.Cipher import AES
from Crypto import Random

def usage():
    if len(sys.argv) != 2:
        print "To use: ", sys.argv[0], "[Server IP] [Server Port]"
        sys.exit()

def sendCommand():

	#key to authenticating the packet
	authPacket = "Authenticate packets"
	#Encryption and decryption variables and initialization
	secretKey = "Secret key lost."
	saltySpatoon = "How tough areyou"
	crypt = AES.new(secretKey, AES.MODE_CFB, saltySpatoon)

	while True:
		command = raw_input('Write your command: ')

		encryptedCommand = crypt.encrypt(authPacket + command)

		# decryptedData = crypt.decrypt(data)

		# if decryptedData.startswith(authPacket) == True:
		# 	newData = decryptedData[20:]
		# 	#Print the output
		# 	if newData == "exit":
		# 		sys.exit()
		# 	else:
		# 		print newData



		pkt = IP(src="127.0.0.1", dst="127.0.0.1")/TCP(sport=5000, dport=80, flags="C")/Raw(load=encryptedCommand)

		send(pkt)

sendCommand()








# #Connection Variables
# #Will change to commandline arguments
# HOST = "127.0.0.1"
# PORT = 8509

# #Open socket and connect to server
# s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# s.connect((HOST, PORT))

# while True:
# 	#User command input to be sent tot he server
# 	command = raw_input('Write your command: ')
# 	#Encrypt the command as well as the packet authenticator
# 	encryptedCommand = crypt.encrypt(authPacket + command)
# 	#Send encrypted command to the server
# 	s.sendall(encryptedCommand)
# 	#Receive the data from the server
# 	data = s.recv(10240)
# 	#Decrypt the data from the server
# 	decryptedData = crypt.decrypt(data)
# 	if decryptedData.startswith(authPacket) == True:
# 		newData = decryptedData[20:]
# 		#Print the output
# 		if newData == "exit":
# 			sys.exit()
# 		else:
# 			print newData
