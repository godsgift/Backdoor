import socket
import sys
from Crypto.Cipher import AES
from Crypto import Random

#Client connects to server
HOST = "127.0.0.1"
PORT = 8505

#Encryption and decryption variables and initialization
secretKey = "Secret key lost."
saltySpatoon = "How tough areyou"
crypt = AES.new(secretKey, AES.MODE_CFB, saltySpatoon)

#Open socket and connect to server
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((HOST, PORT))

while True:
	#User command input to be sent tot he server
	command = raw_input('Write your command: ')
	#Encrypt the string before sending it to the server
	encryptedCommand = crypt.encrypt(command)
	#Send encrypted command to the server
	s.sendall(encryptedCommand)
	#Receive the data from the server
	data = s.recv(10240)
	#Decrypt the data from the server
	decryptedData = crypt.decrypt(data)

	#Print the output
	if data == "exit":
		sys.exit()
	else:
		print decryptedData
