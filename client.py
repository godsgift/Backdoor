import socket

#Client connects to server
HOST = "127.0.0.1"
PORT = 8505

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((HOST, PORT))

while True:
	command = raw_input('Write your command: ')
	s.sendall(command)

	data = s.recv(10240)

	if data == "quit":
		break
	else:
		print data
