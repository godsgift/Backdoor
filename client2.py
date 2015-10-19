######################################################################
#   Created by: Elton Sia A00800541
#   
#   File: client.py
#
#   Description:
#   Once the client.py is running, it waits for user to type in a 
#   command. It then adds an authentication string at the start and 
#   then encrypts the command using AES encryption algorithm. Once 
#   encryption is done, it is then sent the server. Once it sends to
#   the server, we go into receiving mode and sniff for packets for 3 
#   seconds. Once we receive the packet we decrypt it and check if the
#   packet has the flag set to "C". If it does we then decrypt the data
#   and check if the decrypted data has the authentication string. If 
#   it does, we delete the authentication string and check if the output
#   is an exit command or not. If it is an exit command, we exit the 
#   program, if not then we print the output.
#
#   Functions:
#   usage()
#   stopfilter()
#   encryptCommand()
#   decryptCommand()
#   sendCOmmand()
#   receiveOutput()
######################################################################

import sys
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
#	python client.py [Server IP] [Server Port] [Client Port]
#
#	Example:
#	python client.py 192.168.0.12 8505 8506
######################################################################
def usage():
    if len(sys.argv) != 4:
        print "To use: ", sys.argv[0], "[Server IP] [Server Port] [Client Port]"
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
    #Secret key and Salt initialization
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
    #Secret key and Salt initialization
    secretKey = "Secret key lost."
    saltySpatoon = "How tough areyou"
    #decryption initialization
    crypt = AES.new(secretKey, AES.MODE_CFB, saltySpatoon)
    #decrypt the data
    decryptedData = crypt.decrypt(message)
    return decryptedData

######################################################################
#	Function: sendCommand()
#
#	Description:
#	The function takes in the command line arguments when the program
#	first runs. We store the [Server IP] and [Server Port] into a 
#	variable. We then check if we will be sending a command or 
#	receiving an output from the server. If we are sending, we grab
#	the string the user has inputted and add the authentication
#	packet at the start and then encrypt the whole data. We then 
#	send it to the server. After we send a packet to the server,
#	we go into receiving mode and sniff for TCP packets with the 
#	correct destination port. When we receive the packet we send it to
#	the receiveOutput() function. After sending it to the receiveOutput
#	function, we go back into sending mode and wait for user input for
#	the next command
#	
#	Input:
#	User input for encrypted command to be sent over to the server
#
#	Output:
#	Sends an encrypted command to the server
######################################################################
def sendCommand():
    global destIP
    global authPacket
    #command line arguments 
    destIP = sys.argv[1]
    destPort = sys.argv[2]
    clientPort = sys.argv[3]
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
            pkt = IP(dst=destIP)/TCP(dport=int(destPort), flags='C')/Raw(load=encryptedCommand)
            #Send the packet
            send(pkt)
            sending = False
        else:
            sniff(timeout=2, filter="tcp and host " + destIP + " and dst port " + clientPort, stop_filter=receiveOutput)
            sending = True

######################################################################
#   Function: receiveOutput(pkt)
#
#   Parameter: pkt
#
#   Description:
#   The function takes in the packets sniffed from the sendCommand()
#   function. We first check if it's an ARP packet, and if it is, we
#   do nothing. We then check for DHCP packet and do nothing if we 
#   get it. If the source IP address is the same as the [Server IP]
#   that the user specified, then we check for the flag of the packet.
#   If the flag is "C", we then grab the data and decrypt it. If the
#   data has the authentication string, we take out the authentication
#   string and check whether we receive an "exit" command. If it is an 
#   "exit" command, the program exits, otherwise print the output from
#   the server.
#   
#   Input:
#   Packet received from sniffing for TCP packets with the correct 
#   destination IP address and destination port.
#
#   Output:
#   If we receive exit command, we exit the program, otherwise
#   print the output received from the server
######################################################################
def receiveOutput(pkt):
    global destIP
    global authPacket

    if pkt[IP].src == destIP:
        flagSet = pkt['TCP'].flags
        if flagSet == long(128):
            #grab the raw data
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
    else:
    	return

if __name__ == "__main__":
    usage()
    sendCommand()
