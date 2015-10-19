# Backdoor
Before running any of the programs, you will need to install the following external libraries on both machines:
########################
pip install pycrypto
pip install setproctitle
pip install scapy
########################
To run the backdoor (server.py):
python server.py [Server Port] [Client Port]
########################
To run the attacker (client.py):
python client.py [Server IP] [Server Port] [Client Port]
