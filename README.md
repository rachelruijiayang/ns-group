# COMS 4180 Group 7
## Installation/User Guide

### Installation

### Creating and setting up certificates
Run the following command, replacing \<key_name> and \<cert_name> with the desired names for client and server RSA keys/certificates.
- ``openssl req -x509 -newkey rsa:2048 -keyout <key_name>.pem -out <cert_name>.pem -days 365``
- Answer the prompts given by OpenSSL.

### Environment Setting
In order to establish the connection with the server on the Google VM, specific firewall rules in the Google Cloud Platform need to be modified for allowing the tcp port connection. The process is set as follow:
- Choose "Compute Engine" in the VM
- Choose "Networking" option
- Choose Firewall rules, click create new firewall rule 
- In Allowed protocols and ports blank, enter "tcp" for all tcp port or tcp:xxxx for specific xxxx port
- Set the IP range for this rule
- Save

### Run
Client: Run one of the Makefile test commands (``make c1``, ``make c2``, or ``make c3``)
testserver: python testserver.py (adjust the port used within the code)


### Division of Labor

#### Client
Jianpu
- Skeleton code

Ruijia
- More skeleton code
- Implemented plaintext and encrypted file transfer
