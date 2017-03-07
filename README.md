# COMS 4180 Group 7
## Installation/User Guide

### Installation

#### Creating and setting up certificates:
We have included some premade client and server keys/certificates in the auth folder, but you can also generate your own.

The following instructions specify how to generate the client's private and public keys and certificate. To generate these for the server, replace ``client`` with ``server``.
- ``openssl genrsa -out client.key 2048``: Generates the client's private key
- ``openssl req -new -key client.key -out client.csr``: Generates a certificate request for the client. Follow the prompts.
- ``openssl x509 -req -sha256 -days 365 -in client.csr -signkey client.key -out client.crt``: Client self-signs the requested certificate
- ``openssl x509 -pubkey -noout < client.crt > clientpubkey.pem``: Extracts the client's public key from the certificate. Necessary for PyCrypto
- ``rm *.csr``: Removes the now-unnecessary certificate request.

Note: The commands above do not set up a password for encrypting the RSA keys.

Reference: https://devcenter.heroku.com/articles/ssl-certificate-self

### Environment Setting
In order to establish the connection with the server on Google VM, specific firewall rules need to be added for allowing the tcp port connection.The process is set as follow:
- Choose "Compute Engine" in the VM
- Choose "Networking" option
- Choose Firewall rules, click create new firewall rule 
- In Allowed protocols and ports blank, enter "tcp" for all tcp port or tcp:xxxx for specific xxxx port
- Set the IP range for this rule
- Save

From a fresh Ubuntu 16.04 VM on GCP:</br>
Install pip by running - ``$ sudo apt-get install python-pip``</br>
Then install the pycrypto package with - ``$ pip install pycrypto``

### Run
Quick Run: Run one of the Makefile test command pairs (``make c1`` and ``make s1``, ``make c2`` and ``make s2``, etc.)

Alternatively:
``python client.py <server's IP or hostname> <server port> <client certificate filename> <client private key filename> <server certificate filename> <client public key filename>``

``python server.py <server port> <server certificate filename> <server private key filename> <client certificate filename>``

where 
- ``<server port>`` is a port number in the inclusive range [1024, 65535] to listen on
- ``<server certificate filename>`` is the server's certificate file (for example, auth/server.crt)
- ``<server private key filename>`` is the server's RSA private key file (for example, auth/server.key)
- ``<client certificate filename>`` is the client's certificate file (for example, auth/client.crt)
- ``<client private key filename>`` is the client's RSA private key file (for example, auth/client.key)
- ``<client public key filename>`` is the client's RSA public key file (for example, auth/clientpubkey.key)

The program then behaves as specified in the project instructions.
