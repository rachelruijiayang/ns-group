# COMS 4180 Group 7
Jianpu Ma (jm4437)
Kevin Liu (kll2146)
Ilan Buchwald (ib2348)
Ruijia Yang (ry2277)

## Installation/User Guide

### Installation

#### Creating and setting up certificates:
We have included some premade client and server keys/certificates in the auth folder, but you can also generate your own in a directory of your choosing.

The following instructions specify how to generate the client's private and public keys and certificate. To generate these for the server, replace ``client`` with ``server``.
- ``openssl genrsa -out client.key 2048``: Generates the client's private key
- ``openssl req -new -key client.key -out client.csr``: Generates a certificate request for the client. Follow the prompts.
- ``openssl x509 -req -sha256 -days 365 -in client.csr -signkey client.key -out client.crt``: Client self-signs the requested certificate
- ``openssl x509 -pubkey -noout < client.crt > clientpubkey.pem``: Extracts the client's public key from the certificate. Necessary for PyCrypto
- ``rm *.csr``: Removes the now-unnecessary certificate request.

Note: The commands above do not set up a password for encrypting the RSA keys.

Reference: https://devcenter.heroku.com/articles/ssl-certificate-self

### Environment Setting
If you are running the server on a Google VM and want to connect with a client that is running somewhere other than the VM that the server is running on, specific firewall rules need to be added to allow the TCP port connection. The process is:
- Go to https://console.cloud.google.com and navigate to your project. On the hamburger menu in the top-left, choose "Networking" under the "Compute" section
- Choose Firewall rules, click create new firewall rule 
- In the "Allowed protocols and ports" field, enter "tcp" to allow all TCP ports, or tcp:xxxx for a specific xxxx port
- Under the "Source filter" dropdown, select "allow from any source" (or, you can instead designate an allowed IP range)
- Give this rule a name in the "Name" field
- Click Create

SSH into your Google Compute Engine VM. If it is a fresh VM (fresh Ubuntu 16.04 VMs will need this step), or if it doesn't have Python's pycrypto library, install it:</br>
- Install pip by running - ``$ sudo apt-get install python-pip``</br>
- Then install the pycrypto package with - ``$ pip install pycrypto``
In particular, client.py uses the pycrypto package, so whatever machine you run the client on, it needs to have pycrypto installed.

### Run
Quick Run: Run one of the Makefile test command pairs (``make c1`` and ``make s1``, ``make c2`` and ``make s2``, etc.)

Alternatively:
``python client.py <server's IP or hostname> <server port> <client certificate file path> <client private key filename> <server certificate filename> <client public key filename>``

``python server.py <server port> <server certificate filename> <server private key filename> <client certificate filename>``

where 
- ``<server port>`` is a port number in the inclusive range [1024, 65535] to listen on
- ``<server certificate filename>`` is the server's certificate file (for example, auth/server.crt)
- ``<server private key filename>`` is the server's RSA private key file (for example, auth/server.key)
- ``<client certificate filename>`` is the client's certificate file (for example, auth/client.crt)
- ``<client private key filename>`` is the client's RSA private key file (for example, auth/client.key)
- ``<client public key filename>`` is the client's RSA public key file (for example, auth/clientpubkey.key)

From here, the program follows the assignment specs.

Note: All files sent by the client will be put into the simulated directory structure under client_files, which is located in the same directory that the server is run in. Clients can specify absolute or relative paths for the files they 'put' or 'get'. Both will be converted into the absolute path. Then, the file the client 'put's or 'get's and its absolute path will be sent to the server, where the file will be located inside the simulated directory structure under client_files/`<`absolute path provided by client`>`. In summary, when a client 'put's or 'get's files, it does so within a simulated directory structuring mirroring the directory structure of its own system.
