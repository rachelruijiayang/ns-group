# COMS 4180 Group 7
## Installation/User Guide

### Installation

### Creating and setting up certificates
Run the following command, replacing \<key_name> and \<cert_name> with the desired names for client and server RSA keys/certificates.
- ``openssl req -x509 -newkey rsa:2048 -keyout <key_name>.pem -out <cert_name>.pem -days 365``
- Answer the prompts given by OpenSSL.

### Run

### Division of Labor

#### Client
Jianpu
- Skeleton code & command line file transfer

Ruijia
- Implement plaintext file transfer
