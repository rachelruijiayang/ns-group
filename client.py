#!/usr/bin/env python2
# -*- coding: utf-8 -*-

# COMS W4180 - Group 7

# General
import sys, os, pickle
import helpers

# Sockets, TLS/SSL
import socket, ssl
import tools

# Cryptography
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto import Random
import random
from Crypto.Util.asn1 import DerSequence
from Crypto.PublicKey import RSA
from binascii import a2b_base64

"""
client_to_server:
{
	"action": action,	# put or get
	"filename": filename,
	"text": text,		# either plaintext or IV+ciphertext
	"signature": signature
}

server_to_client:
{
	"action": action,	# put or get
	"status": status,	# server succeeded or failed to put or get file
	"filename": filename,
	"text": text,		# file contents
	"signature": signature	
}
"""

if(len(sys.argv) != 6):
    print "Usage: ./client <server's IP or hostname> <server port> <client certificate filename> " \
        "<client private key filename> <server certificate filename>"
    exit()

# Check server IP/hostname
try:
    server_ip = socket.gethostbyname(sys.argv[1])
except socket.gaierror:
    print "Server IP/hostname could not be resolved"
    exit()

# Check port number
if (not sys.argv[2].isdigit()):
    print "Server port must contain only digits 0-9"
    exit()
server_port = int(sys.argv[2])
if (server_port < 1024 or server_port > 65535):
    print "Port number must be in the inclusive range [1024, 65535]"
    exit()

# Check client certificate filename, load public key
if (not os.path.isfile(sys.argv[3])):
    print "File " + sys.argv[3] + " does not exist"
    exit()
ccert_fn = sys.argv[3]
try:
	ccert_f = open(ccert_fn)
	ccert = RSA.importKey(ccert_f.read())


# Check client private key filename, load private key
if (not os.path.isfile(sys.argv[4])):
    print "File " + sys.argv[4] + " does not exist"
    exit()
ckey_fn = sys.argv[4]
try:
	ckey_f = open(ckey_fn)
	ckey = RSA.importKey(ckey_f.read())
except:
	print "Could not import client's RSA private key in file " + ckey_fn
	exit()
finally:
	ckey_f.close()

# Check server certificate filename
if (not os.path.isfile(sys.argv[5])):
    print "File " + sys.argv[5] + " does not exist"
    exit()
scert_fn = sys.argv[5]

################################################################################
# AES Encryption
################################################################################
def generateAesKey(pw):
	if (len(pw) != 8):
		return 0
	random.seed(pw)
	shift = AES.block_size*8 - 1;
	#num = random.getrandbits(shift) + (1 << shift)
	num = random.randrange(1 << 127, 1 << 128)
	#print "AES BLOCK SIZE: " + str(AES.block_size)
	#print "SIZE OF NUM: " + str(sys.getsizeof(num))
	#return str(random.getrandbits(AES.block_size))
	#return str(num)	# TODO
	return "temporaryaeskey!"

def pad(msg):
	return msg + (AES.block_size - len(msg) % AES.block_size) * chr(AES.block_size - len(msg) % AES.block_size)

def unpad(padded_msg):
	num_padding_bytes = ord(padded_msg[len(padded_msg)-1:])
	return padded_msg[:-num_padding_bytes]

def encryptAesCbc(aes_key, plaintext):
	# Create an IV
	iv = Random.new().read(AES.block_size)

	# Pad file (PKCS standard)
	padded_file = pad(plaintext)

	# Encrypt the file with AES in CBC mode
	cipher = AES.new(aes_key, AES.MODE_CBC, iv)
	ciphertext = cipher.encrypt(padded_file)

	# Prepend the IV to the ciphertext
	iv_ciphertext = iv + ciphertext

	return iv_ciphertext

def decryptAesCbc(aes_key, iv_ciphertext):
	# Separate the IV from the ciphertext
	iv = iv_ciphertext[:16]
	ciphertext = iv_ciphertext[16:]

	# Decrypt the file using IV
	cipher = AES.new(aes_key, AES.MODE_CBC, iv)
	padded_plaintext = cipher.decrypt(ciphertext)
	
	# Unpad the file
	plaintext = unpad(padded_plaintext)

	return plaintext

################################################################################
# File Handling
################################################################################
def readFileSafe(filename, option='rb'):
	f = open(filename, option)
	read_contents = None
	try:
		read_contents = f.read()
	except:
		print "Could not read file " + filename
	finally:
		f.close()
		return read_contents

def writeFileSafe(filename, write_contents, option='wb'):
	f = open(filename, option)
	success = 0
	try:
		f.write(write_contents)
		success = 1
	except:
		print "Could not write file " + filename
	finally:
		f.close()
		return success

################################################################################
# Hashing
################################################################################
def sha256Hash(text):
	hasher = SHA256.new()
	hasher.update(text)
	file_hash = hasher.digest()
	return file_hash

def extractPubKeyFromCert(cert_fn):
	# Convert from PEM to DER
	f = open(cert_fn)
	pem = f.read()
	f.close()
	lines = pem.replace(" ",'').split()
	der = a2b_base64(''.join(lines[1:-1]))

	# Extract subjectPublicKeyInfo field from X.509 certificate (see RFC3280)
	cert = DerSequence()
	cert.decode(der)
	tbsCertificate = DerSequence()
	tbsCertificate.decode(cert[0])
	subjectPublicKeyInfo = tbsCertificate[6]

	# Initialize RSA key
	pubkey = RSA.importKey(subjectPublicKeyInfo)

	return pubkey

################################################################################
# Application actions
################################################################################
def putE(ssl_sock, filename, aes_key):

	# Open and read file
	plaintext = readFileSafe(filename, 'rb')
	if (plaintext == None):
		return

	# AES encryption
	iv_ciphertext = encryptAesCbc(aes_key, plaintext)

	# Hash the plaintext file
	file_hash = sha256Hash(plaintext)

	# Signature - encrypt the hash with client's RSA private key
	signature = ckey.sign(file_hash, '')

	# Serialize data and send to server
	ctos = pickle.dumps({
		"action": "put"
		"filename": filename,
		"text": iv_ciphertext,
		"signature": signature
		})
	
	# ssl_sock.send(ctos) # helper function

	# get stoc from server
	print "transfer of " + filename + " complete"

"""
def getE(ssl_sock, filename, aes_key):
	
	# Send a request to the server asking for the file
	pickled_string = pickle.dumps({
		"action": "get"
		"filename": filename,
		"text": None,
		"signature": None
		})
	# ssl_sock.send(pickled_string) # helper function

	# Receive file and corresponding hash from server
	# data = server.recv()	# Blocks until data is received # helper function
	
	stoc = pickle.loads(res)

	stoc_status = stoc["status"]
	stoc_text = stoc["text"]
	stoc_signature = stoc["signature"]

	# Decrypt the file
	plaintext = decryptAesCbc(aes_key, stoc_text)

	# Use client's public key to unencrypt the hash

	# Compute the sha256 hash of the plaintext file
	hasher = SHA256.new()
	hasher.update(plaintext)
	computed_hash = hasher.digest()

	# Compare the computed hash to the received hash
	if (computed_hash == recv_hash):
		# If the hash matches, client writes the file to the current directory
		f = open(filename, 'wb')
		f.write(plaintext)
		f.close()
		print "retrieval of " + filename + " complete"

	else:
		# If the hash does not match, client displays a message to the user before 
		# displaying the prompt again
		print "Error: Computed hash of " + recv_filename + " does not match received hash"

def putN(ssl_sock, filename):
	# Open and read file
	f = open(filename, 'rb')
	plaintext = f.read()
	f.close()

	# Hash the file
	hasher = SHA256.new()
	hasher.update(plaintext)
	file_hash = hasher.digest()

	# Signature - encrypt the hash with client's RSA private key
	ckey_f = open(ckey_fn)
	ckey = RSA.importKey(ckey_f.read())
	ckey_f.close()
	signature = ckey.sign(file_hash, '')

	# Serialize data and send to server
	pickled_string = pickle.dumps({
		"action": "put"
		"mode": "N",
		"filename": filename,
		"plaintext": plaintext, 
		"iv": None,
		"ciphertext": None,
		"signature": signature
		})
	ssl_sock.send(pickled_string)
	
	print "transfer of " + filename + " complete"

def getN(ssl_sock, filename):
	# Send a request to the server asking for the file
	pickled_string = pickle.dumps({
		"action": "get"
		"mode": "E",
		"filename": filename,
		"plaintext": None, 
		"iv": None,
		"ciphertext": None,
		"signature": None
		})
	ssl_sock.send(pickled_string)

	# Receive file and corresponding hash from server
	data = server.recv()	# Blocks until data is received
	file_and_hash = pickle.loads(res)

	filename = file_and_hash["filename"]
	recv_text = file_and_hash["file"]
	recv_hash = file_and_hash["hash"]

	# Compute the sha256 hash of the plaintext file
	hasher = SHA256.new()
	hasher.update(plaintext)
	computed_hash = hasher.digest()

	# Compare the computed hash to the received hash
	if (computed_hash == recv_hash):
		# If the hash matches, client writes the file to the current directory
		f = open(filename, 'wb')
		f.write(plaintext)
		f.close()
		print "retrieval of " + filename + " complete"

	else:
		# If the hash does not match, client displays a message to the user before 
		# displaying the prompt again
		print "Error: Computed hash of " + filename + " does not match received hash"
"""


################################################################################
# Main
################################################################################
def main():

	# Connect to server
	sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	ssl_sock = ssl.wrap_socket(sock, certfile=ccert_fn, keyfile=ckey_fn, ca_certs=scert_fn, cert_reqs=ssl.CERT_REQUIRED)
	ssl_sock.connect((server_ip, server_port))

	# Command-line application
	while (ssl_sock):
		action_string = raw_input("> ").split(' ')
		action = action_string[0]

		# stop
		if (action == "stop" and len(action_string) == 1):
			ssl_sock.close()
			exit(0)

		filename = action_string[1]
		encrypt_option = action_string[2]

		# E option
		if (encrypt_option == "E"):
			if (len(action_string) != 4):
				print "Error: Missing parameters, \"E\" requires a password"
				continue
			aes_key = generateAesKey(action_string[3])
			if (aes_key == 0):
				print "Error: E mode password must be eight characters"
				continue

		# put
		if (action == "put"):
			if (encrypt_option == "E"):
				putE(ssl_sock, filename, aes_key)
			elif (encrypt_option == "N"):
				putN(ssl_sock, filename)
			else:
				print "Invalid parameter \"" + encrypt_option +"\""
		# get
		elif (action == "get"):
			if (encrypt_option == "E"):
				getE(ssl_sock, filename, aes_key)
			elif (encrypt_option == "N"):
				getN(ssl_sock, filename)
			else:
				print "Invalid parameter \"" + encrypt_option +"\""
		else:
			print "Invalid commands, options are \"get\" \"put\" \"stop\""

if __name__ == "__main__":
	main()
