#usr/bin/env python2
# -*- coding: utf-8 -*-

# COMS W4180 - Group 7

# General
import sys, os, json
import helpers
import base64

# Sockets, TLS/SSL
import socket, ssl
import struct

# Cryptography
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto import Random
import random

"""
Protocol: 
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

if(len(sys.argv) != 7):
    print "Usage: python client.py <server's IP or hostname> <server port> <client certificate file path> " \
        "<client private key file path> <server certificate file path> <client public key file path>"
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

# Check client private key filename, load private key
if (not os.path.isfile(sys.argv[4])):
    print "File " + sys.argv[4] + " does not exist"
    exit()
ckey_fn = sys.argv[4]
try:
	ckey_f = open(ckey_fn, 'rb')
	ckey = RSA.importKey(ckey_f.read())
except Exception as e:
	print "Could not import client's RSA private key in file " + ckey_fn
	exit()
finally:
	ckey_f.close()

# Check server certificate filename
if (not os.path.isfile(sys.argv[5])):
    print "File " + sys.argv[5] + " does not exist"
    exit()
scert_fn = sys.argv[5]

# Check client's extracted public key filename
if (not os.path.isfile(sys.argv[6])):
    print "File " + sys.argv[6] + " does not exist"
    exit()
cpubkey_fn = sys.argv[6]
try:
	cpubkey_f = open(cpubkey_fn, 'rb')
	cpubkey = RSA.importKey(cpubkey_f.read())
except Exception as e:
	print "Could not import client's RSA public key in file " + cpubkey_fn
	exit()
finally:
	cpubkey_f.close()

################################################################################
# AES Encryption
################################################################################
def generateAesKey(pw):
	if (len(pw) != 8):
		return 0
	random.seed(pw)

	return struct.pack('>I', random.getrandbits(32)) + struct.pack('>I', random.getrandbits(32)) + struct.pack('>I', random.getrandbits(32)) + struct.pack('>I', random.getrandbits(32))

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
	read_contents = None
	if (os.path.isfile(filename)):
		try:
			f = open(filename, option)
			read_contents = f.read()
		except IOError as e:
			print "File " + filename + " could not be transferred"
		finally:
			try:
				f #check that f exists
				f.close()
			except NameError:
				return None

	else:
		print "File " + filename + " could not be transferred"
	return read_contents

def writeFileSafe(filename, write_contents, option='wb'):
	f = open(filename, option)
	success = 0
	try:
		f.write(write_contents)
		success = 1
	except IOError as e:
		print "Could not write file " + filename
	finally:
		f.close()
		return success

################################################################################
# Hashing & Signing
################################################################################
def sha256Hash(text):
	hasher = SHA256.new()
	hasher.update(text)
	file_hash = hasher.digest()
	return file_hash

################################################################################
# Application actions
################################################################################
def put(option, ssl_sock, filename, aes_key=""):
	#check if the filename's last 7 characters equals '.sha256'. if so, disallow it, because
	#we don't want to allow the client to overwrite our .sha256 files on the server side
	if filename[-7:] == '.sha256':
		print 'You are not allowed to put a file whose filename ends in .sha256 on the server, because that file extension is reserved.'
		return

	# Open and read file
	plaintext = readFileSafe(filename, 'rb')
	if (plaintext == None):
		return

	if (option == "E"):
		# AES encryption
		text = encryptAesCbc(aes_key, plaintext)
	else:	# option == N
		text = plaintext

	# Hash the plaintext file
	plaintext_hash = sha256Hash(plaintext)

	# Signature - encrypt the hash with client's RSA private key
	signature = ckey.sign(plaintext_hash, '')

	# Serialize data into client_to_server json and send to server
	ctos_json = json.dumps({
		"action": "put",
		"filename": filename,
		"text": text.encode('base64'),
		"signature": signature
		})
	helpers.send_message(ssl_sock, ctos_json) # helper function

	# get server_to_client message from server
	stoc_json = helpers.recv_message(ssl_sock)
	if (stoc_json == None):
		print "Error: Connection to server lost. Exiting"
		exit()
	stoc = json.loads(stoc_json)
	if (stoc["status"] == "success"):
		print "transfer of " + filename + " complete"
	else:
		print "Error: " + filename + " could not be transferred"

def get(option, ssl_sock, filename, aes_key=""):
	# Send a client_to_server request to the server asking for file
	ctos_json = json.dumps({
		"action": "get",
		"filename": filename,
		"text": None,
		"signature": None
		})
	helpers.send_message(ssl_sock, ctos_json)

	# Receive file and corresponding hash in server_to_client json from server
	stoc_json = helpers.recv_message(ssl_sock)
	if (stoc_json == None):
		print "Error: Connection to server lost. Exiting"
		exit()
	stoc = json.loads(stoc_json)
	if (stoc["status"] != "success"):
		print "Error: " + filename + " was not retrieved."
		return

	binaryText = stoc["text"].decode('base64')

	# Option-specific
	if (option == "E"):
		# AES encryption
		try:
			plaintext = decryptAesCbc(aes_key, binaryText)
		except ValueError as e:
			#from the assignment specs:
			# "If the client attempts to decrypt a file that was not encrypted (detected because the call to AES-CBC will 
			# return an error message), no file will be written and the client will display a message indicating decryption 
			# failed then display the prompt again."
			print "Error: " + filename + " was not retrieved. It's possible that you tried to 'get E' a file that you put on the server without encryption, with 'put N'"
			return 
	else:	# option == N
		plaintext = binaryText
		
	# Compute the sha256 hash of the plaintext file
	plaintext_hash = sha256Hash(plaintext)

	# Use client's public key to decrypt the hash and compare the computed hash to the received hash
	#cpubkey = extractPubKeyFromCert(ccert_fn)
	# print "signature is of type: " + str(type(stoc["signature"]))
	if (cpubkey.verify(plaintext_hash, stoc["signature"])==1):
		f = open(filename, 'wb')
		f.write(plaintext)
		f.close()
		print "retrieval of " + filename + " complete"
	else:
		if (option == "N"):
			print "Error: Computed hash of " + filename + " does not match retrieved hash."
		elif (option == "E"):
			print "Error: Computed hash of " + filename + " does not match retrieved hash. Decryption failed. Are you sure file was encrypted?"


################################################################################
# Main
################################################################################
def main():

	# Connect to server
	sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	
	try:
		ssl_sock = ssl.wrap_socket(sock, certfile=ccert_fn, keyfile=ckey_fn, ca_certs=scert_fn, cert_reqs=ssl.CERT_REQUIRED)
		ssl_sock.connect((server_ip, server_port))
	except ssl.SSLError as ssl_e:
		print "Error: Could not perform mutual authentication; at least one of the following is invalid: server certificate, server private key, client certificate"
		exit()
	except Exception as e:
		print "Error: Could not connect to server " + server_ip + " on port " + str(server_port) + ". Are you sure the server is running?"
		exit()

	# Command-line application
	try:
		while (ssl_sock):
			action_string = raw_input("> ").split(' ')
			action = action_string[0]

			# stop
			if (action == "stop" and len(action_string) == 1):
				ssl_sock.close()
				exit(0)

			if (len(action_string) == 3 or len(action_string) == 4):
				filename = os.path.abspath(action_string[1])
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
						put("E", ssl_sock, filename, aes_key)
					elif (encrypt_option == "N"):
						put("N", ssl_sock, filename)
					else:
						print "Invalid parameter \"" + encrypt_option +"\""
				# get
				elif (action == "get"):
					if (encrypt_option == "E"):
						get("E", ssl_sock, filename, aes_key)
					elif (encrypt_option == "N"):
						get("N", ssl_sock, filename)
					else:
						print "Invalid parameter \"" + encrypt_option +"\""
				else: 
					print "Usage:\n1. <put/get> <filename> <E/N> <password (if E mode)>\n2. <stop>"
			else:
				print "Usage:\n1. <put/get> <filename> <E/N> <password (if E mode)>\n2. <stop>"
	except KeyboardInterrupt:
		print "\nExiting client application."
		ssl_sock.close()

if __name__ == "__main__":
	main()
