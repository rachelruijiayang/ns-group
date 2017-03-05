#!/usr/bin/env python2
# -*- coding: utf-8 -*-

# COMS W4180 - Group 7

# General
import sys, os, pickle

# Sockets, TLS/SSL
import socket, ssl
import tools

# Cryptography
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto import Random
import random

BUF_SIZE = 1024

"""
Format of pickled string:
pickled_string = pickle.dumps({
	"filename": filename,
	"mode": mode,
	"plaintext": plaintext, 
	"iv": iv,
	"ciphertext": ciphertext,
	"signature": signature
})
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

# Check client certificate filename
if (not os.path.isfile(sys.argv[3])):
    print "File " + sys.argv[3] + " does not exist"
    exit()
ccert_fn = sys.argv[3]

# Check client private key filename
if (not os.path.isfile(sys.argv[4])):
    print "File " + sys.argv[4] + " does not exist"
    exit()
ckey_fn = sys.argv[4]

# Check server certificate filename
if (not os.path.isfile(sys.argv[5])):
    print "File " + sys.argv[5] + " does not exist"
    exit()
scert_fn = sys.argv[5]

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

def putE(ssl_sock, filename, aes_key):
	# Create an IV
	iv = Random.new().read(AES.block_size)

	# Prepare/pad the file
	f = open(filename, 'rb')
	plaintext = f.read()
	f.close()
	padded_file = pad(plaintext)

	# Encrypt the file with AES in CBC mode
	cipher = AES.new(aes_key, AES.MODE_CBC, iv)
	ciphertext = cipher.encrypt(padded_file)

	# Hash the file
	hasher = SHA256.new()
	hasher.update(plaintext)
	file_hash = hasher.digest()

	# Encrypt the hash with client's RSA private key
	ckey_f = open(ckey_fn)
	ckey = RSA.importKey(ckey_f.read())
	ckey_f.close()
	signature = ckey.sign(file_hash, '')

	# Serialize data and send to server
	pickled_string = pickle.dumps({
		"filename": filename,
		"mode": "E",
		"plaintext": None, 
		"iv": iv,
		"ciphertext": ciphertext,
		"signature": signature
		})
	ssl_sock.send(pickled_string)

def getE(ssl_sock, filename, aes_key):
	pass

def putN(ssl_sock, filename):
	f = open(filename, 'rb')
	plaintext = f.read()
	f.close()
	pickled_string = pickle.dumps({
		"filename": filename,
		"mode": "N",
		"plaintext": plaintext, 
		"iv": None,
		"ciphertext": None,
		"signature": None
		})
	ssl_sock.send(pickled_string)

def getN(ssl_sock, filename):
	pass

def main():

	################################################################################
	# Connect to server
	################################################################################
	sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	ssl_sock = ssl.wrap_socket(sock, certfile=ccert_fn, keyfile=ckey_fn, ca_certs=scert_fn, cert_reqs=ssl.CERT_REQUIRED)
	ssl_sock.connect((server_ip, server_port))

	################################################################################
	# Command-line application
	################################################################################
	while (ssl_sock):	# While server is alive?
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
