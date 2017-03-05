#authors: kevin liu, ilan buchwald, ruija yang, and jianpu ma
#COMS 4180 group project
#server
#
# Command line arguments:
# -port number on which server will listen for connections
#

from socket import *
import ssl
import pickle
import signal
import sys
import threading
from helpers import *
import os


#====================================================== get command line arguments and validate them

#if you run "python server.py 1555 auth/server.crt auth/server.key auth/client.crt", then sys.argv has 5 arguments: server.py is the 1st, 1555 is the 2nd, auth/server.crt is the 3rd, auth/server.key is the 4th, and auth/client.crt is the 5th
if(len(sys.argv) != 5):
	print "Invalid number of arguments. Invoke the server using: python server.py <port> <server certificate> <server private key> <client certificate>, where <port> is a port number in the inclusive range [1024, 65535], <server certificate> is the server's certificate file (for example, auth/server.crt), <server private key> is the server's RSA private key file (for example, auth/server.key), and <client certificate> is the client's certificate file (for example, auth/client.crt)"

if(not sys.argv[1].isdigit()):
	print 'Port number must contain only digits 0-9'
	exit()
serverPort = int(sys.argv[1])
#65535 is the max valid port number. port numbers below 1024 don't work because of some sort of permissioning
#thing -- i think it's because many of those port numbers are reserved for certain protocols.
if(serverPort < 1024 or serverPort > 65535): 
	print 'Port number must be in the inclusive range [1024, 65535]'
	exit()

# Check server certificate filename -- make sure this file exists
if (not os.path.isfile(sys.argv[2])):
    print "File " + sys.argv[2] + " does not exist"
    exit()
serverCertPath = sys.argv[2]

# Check server RSA private key filename -- make sure this file exists
if (not os.path.isfile(sys.argv[3])):
    print "File " + sys.argv[3] + " does not exist"
    exit()
serverPrivKeyPath = sys.argv[3]

# Check client certificate filename -- make sure this file exists
if (not os.path.isfile(sys.argv[4])):
    print "File " + sys.argv[4] + " does not exist"
    exit()
clientCertPath = sys.argv[4]



#====================================================== CTRL+C handler

def signal_handler(signal, frame):
	print('\nYou pressed Ctrl+C! Exiting...')
	listenerSocket.close()
	if userThread.isAlive():
		userThread.stop()
	sys.exit(0)
signal.signal(signal.SIGINT, signal_handler)



#====================================================== thread class definition

class userThread(threading.Thread):
	def __init__(self, _mySocket):
		threading.Thread.__init__(self)
		self.mySocket = _mySocket
		self._stop = threading.Event()

	#call this function to stop the thread
	def stop(self):
		mySocket.close()
		self._stop.set()

	#call this function to check if the thread's "stop" event has been set.
	def stopped(self):
		return self._stop.isSet()

	def run(self):
		while 1:
			if(self.stopped()):
				return
		
		receivedMessage = recv_message(mySocket)

    unpickled_dict = pickle.loads(receivedMessage)

    action = unpickled_dict['action']
		filename = unpickled_dict['filename']
		text = unpickled_dict['text'] #this could be plaintext or IV+ciphertext
		signature = unpickled_dict['signature']

		if action == "put":
			basename = os.path.basename(filename) #if filename is "/foo/bar/text.txt", then basename is "text.txt"
			try: 
				f = open(basename, 'wb')
				f.write(text)
				f.close()

				f = open(basename + '.sha256', 'wb')
				f.write(signature)
				f.close()

				status = 'success'
			except IOError as e:
				status = 'failure'



			pickled_message = pickle.dumps({
				'status': status,
				'text': None, 
				'signature': None
				})
			send_message(mySocket, pickled_message)

		if action == "get":
			try:
				#filename might be a full or relative path ("/foo/bar/file.txt" or "./subdirectory/file.txt"). the server will then
				#try to access that. this may fail because we attempt to read something we don't have access to.
				f = open(filename, 'rb')
				text = f.read()
				f.close()

				f = open(filename + '.sha256', 'rb')
				signature = f.read()
				f.close()

				status = 'success'
			except IOError as e:
				status = 'failure'
				text = None,
				signature = None

			pickled_message = pickle.dumps({
				'status': status,
				'text': text, 
				'signature': signature
				})
			send_message(mySocket, pickled_message)

		print "Received action '" + action + "', filename '" + filename + "', status is: " + status
			

#====================================================== the main code

listenerSocket = socket(AF_INET, SOCK_STREAM)
listenerSocket.bind(("", serverPort))
listenerSocket.listen(1)


socketToClient, addr = listenerSocket.accept()
sslSocketToClient = ssl.wrap_socket(socketToClient, server_side=True, certfile=serverCertPath, keyfile=serverPrivKeyPath, ca_certs=clientCertPath, cert_reqs=ssl.CERT_REQUIRED)
print 'Received incoming connection from ' + addr[0] + ':' + str(addr[1])

#create a thread, give the thread the socket connection with the client, and run the thread
userThread = userThread(sslSocketToClient)
userThread.start()