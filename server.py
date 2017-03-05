#authors: kevin liu, ilan buchwald, ruija yang, and jianpu ma
#COMS 4180 group project
#server
#
# Command line arguments:
# -port number on which server will listen for connections
#

from socket import *
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
import pickle
import signal
import sys
import threading


#====================================================== get command line arguments and validate them

#if you run "python server.py 1555", then sys.argv has 2 arguments: server.py is the 1st, 1555 is the 2nd
##TODO: also need to pass cert file names, i think
if(len(sys.argv) != 2):
	print "Invalid number of arguments. Invoke the server using: python server.py <port>, where <port> is a port number in the inclusive range [1024, 65535]"

if(not sys.argv[1].isdigit()):
	print 'Port number must contain only digits 0-9'
	exit()
serverPort = int(sys.argv[1])
#65535 is the max valid port number. port numbers below 1024 don't work because of some sort of permissioning
#thing -- i think it's because many of those port numbers are reserved for certain protocols.
if(serverPort < 1024 or serverPort > 65535): 
	print 'Port number must be in the inclusive range [1024, 65535]'
	exit()




#====================================================== CTRL+C handler

def signal_handler(signal, frame):
	print('\nYou pressed Ctrl+C! Exiting...')
	listenerSocket.close()
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
			self._stop.set()

	#call this function to check if the thread's "stop" event has been set.
	def stopped(self):
		return self._stop.isSet()

	def run(self):
		while 1:
			if(self.stopped()):
				return
			

#====================================================== the main code

listenerSocket = socket(AF_INET, SOCK_STREAM)
listenerSocket.bind(("", serverPort))
listenerSocket.listen(1)


socketToClient, addr = listenerSocket.accept()
print 'Received incoming connection from ' + addr[0] + ':' + str(addr[1])

userThread = userThread(socketToClient)
userThread.start()