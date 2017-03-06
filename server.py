#authors: kevin liu, ilan buchwald, ruija yang, and jianpu ma
#COMS 4180 group project
#server
#
# this code currently assumes that only 1 client will connect to the server during the lifetime of the server. this means
# that the following situations are not supported:
# 1) multiple clients being connected simultaneously
# 2) client connecting, then user kills the client side (with "stop") command which kills the socket (which causes server
#    to exit), and then client connecting again
# TODO: wait for instructor response on whether current behavior is correct, or whether we need to support case #2

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
  try:
    myUserThread
    if myUserThread.isAlive():
      myUserThread.stop()
  except NameError:
    sys.exit(0)
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
    self.mySocket.close()
    self._stop.set()

  #call this function to check if the thread's "stop" event has been set.
  def stopped(self):
    return self._stop.isSet()

  def run(self):
    while 1:
      if(self.stopped()):
        return
    
      receivedMessage = recv_message(self.mySocket)
      if receivedMessage is None: #then that means the socket was closed on the client side
        self.stop()
        return

      unpickled_dict = pickle.loads(receivedMessage)

       #we established our client-server protocol such that the client's message to the server will always be a dictionary
      #contanining these 4 fields
      action = unpickled_dict['action'] #either "get" or "put"
      filename = unpickled_dict['filename'] #this can be full path + filename, relative path + filename, or just the filename
      text = unpickled_dict['text'] #this could be plaintext or IV+ciphertext
      signature = unpickled_dict['signature'] #SHA256 hash, then signed with client's RSA private key

      if action != "put" and action != "get":
        #then the received message was invalid because action must be either "put" or "get". ignore the message.
        continue

      if action == "put":
        basename = os.path.basename(filename) #if filename is "/foo/bar/text.txt", then basename is "text.txt"
        try:
          f = open(basename, 'wb')
          f.write(text)
          f.close()

          f = open(basename + '.sha256', 'wb')
          print "serv received signature: " + signature
          f.write(signature)
          f.close()

          status = 'success'
        except IOError as e:
          #theoretically this shouldn't happen because we are writing the file to the same directory that the server is executing in, so there should be no permission problems
          status = 'failure'



        pickled_message = pickle.dumps({
          'status': status,
          'text': None,
          'signature': None
          })
        send_message(self.mySocket, pickled_message)

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
        send_message(self.mySocket, pickled_message)

      print "Received action '" + action + "', filename '" + filename + "', resulting status is: " + status
      

#====================================================== the main code

listenerSocket = socket(AF_INET, SOCK_STREAM)
listenerSocket.bind(("", serverPort))
listenerSocket.listen(1)
#TODO: handle case for when serverPort is already in use:
#
# Kevins-MacBook-Pro:ns-group kevinliu$ python server.py 12345 auth/server.crt auth/server.key auth/client.crt 
# Traceback (most recent call last):
#   File "server.py", line 166, in <module>
#     listenerSocket.bind(("", serverPort))
#   File "/System/Library/Frameworks/Python.framework/Versions/2.7/lib/python2.7/socket.py", line 228, in meth
#     return getattr(self._sock,name)(*args)
# socket.error: [Errno 48] Address already in use


socketToClient, addr = listenerSocket.accept()
##TODO: what if serverCertPath, serverPrivKeyPath, clientCertPath are existing files, but not of the valid format? for example, what if they are images? should handle this case
sslSocketToClient = ssl.wrap_socket(socketToClient, server_side=True, certfile=serverCertPath, keyfile=serverPrivKeyPath, ca_certs=clientCertPath, cert_reqs=ssl.CERT_REQUIRED)
print 'Received incoming connection from ' + addr[0] + ':' + str(addr[1])

#create a thread, give the thread the socket connection with the client, and run the thread
myUserThread = userThread(sslSocketToClient)
myUserThread.start()