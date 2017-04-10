#authors: kevin liu, ilan buchwald, ruija yang, and jianpu ma
#COMS 4180 group project
#server
#
# this code currently assumes that only 1 client will connect to the server during the lifetime of the server. this means
# that the following situations are not supported:
# 1) multiple clients being connected simultaneously
# 2) client connecting, then user kills the client side (with "stop") command which kills the socket (which causes server
#    to exit), and then client connecting again
# the instructor has confirmed that the behavior we implement is acceptable

import socket
import ssl
import json
import signal
import sys
import threading
from helpers import *
import os
import errno
import base64


#====================================================== get command line arguments and validate them

#if you run "python server.py 1555 auth/server.crt auth/server.key auth/client.crt", then sys.argv has 5 arguments: server.py is the 1st, 1555 is the 2nd, auth/server.crt is the 3rd, auth/server.key is the 4th, and auth/client.crt is the 5th
if(len(sys.argv) != 5):
  print "Invalid number of arguments. Invoke the server using: python server.py <port> <server certificate> <server private key> <client certificate>, where <port> is a port number in the inclusive range [1024, 65535], <server certificate> is the server's certificate file path (for example, auth/server.crt), <server private key> is the server's RSA private key file path (for example, auth/server.key), and <client certificate> is the client's certificate file path (for example, auth/client.crt)"

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

def mainThreadSignalHandler(signal, frame):
  print('\nYou pressed Ctrl+C! Exiting...')
  keepMainThreadAlive = False
  listenerSocket.close()

  try: #in case a client has connected, then we need to stop that thread and close the socket
    myUserThread
    if myUserThread.isAlive():
      myUserThread.stop()
  except NameError:
    sys.exit(0)

  sys.exit(0)

signal.signal(signal.SIGINT, mainThreadSignalHandler)



#====================================================== thread class definition

class userThread(threading.Thread):
  def __init__(self, _mySocket):
    threading.Thread.__init__(self)
    self.mySocket = _mySocket
    self._stop = threading.Event()

  #call this function to stop the thread
  def stop(self):
    global keepMainThreadAlive
    keepMainThreadAlive = False #so the main thread exits, and the entire program exits
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

      unjsond_dict = json.loads(receivedMessage)

      #we established our client-server protocol such that the client's message to the server will always be a dictionary
      #contanining these 4 fields
      action = unjsond_dict['action'] #either "get" or "put"
      filename = unjsond_dict['filename'] #this can be full path + filename, relative path + filename, or just the filename
      text = unjsond_dict['text'] #this could be plaintext or IV+ciphertext
      signature = unjsond_dict['signature'] #SHA256 hash, then signed with client's RSA private key
      status = 'failure'

      client_files_path = "client_files" + filename

      if action != "put" and action != "get":
        #then the received message was invalid because action must be either "put" or "get". ignore the message.
        continue

      if action == "put":
        try:
          if not os.path.exists(os.path.dirname(client_files_path)):
            os.makedirs(os.path.dirname(client_files_path))

          if client_files_path[-7:] == '.sha256':
            status = 'failure'
          else:
            f = open(client_files_path, 'wb')
            f.write(text)
            f.close()

            f = open(client_files_path + '.sha256', 'wb')
            f.write(json.dumps(signature))
            f.close()

            status = 'success'
        except OSError as exc: # Guard against race condition
          print exc
          status = 'failure'
        except IOError as e:
          #theoretically this shouldn't happen because we are writing the file to the same directory that the server is executing in, so there should be no permission problems
          status = 'failure'

        jsond_message = json.dumps({
          'status': status,
          'text': None,
          'signature': None
          })
        send_message(self.mySocket, jsond_message)

      if action == "get":
        try:
          f = open(client_files_path, 'rb')
          text = f.read()
          f.close()

          f = open(client_files_path + '.sha256', 'rb')
          signature = json.loads(f.read())
          f.close()

          status = 'success'
        except IOError as e:
          status = 'failure'
          text = None,
          signature = None

        jsond_message = json.dumps({
          'status': status,
          'text': text,
          'signature': signature
          })
        send_message(self.mySocket, jsond_message)

      print "Received action '" + action + "', client_files_path '" + client_files_path + "', resulting status is: " + status
      

#====================================================== the main code

try:
  listenerSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  listenerSocket.bind(("", serverPort))
  listenerSocket.listen(1)
except socket.error as e:
  if hasattr(e, 'errno'):
    if e.errno == errno.EADDRINUSE:
      print "Port " + str(serverPort) + " is already in use. Please use another port number."
      exit()
  print e
  exit()


socketToClient, addr = listenerSocket.accept()
print 'Received incoming connection from ' + addr[0] + ':' + str(addr[1])

try:
  sslSocketToClient = ssl.wrap_socket(socketToClient, server_side=True, certfile=serverCertPath, keyfile=serverPrivKeyPath, ca_certs=clientCertPath, cert_reqs=ssl.CERT_REQUIRED)
except ssl.SSLError as e:
  print "Error: Could not perform mutual authentication; at least one of the following is invalid: server certificate, server private key, client certificate"
  exit()
except Exception as e:
  print "Exception occurred: " + str(e)
  exit()


#create a thread, give the thread the socket connection with the client, and run the thread
myUserThread = userThread(sslSocketToClient)
myUserThread.daemon = True
myUserThread.start()


keepMainThreadAlive = True
while keepMainThreadAlive: #keep main thread alive until someone else sets keepMainThreadAlive=False
  pass 
