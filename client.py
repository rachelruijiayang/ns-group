#COMS 4180 group 7 programming  assignment 1
#client part
#

from socket import *
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
import argparse
from Crypto import Random
import pickle
import sys
import os


###########   get commandline argument and validate them
##########    argument :   server ip or hostname,   server's port number, other required parameters for TLS



if(len(sys.argv) != 3):
	print "Invalid number of arguments"

if (not sys.argv[2].isdigit()):

    print 'Port number must contain only digits 0-9'
    exit()

serverPort = int(sys.argv[2])
if (serverPort < 1024 or serverPort > 65535):  # 65535 is the max valid port number
    print 'Port number must be in the inclusive range [1024, 65535]'
    exit()


################ verify other parameters for TLS






serverIP = sys.argv[1]




def main():
    ###########       establish the connection with server
    clientSocket = socket(AF_INET, SOCK_STREAM)
    clientSocket.connect((serverIP, serverPort))

    while clientSocket:

        action_string = raw_input("Input your action with parameter ").split(' ')  # put / get /stop with further parameter
        action =action_string[0]

        if action == 'stop':
            clientSocket.close()             ###############need to close the socket connection before exit
            exit(0)
        file_name=action_string[1]
        encrypt_option=action_string[2]      # encrypt_option for E or N,

        if encrypt_option=='E':
            if action_string[3]:
                password=action_string[3]
                if len(password)!=8:
                    print'password must be exactly 8 digit long'
                    continue
            else:
                print "Missing parameters, E mode requires a password"


        if action == 'put':
            if not (os.path.isfile('file_name')):
                print "Missing file in the current folder"

            if encrypt_option =='E':
                pass
                ##################  generate the SHA256 hash of the plaintext file
                ##################  using the password to create a 16-byte AES key

        ################### client send the file and hash to server



            ##### if successful
            print "sending file complete"

        if action == 'get':


            ##client send a request asking for the file
            ######


            if encrypt_option == 'E':
                ########## decrypt the file
                pass

            #####compute the sha256  hash of the plaintext

            #####compare the hash with the one received

        ########  if the hash matches, the client writes the file to client derectory (not the hash) else display message

        else:
            print "Invalid input action, action must be put, get or stop"


if __name__ == '__main__':
    main()