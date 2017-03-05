#!/usr/bin/env python2
# -*- coding: utf-8 -*-

# based on https://docs.python.org/2/library/ssl.html#server-side-operation

import socket, ssl, pprint, pickle

def main():
    data = None
    res = ""

    # creating socket
    bindsocket = socket.socket()
    # binding socket to a port
    #bindsocket.bind(('', 3000))
    #bindsocket.bind(('', 8888))
    bindsocket.bind(('', 32616))
    # listening up to 1 queued connections made to the socket 
    bindsocket.listen(1)
    
    # socket accepts a connection from a socket with address fromaddr
    newsocket, fromaddr = bindsocket.accept()
    # creating server side ssl.SSLSocket with self-signed certificate - mutual authentication
    server = ssl.wrap_socket(newsocket, server_side=True, certfile="auth/server.crt", keyfile="auth/server.key", ca_certs="auth/client.crt", cert_reqs=ssl.CERT_REQUIRED)

    while True:
        data = server.recv()
        res += data
        print res
        pprint.pprint(res)
        unpickled_res = pickle.loads(res)
        print type(unpickled_res)

        filename = unpickled_res["filename"]
        mode = unpickled_res["mode"]
        plaintext = unpickled_res["plaintext"]
        iv = unpickled_res["iv"]
        ciphertext = unpickled_res["ciphertext"]
        signature = unpickled_res["signature"]

        print unpickled_res

        while data:
            data += server.recv()
            res += data
        print res


    # shutting down connection and further sends and receives are now allowed
    server.shutdown(socket.SHUT_RDWR)
    server.close()
                
if __name__ == "__main__":
    main()          
