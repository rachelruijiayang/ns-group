#authors: kevin liu, ilan buchwald, ruija yang, and jianpu ma
#COMS 4180 group project
#
#helper functions that both server.py and client.py import and use
#
#since TCP is a stream-based protocol and we need a message-based protocol (to figure out in the byte-stream the
#boundaries when one message ends and another begins), we send a 4-byte int that specifies the length of the
#message. we then read that many bytes from the socket.


def send_message(socket, message):
    message = struct.pack('>I', len(message)) + message
    socket.sendall(message)

def recv_message(socket):
    packedMessageLength = recvall(socket, 4)
    if not packedMessageLength: #then the socket was closed
        return None
    messageLength = struct.unpack('>I', packedMessageLength)[0]
    # Read the message data
    return recvall(socket, messageLength)

#reads n bytes of data from the socket
def recvData(socket, n):
    data = ''
    while len(data) < n:
        chunk = socket.recv(n - len(data))
        if not packet: #then the socket was closed
            return None
        data += chunk
   return data
