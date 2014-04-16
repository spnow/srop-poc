section .text
push 2
pop rsi
xor rdi, rdi
inc rdi
inc rdi
inc rdi
inc rdi

loop:
xor rax, rax
mov rax, 33
syscall
dec rsi
jns loop
