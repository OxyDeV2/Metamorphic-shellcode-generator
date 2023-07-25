import random

shellcode = ""

###### LOOP ######

# mov al, 0x21 -> b021 [Default]

# mov al, 0x11
# add al, 0x10 -> b0110410

# mov al, 0x38
# sub al 0x17 -> b0382c17

# add al, 0xb
# add al, 0xb
# add al, 0xb -> adda0badda0badda0b

 ###### XOR BEFORE SYSCALL ######

# xor rax, rax
# xor rdx, rdx -> 4831c04831d2 [Default]

# xor rdx, rdx
# xor rax, rax -> 4831d24831c0

# mov rax, rdx
# xor rax, rdx
# xor rdx, rdx -> 4889d04831d04831d2

 ###### SYSCALL EXIT ######

#mov al, 60 -> B03C
#mov al, 99 - sub al, 39 -> B0632C27
#mov al, 30 - add al, 30 -> B01E041E
#mov dl, 60 - mov rax, rdx -> B23C4889D0

list_exit = ["b03c", "b0632c27", "b01e041e", "b23c4889d0"]
shellcode += random.choice(list_exit)
print(shellcode)

def shellcodize(s):
    shellcode = 'X'
    shellcode += 'X'.join(a+b for a,b in zip(s[::2], s[1::2]))
    shellcode = shellcode.replace('X', '\\x')
    print(shellcode)

shellcodize(shellcode)
