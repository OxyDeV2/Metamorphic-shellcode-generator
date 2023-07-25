import random

shellcode = ""

 ###### SYSCALL EXIT ######

#mov al, 60 -> B03C
#mov al, 99 - sub al, 39 -> B0632C27
#mov al, 30 - add al, 30 -> B01E041E
#mov dl, 60 - mov rax, rdx -> B23C4889D0


list_exit = ["b03c", "b0632c27", "b01e041e", "b23c4889d0"]
shellcode += random.choice(list_exit)
print(shellcode)

#def main()

#def shellcodize(s):
#    shellcode = 'X'
#    shellcode += 'X'.join(a+b for a,b in zip(s[::2], s[1::2]))
#    shellcode = shellcode.replace('X', '\\x')
#    return(shellcode)
