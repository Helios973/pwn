# _io_file源码

## file结构

在我们看这个io的结构体的时候我们应该先了解一下io主要的一个作用，这里我们可以知道io这个代表的就是对输入输出的一个使用，因此这里代表的也是对文件的一个操作，也就是对文件的要给读写操作的一个集合，知道了这个那么我们看看从io的一个源头开始看源代码

```c
/* We always allocate an extra word following an _IO_FILE.
   This contains a pointer to the function jump table used.
   This is for compatibility with C++ streambuf; the word can
   be used to smash to a pointer to a virtual function table. */
struct _IO_FILE_plus
{
  _IO_FILE file;
  const struct _IO_jump_t *vtable;
};
```

实际上我们最终描述的文件流文件的数据结构就是io-file-plus，其中有io-file结构体和常量io-jump-t（内容不可以被修改），而根据成员名称，我们大概率推测不出成员作用中file这个成员变量的一个关键信息，而vtable他是一个虚表，以及各种操作函数的指针。

下面我们看一下对应io-file的一个源码结构，主要的源码在libio/libio.h文件中，如下所示

```c
struct _IO_FILE {
  int _flags;		/* High-order word is _IO_MAGIC; rest is flags. */
#define _IO_file_flags _flags

  /* The following pointers correspond to the C++ streambuf protocol. */
  /* Note:  Tk uses the _IO_read_ptr and _IO_read_end fields directly. */
  char* _IO_read_ptr;	/* Current read pointer */
  char* _IO_read_end;	/* End of get area. */
  char* _IO_read_base;	/* Start of putback+get area. */
  char* _IO_write_base;	/* Start of put area. */
  char* _IO_write_ptr;	/* Current put pointer. */
  char* _IO_write_end;	/* End of put area. */
  char* _IO_buf_base;	/* Start of reserve area. */
  char* _IO_buf_end;	/* End of reserve area. */
  /* The following fields are used to support backing up and undo. */
  char *_IO_save_base; /* Pointer to start of non-current get area. */
  char *_IO_backup_base;  /* Pointer to first valid character of backup area */
  char *_IO_save_end; /* Pointer to end of non-current get area. */

  struct _IO_marker *_markers;

  struct _IO_FILE *_chain;

  int _fileno;
#if 0
  int _blksize;
#else
  int _flags2;
#endif
  _IO_off_t _old_offset; /* This used to be _offset but it's too small.  */

#define __HAVE_COLUMN /* temporary */
  /* 1+column number of pbase(); 0 is unknown. */
  unsigned short _cur_column;
  signed char _vtable_offset;
  char _shortbuf[1];

  /*  char* _save_gptr;  char* _save_egptr; */

  _IO_lock_t *_lock;
#ifdef _IO_USE_OLD_IO_FILE
};

struct _IO_FILE_complete
{
  struct _IO_FILE _file;
#endif
#if defined _G_IO_IO_FILE_VERSION && _G_IO_IO_FILE_VERSION == 0x20001
  _IO_off64_t _offset;
# if defined _LIBC || defined _GLIBCPP_USE_WCHAR_T
  /* Wide character stream stuff.  */
  struct _IO_codecvt *_codecvt;
  struct _IO_wide_data *_wide_data;
  struct _IO_FILE *_freeres_list;
  void *_freeres_buf;
# else
  void *__pad1;
  void *__pad2;
  void *__pad3;
  void *__pad4;
# endif
  size_t __pad5;
  int _mode;
  /* Make sure we don't get into trouble again.  */
  char _unused2[15 * sizeof (int) - 4 * sizeof (void *) - sizeof (size_t)];
#endif
};
```

主要的数据也就是他的一些结构在这个结构体中我们可以知道在这个版本的libc中他有一个flags的一个结构，这个结构的用法就是一个用来验证的一些操作的，剩下的一些数据比如_IO_read_ptr这些都是指向的一个指针用来指向对应的一个使用的方向和方法的，但是在这些文件中会出现一些chain的需要我们了解和知道。

进程中的 FILE 结构会通过_chain 域彼此连接形成一个链表，链表头部用全局变量_IO_list_all 表示，通过这个值我们可以遍历所有的 FILE 结构。

在标准的io库中，每个程序启动时有三个文件会被自动的打开分别时stdin,stdout,stderr这里三个。因此在初始状态下，_IO_list_all指向了一个有这些文件流构成的一个链表，但是我们还是主要关注这三个文件位于libc.so的数据段。而我们使用fopen来创建文件流是分配在堆内存上的。

我们可以在libc.so中找到stdin、stdout、stderr等符号

但是事实上io file这个结构外包裹着另一种结构io file plus，其中包含了一个重要的指针也就是vtable指向了一系列函数指针

在libc2.23中32位vtable偏移位**0x94**，在64位上偏移位**0xd8**

同时这个vtable是一个io_jump_t类型的要给指针，IO_jump_t中保存了一些函数指针，在后面我们会看到在一系列标准io函数中会调用这些函数的指针

```c
struct _IO_jump_t
{
    JUMP_FIELD(size_t, __dummy);
    JUMP_FIELD(size_t, __dummy2);
    JUMP_FIELD(_IO_finish_t, __finish);
    JUMP_FIELD(_IO_overflow_t, __overflow);
    JUMP_FIELD(_IO_underflow_t, __underflow);
    JUMP_FIELD(_IO_underflow_t, __uflow);
    JUMP_FIELD(_IO_pbackfail_t, __pbackfail);
    /* showmany */
    JUMP_FIELD(_IO_xsputn_t, __xsputn);
    JUMP_FIELD(_IO_xsgetn_t, __xsgetn);
    JUMP_FIELD(_IO_seekoff_t, __seekoff);
    JUMP_FIELD(_IO_seekpos_t, __seekpos);
    JUMP_FIELD(_IO_setbuf_t, __setbuf);
    JUMP_FIELD(_IO_sync_t, __sync);
    JUMP_FIELD(_IO_doallocate_t, __doallocate);
    JUMP_FIELD(_IO_read_t, __read);
    JUMP_FIELD(_IO_write_t, __write);
    JUMP_FIELD(_IO_seek_t, __seek);
    JUMP_FIELD(_IO_close_t, __close);
    JUMP_FIELD(_IO_stat_t, __stat);
    JUMP_FIELD(_IO_showmanyc_t, __showmanyc);
    JUMP_FIELD(_IO_imbue_t, __imbue);
#if 0
    get_column;
    set_column;
#endif
};

```

---

在上面我们知道这个是一个io库所以我们重点还是看对io进行操作的一些库和函数下面是我们这个的第一个函数就是我们的fread这个函数

## fread

fread是标准io库函数，作用是从文件中读取数据，函数原型如下

```c
size_t fread ( void *buffer, size_t size, size_t count, FILE *stream) ;
```

- buffer 存放读取数据的缓冲区。
- size：指定每个记录的长度。
- count： 指定记录的个数。
- stream：目标文件流。
- 返回值：返回读取到数据缓冲区中的记录个数

在_IO_sgetn 函数中会调用_IO_XSGETN，而_IO_XSGETN 是_IO_FILE_plus.vtable 中的函数指针，在调用这个函数时会首先取出 vtable 中的指针然后再进行调用。

源码：

```c
#include "libioP.h"

_IO_size_t
_IO_fread (void *buf, _IO_size_t size, _IO_size_t count, _IO_FILE *fp)
{
  _IO_size_t bytes_requested = size * count;
  _IO_size_t bytes_read;
  CHECK_FILE (fp, 0);
  if (bytes_requested == 0)//验证读入的数据是否为0
    return 0;
  _IO_acquire_lock (fp);
  bytes_read = _IO_sgetn (fp, (char *) buf, bytes_requested);// 从文件流中读取指定字节数到 buf
  _IO_release_lock (fp);
  return bytes_requested == bytes_read ? count : bytes_read / size; //如果读取成功就返回读取的数量，否则就返回实际读取的数量
}
libc_hidden_def (_IO_fread)

#ifdef weak_alias
weak_alias (_IO_fread, fread)

# ifndef _IO_MTSAFE_IO
strong_alias (_IO_fread, __fread_unlocked)
libc_hidden_def (__fread_unlocked)
weak_alias (_IO_fread, fread_unlocked)
# endif
#endif

```

其实他的代码并不多（这个原因也有可能是）

## fwrite

fwrite 同样是标准 IO 库函数，作用是向文件流写入数据，函数原型如下

```
size_t fwrite(const void* buffer, size_t size, size_t count, FILE* stream);
```

- buffer: 是一个指针，对 fwrite 来说，是要写入数据的地址;
- size: 要写入内容的单字节数;
- count: 要进行写入 size 字节的数据项的个数;
- stream: 目标文件指针;
- 返回值：实际写入的数据项个数 count。

根据前面对_IO_FILE_plus 的介绍，可知_IO_XSPUTN 位于_IO_FILE_plus 的 vtable 中，调用这个函数需要首先取出 vtable 中的指针，再跳过去进行调用。

源码：

```c
#include "libioP.h"

_IO_size_t
_IO_fwrite (const void *buf, _IO_size_t size, _IO_size_t count, _IO_FILE *fp)
{
  _IO_size_t request = size * count;
  _IO_size_t written = 0;
  CHECK_FILE (fp, 0);
  if (request == 0)
    return 0;
  _IO_acquire_lock (fp);
  if (_IO_vtable_offset (fp) != 0 || _IO_fwide (fp, -1) == -1)
    written = _IO_sputn (fp, (const char *) buf, request);// 写入数据到文件流
  _IO_release_lock (fp);
  /* We have written all of the input in case the return value indicates
     this or EOF is returned.  The latter is a special case where we
     simply did not manage to flush the buffer.  But the data is in the
     buffer and therefore written as far as fwrite is concerned.  */
  if (written == request || written == EOF)
    return count;
  else
    return written / size;
}
libc_hidden_def (_IO_fwrite)

#ifdef weak_alias
# include <stdio.h>
weak_alias (_IO_fwrite, fwrite)
libc_hidden_weak (fwrite)
# ifndef _IO_MTSAFE_IO
weak_alias (_IO_fwrite, fwrite_unlocked)
libc_hidden_weak (fwrite_unlocked)
# endif
#endif
```



## fopen

fopen 在标准 IO 库中用于打开文件，函数原型如下

```
FILE *fopen(char *filename, *type);
```

- filename: 目标文件的路径
- type: 打开方式的类型
- 返回值: 返回一个文件指针

```c
_IO_FILE *
__fopen_internal (const char *filename, const char *mode, int is32)
{
  struct locked_FILE
  {
    struct _IO_FILE_plus fp;
#ifdef _IO_MTSAFE_IO
    _IO_lock_t lock;
#endif
    struct _IO_wide_data wd;
  } *new_f = (struct locked_FILE *) malloc (sizeof (struct locked_FILE));

  if (new_f == NULL)
    return NULL;
#ifdef _IO_MTSAFE_IO
  new_f->fp.file._lock = &new_f->lock;
#endif
#if defined _LIBC || defined _GLIBCPP_USE_WCHAR_T
  _IO_no_init (&new_f->fp.file, 0, 0, &new_f->wd, &_IO_wfile_jumps);
#else
  _IO_no_init (&new_f->fp.file, 1, 0, NULL, NULL);
#endif
  _IO_JUMPS (&new_f->fp) = &_IO_file_jumps;
  _IO_file_init (&new_f->fp);
#if  !_IO_UNIFIED_JUMPTABLES
  new_f->fp.vtable = NULL;
#endif
  if (_IO_file_fopen ((_IO_FILE *) new_f, filename, mode, is32) != NULL)
    return __fopen_maybe_mmap (&new_f->fp.file);

  _IO_un_link (&new_f->fp);
  free (new_f);
  return NULL;
}
```



## fclose

fclose 是标准 IO 库中用于关闭已打开文件的函数，其作用与 fopen 相反。



```
int fclose(FILE *stream)
```

功能：关闭一个文件流，使用 fclose 就可以把缓冲区内最后剩余的数据输出到磁盘文件中，并释放文件指针和有关的缓冲区

```c
#include "libioP.h"
#include <stdlib.h>
#if _LIBC
# include "../iconv/gconv_int.h"
# include <shlib-compat.h>
#else
# define SHLIB_COMPAT(a, b, c) 0
# define _IO_new_fclose fclose
#endif

int
_IO_new_fclose (_IO_FILE *fp)
{
  int status;

  CHECK_FILE(fp, EOF);

#if SHLIB_COMPAT (libc, GLIBC_2_0, GLIBC_2_1)
  /* We desperately try to help programs which are using streams in a
     strange way and mix old and new functions.  Detect old streams
     here.  */
  if (_IO_vtable_offset (fp) != 0)
    return _IO_old_fclose (fp);
#endif

  /* First unlink the stream.  */
  if (fp->_IO_file_flags & _IO_IS_FILEBUF)
    _IO_un_link ((struct _IO_FILE_plus *) fp);

  _IO_acquire_lock (fp);
  if (fp->_IO_file_flags & _IO_IS_FILEBUF)
    status = _IO_file_close_it (fp);
  else
    status = fp->_flags & _IO_ERR_SEEN ? -1 : 0;
  _IO_release_lock (fp);
  _IO_FINISH (fp);
  if (fp->_mode > 0)
    {
#if _LIBC
      /* This stream has a wide orientation.  This means we have to free
	 the conversion functions.  */
      struct _IO_codecvt *cc = fp->_codecvt;

      __libc_lock_lock (__gconv_lock);
      __gconv_release_step (cc->__cd_in.__cd.__steps);
      __gconv_release_step (cc->__cd_out.__cd.__steps);
      __libc_lock_unlock (__gconv_lock);
#endif
    }
  else
    {
      if (_IO_have_backup (fp))
	_IO_free_backup_area (fp);
    }
  if (fp != _IO_stdin && fp != _IO_stdout && fp != _IO_stderr)
    {
      fp->_IO_file_flags = 0;
      free(fp);//清空fp的空间
    }

  return status;
}

#ifdef _LIBC
versioned_symbol (libc, _IO_new_fclose, _IO_fclose, GLIBC_2_1);
strong_alias (_IO_new_fclose, __new_fclose)
versioned_symbol (libc, __new_fclose, fclose, GLIBC_2_1);
#endif

```



## printf/puts

printf 和 puts 是常用的输出函数，在 printf 的参数是以'\n'结束的纯字符串时，printf 会被优化为 puts 函数并去除换行符。

puts 在源码中实现的函数是_IO_puts，这个函数的操作与 fwrite 的流程大致相同，函数内部同样会调用 vtable 中的_IO_sputn，结果会执行_IO_new_file_xsputn，最后会调用到系统接口 write 函数。

printf 的调用栈回溯如下，同样是通过_IO_file_xsputn 实现

```tex
vfprintf+11
_IO_file_xsputn
_IO_file_overflow
funlockfile
_IO_file_write
write
```

