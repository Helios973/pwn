# ret2csu

这个手法只能使用到64位程序这里主要使用到的是csu_init函数，这个函数一般会放一个万能的gadget用来控制程序流

## libc_csu_init

函数代码

```assembly
[...]
.text:0000000000400740 loc_400740: ; CODE XREF:
__libc_csu_init+54↓j
.text:0000000000400740 mov rdx, r13
.text:0000000000400743 mov rsi, r14
.text:0000000000400746 mov edi, r15d
.text:0000000000400749 call ds:
(__frame_dummy_init_array_entry - 600E10h)[r12+rbx*8]
.text:000000000040074D add rbx, 1
.text:0000000000400751 cmp rbx, rbp
.text:0000000000400754 jnz short loc_400740
.text:0000000000400756
.text:0000000000400756 loc_400756: ; CODE XREF:
__libc_csu_init+34↑j
.text:0000000000400756 add rsp, 8
.text:000000000040075A pop rbx
.text:000000000040075B pop rbp
.text:000000000040075C pop r12
.text:000000000040075E pop r13
.text:0000000000400760 pop r14
.text:0000000000400762 pop r15
.text:0000000000400764 retn
.text:0000000000400764 ; } // starts at 400700
.text:0000000000400764 __libc_csu_init endp
```

这个很多时候是不能调用rax寄存器的gadget，如果程序不提供libc代码，并且条件用ret2libc的时候就可以使用ret2csu的方法来泄露

再这个个代码中40075a的地方是我们可以控制的寄存器，这些寄存器的值会mov到rdx，rsi，edi的寄存器中这样就可以使得我们可以控制整个程序的执行流

在这里主要知道的一点是r15d是一个逻辑寄存器

## 例题

源码：
```c
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
char bss[200];
void init()
{
    setbuf(stdout,0);
    setbuf(stdin,0);
    setbuf(stderr,0);
    write(1,"ok",3);
} 
int main()
{
    init();
    __asm__ (
        "xor %eax,%eaxnt"
        "test %eax,%eaxnt"
        "jz lable2nt"
        "jnz lable1nt"
        "lable1:nt"
        " pop %rax;pop %rdi;retnt"
        " syscall;retnt"
        " call *%raxnt"
        "lable2:nt"
	);
    char buf[10];
    gets(buf);
    __asm__("mov $1,%rdxnt");
    return 0;
}
```

