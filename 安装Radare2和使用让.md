[Radare2](https://link.zhihu.com/?target=https%3A//github.com/radareorg/radare2)是一个开源、免费的二进制逆向分析框架，使用命令行界面，功能包括十六进制代码编辑、[反汇编](https://zhida.zhihu.com/search?content_id=222108987&content_type=Article&match_order=1&q=反汇编&zhida_source=entity)和动态调试。

## 安装Radare2

在Ubuntu系统上，直接使用apt安装Radare2，命令如下：

```text
sudo apt install radare2
```

## 查看程序信息（Binary Information）

**r2**命令打开一个[ELF二进制程序](https://zhida.zhihu.com/search?content_id=222108987&content_type=Article&match_order=1&q=ELF二进制程序&zhida_source=entity)。

```text
r2 megabeets_0x1
```

![img](https://pic1.zhimg.com/v2-23a1b3a34e7c35739cf59c250e1148da_1440w.jpg)

图1 启动动态调试

**i**（Info）命令显示当前程序的信息

![img](https://pic2.zhimg.com/v2-137acd5bf07f04d4530fe2482760bfb3_1440w.jpg)

**ii**(Info Imports)显示引入的库函数信息

![img](https://pic1.zhimg.com/v2-38f661938c0c463d865084aeec424288_1440w.jpg)

**ie**（Info Entrypoint）显示程序入口点信息

![img](https://pic4.zhimg.com/v2-a09d9b47867d60814fb1f1240079e65b_1440w.png)

**il**（Info Libraries）显示程序链接库的信息

![img](https://picx.zhimg.com/v2-7c05137d4beb7bc8cb5527ea5cdc5441_1440w.jpg)

**is**（Info Symbols）显示程序的符号信息

![img](https://pic3.zhimg.com/v2-86c0e1c8fbae5b548a0431d0c74dba10_1440w.jpg)

**izz**（Search for Strings in the whole binary）显示程序的所有字符串信息

![img](https://pic3.zhimg.com/v2-476c1cf438389ba971011db14e725928_1440w.jpg)



## 程序分析（Analysis）

radare2在启动的时候默认是不进行程序分析，因为二进制代码分析是一个复杂的过程，如果程序比较大会花费大量时间。radare2提供了很多分析命令，这些分析命令都是以a开头的。

**aaa（**analyse all**）**命令对打开的程序进行全面的分析，例如函数分析，如图2所示。

![img](https://pic3.zhimg.com/v2-7535fdc8ac3fb5dc415a689579c8d8e4_1440w.jpg)

图2 aaa命令对程序进行深入分析

**afl**(Analyze Function List)列出所有的函数

![img](https://pica.zhimg.com/v2-41116d1fe06356fcbde6181f87ad20a6_1440w.jpg)

## 标识符（Flags）

Radare2将识别出来的有意义的字符串、函数、节、段、符号等都使用标识符（Flags）进行表示。标识符根据标识对象的类型，分成了不同的[标识符空间](https://zhida.zhihu.com/search?content_id=222108987&content_type=Article&match_order=1&q=标识符空间&zhida_source=entity)。

**fs**（flags）命令可以列出当前程序的标识符的类型和该类型标识符的数量信息。

![img](https://pic2.zhimg.com/v2-aa2a2525a781c1921d76e80badfcb887_1440w.jpg)

f命令可以输出一个标识符类型空间中的标识符列表，如下图所示。“fs strings；f“输出了字符串空间的标识符列表。

![img](https://pic1.zhimg.com/v2-f4fccfe501624bf8c8c739a1760c34ce_1440w.jpg)

## 搜索（Search）

**s**（Search）搜索指定的信息，例如搜索main函数的命令是”s main“。搜索之后可以使用反汇编命令对当前位置的函数进行反汇编。

## 反汇编（Disassembly）

**pdf** (Print Disassemble Function）命令对指定函数进行反汇编。

![img](https://pic3.zhimg.com/v2-9b51006d2e40b566222ba3cfbdbc7b0e_1440w.jpg)

## 图形模式（Visual Graphs）

**VV**命令通过图的模式显示反汇编代码。

![img](https://picx.zhimg.com/v2-557e4492483c1ee2ede8dfb31c2099a7_1440w.jpg)