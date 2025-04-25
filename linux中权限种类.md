# linux中权限种类

## **一、用户权限**

1. ### **超级用户（root）权限**

   - 这是系统中最高级别的权限。超级用户拥有对系统的所有操作权限，包括但不限于安装软件、删除系统文件、管理用户账户等。例如，当需要安装一个新的软件包时，如果有复杂的依赖关系和系统配置修改，往往需要 root 权限来确保安装过程顺利进行。在命令行中，使用 “sudo” 命令可以让普通用户在获得授权后执行需要 root 权限的操作。

2. ### **普通用户权限**

   - 普通用户权限是系统为每个用户分配的基本权限。用户可以在自己的主目录下创建、修改和删除自己的文件，可以运行一些基本的程序。例如，一个普通用户可以在自己的主目录下创建一个文档文件，使用文本编辑器对其进行编辑和保存。但对于系统关键文件和目录，如 “/etc” 目录下的配置文件，普通用户通常只有有限的读取权限，而没有写入和修改权限，这是为了防止用户误操作导致系统故障。

3. ### **用户组权限**

   - 用户组是将具有相似权限需求的用户组合在一起的集合。当多个用户需要对同一组文件或目录进行操作时，将他们添加到同一个用户组，然后为该组设置统一的权限是一种高效的管理方式。例如，在一个软件开发团队中，所有的开发人员都被添加到 “developers” 用户组。对于项目的源代码目录，可以设置该目录对 “developers” 组的成员具有读写执行权限，而对其他用户组可能只有只读权限。

## **二、文件权限**

1. ### **读（r）权限**

   - 对于文件，读权限允许用户查看文件的内容。例如，一个文本文件有读权限，用户可以使用文本编辑器打开它并查看其中的文字内容，或者使用命令如 “cat” 来显示文件内容。对于目录，读权限允许用户查看目录中的文件列表，即用户可以看到目录中有哪些文件和子目录，但不一定能访问这些文件或子目录的内容。

2. ### **写（w）权限**

   - 对文件来说，写权限允许用户修改文件的内容，包括添加、删除或编辑文本内容等。例如，如果一个文档文件有写权限，用户可以使用文本编辑器对它进行编辑并保存修改后的版本。对于目录，写权限允许用户在目录中创建、删除或重命名文件和子目录。例如，用户可以在有写权限的目录中创建新的文件或删除已有的文件。

3. ### **执行（x）权限**

   - 对于文件，执行权限是至关重要的，尤其是在可执行程序文件和脚本文件中。如果一个程序文件有执行权限，用户就可以运行这个程序。例如，一个编译好的 Linux 下的可执行程序，如 “./program” 命令中的 “program” 文件，必须有执行权限才能被正常运行。对于脚本文件，如 shell 脚本，也需要有执行权限才能通过 “./script.sh” 这样的命令来执行脚本。对于目录，执行权限允许用户访问目录中的文件和子目录。

## 三、特殊权限

### **1、SUID（Set User ID）**

- **概念**：当一个文件设置了 SUID 权限时，无论该文件被谁执行，执行时都会以文件所有者的身份运行，而不是执行者的身份。
- **示例**：如 `/usr/bin/passwd` 是一个设置了 SUID 的程序。当用户执行`passwd`命令修改密码时，该命令会以 root 用户的身份运行，从而拥有修改`/etc/shadow`等系统文件的权限，否则普通用户无法修改这些文件。
- **安全风险**：SUID 要谨慎使用，因为如果恶意用户能够修改具有 SUID 权限的程序，他们就可以利用该程序以其他用户（特别是 root）的身份执行任意代码。

### **2、SGID（Set Group ID）**

1. **对文件的作用**
   - **概念**：当 SGID 权限设置在文件上时，文件执行时会以文件所属组的权限运行。
   - **示例**：如果有一个用于处理某个特殊组数据的程序，设置了 SGID，那么当任何用户执行该程序时，程序会以该特殊组的权限访问相关文件。
2. **对目录的作用**
   - **概念**：当 SGID 权限设置在目录上时，新创建的文件或子目录会继承该目录的所属组。
   - **示例**：在一个共享目录`/shared/project`中设置了 SGID，无论哪个用户在该目录下创建文件，新文件的所属组都会是`/shared/project`目录的所属组，如`developers`组，方便团队成员共享文件。

### **3、粘滞位（Sticky Bit）**

- **概念**：粘滞位通常用于目录，它允许非目录所有者只能删除或重命名自己拥有的文件或子目录。
- **示例**：在`/tmp`目录上通常会设置粘滞位。多个用户可能都会在`/tmp`目录下创建文件，有了粘滞位后，每个用户只能删除自己创建的文件，不能随意删除其他用户的文件，从而保护了目录中文件的安全性。

### 4.权限属性 chattr

chatrr 只有 root 用户可以使用，用来修改文件系统的权限属性，建立凌驾于 rwx 基础权限之上的授权。chatrr 命令格式：[root@bgx ~]# chattr [+-=] [选项] 文件或目录名

```bash
#选项: + 增加权限 -减少权限 =等于某个权限
# a：让文件或目录仅可追加内容
# i：不得任意更动文件或目录

#1.创建文件并设置属性
[root@lqz ~]# touch file_a file_i
[root@lqz ~]# lsattr file_a file_i
---------------- file_a
---------------- file_i

#2.使用chattr设置属性，lsattr查看权限限制
[root@lqz ~]# chattr +a file_a
[root@lqz ~]# chattr +i file_i
[root@lqz ~]# lsattr file_a file_i
-----a---------- file_a
----i----------- file_i

#3.a权限，无法写入和删除文件，但可以追加数据，适合/etc/passwd这样的文件
[root@lqz ~]# echo "aa" > file_a
bash: file_a: Operation not permitted
[root@lqz ~]# rm -f file_a
rm: cannot remove ‘file_a’: Operation not permitted
[root@lqz ~]# echo "aa" >> file_a

#5.i权限, 无法写入，无法删除，适合不需要更改的重要文件加锁
[root@lqz ~]# echo "i" > file_i
bash: file_i: Permission denied
[root@lqz ~]# echo "i" >> file_i
bash: file_i: Permission denied
[root@lqz ~]# rm -f  file_i
rm: cannot remove ‘file_i’: Operation not permitted

#6.解除限制
[root@tianyun ~]# chattr -a file100
[root@tianyun ~]# chattr -i file200
```

### 5.进程掩码 umask

#### 1.umask 是什么?

当我们登录系统之后创建一个文件总是有一个默认权限的，比如: 目录 755、文件 644、那么这个权限是怎么来的呢？这就是 umask 干的事情。umask 设置了用户创建文件的默认权限。

#### 2.umask 是如何改变创建新文件的权限

系统默认 umask 为 022，那么当我们创建一个目录时，正常情况下目录的权限应该是 777，但 umask 表示要减去的值，所以新目录文件的权限应该是 777 - 022 =755。至于文件的权限也依次类推 666 - 022 =644。

#### 3.umask 涉及哪些配置文件

umask 涉及到的相关文件/etc/bashrc /etc/profile ~/.bashrc ~/.bash_profileshell (vim,touch) –umask–> 会影响创建的新文件或目录权限 vsftpd 服务如果修改–umask–> 会影响 ftp 服务中新创建文件或创建目录权限 useradd 如果修改 umask–> 会影响用户 HOME 家目录权限

#### 4.umask 演示示例

```bash
#1.假设umask值为：022（所有位为偶数）
#文件的起始权限值
6 6 6  -  0 2 2  = 6 4 4

#2.假设umask值为：045（其他用户组位为奇数）
#计算出来的权限。由于umask的最后一位数字是5，所以，在其他用户组位再加1。
6 6 6  -   0 4 5 = 6 2 1

#3.默认目录权限计算方法
7 7 7  -  0 2 2 = 7 5 5

#umask所有位全为偶数时
# umask 044
# mkdir d044   目录权限为733
# touch f044   文件权限为622

#umask部分位为奇数时
# umask 023
# mkdir d023   目录权限为754
# touch f023   文件权限为644

#umask值的所有位为奇数时
# umask 035
# mkdir d035   目录权限为742
# touch f035   文件权限为642
```

示例 1: 在 shell 进程中创建文件

```bash
#查看当前用户的umask权限
[root@lqz ~]# umask
0022
[root@lqz ~]# touch file0022
[root@lqz ~]# mkdir dir0022
[root@lqz ~]# ll -d file0022  dir0022/
drwxr-xr-x 2 root root 6 Jan 24 09:02 dir0022/
-rw-r--r-- 1 root root 0 Jan 24 09:02 file0022
```

示例 2: 修改 shell umask 值(临时生效)

```bash
[root@lqz ~]# umask 000
[root@lqz ~]# mkdir dir000
[root@lqz ~]# touch file000
[root@lqz ~]# ll -d dir000 file000
drwxrwxrwx 2 root root 6 Jan 24 09:04 dir000
-rw-rw-rw- 1 root root 0 Jan 24 09:04 file000
```

示例 3: 通过 umask 决定新建用户 HOME 目录的权限

```bash
[root@lqz ~]# vim /etc/login.defs
UMASK 077
[root@lqz ~]# useradd dba
[root@lqz ~]# ll -d /home/dba/
drwx------. 4 dba dba 4096 3 月 11 19:50 /home/dba/

[root@tianyun ~]# vim /etc/login.defs
UMASK 000
[root@lqz ~]# useradd sa
[root@lqz ~]# ll -d /home/sa/
drwxrwxrwx. 4 sa sa 4096 3 月 11 19:53 /home/sa/
```

## 四、LinuxACL 控制

### 1.ACL 访问控制概述

上一章节我们学习了基础权限`UGO`、特殊权限，但所有的权限是针对某一类用户设置的, 如果希望对文件进行自定义权限控制，就需要用到文件的访问控制列表`ACL`

UGO 设置基本权限: 只能一个用户，一个组和其他人 ACL 设置基本权限： r、w、x 设定`acl`只能是`root`管理员用户. 相关命令: `getfacl` , `setfacl`

`acl`基本使用方式

```bash
//环境准备
[root@lqz ~]# cp /etc/passwd /root/passwd
//文件在没有设定acl, 看到的和传统权限是一样
[root@lqz ~]# ll passwd
-rw-r--r-- 1 root root 0 10-26 13:59 /home/test.txt

//使用getacl查看权限
[root@lqz ~]# getfacl passwd
# file: passwd
# owner: root
# group: root
user::rw-   //文件owner权限
group::r--  //文件拥有组权限
other::r--  //其他人权限
```

#### 1.设定 acl 权限案例如下

```bash
-rw-r--r-- 1 root root 1380 Feb 27 11:25 passwd

alice 拥有读写权限    rw
bgx  没有任何权限     -
jack 组拥有读权限     r
匿名用户拥有读写权限  rw


//建立相关用户
[root@lqz ~]# useradd alice
[root@lqz ~]# useradd bgx
[root@lqz ~]# useradd jack

//增加用户 alice 权限
[root@lqz ~]# setfacl -m u:alice:rw passwd

//增加用户 bgx 权限
[root@lqz ~]# setfacl -m u:bgx:- passwd

//增加匿名用户权限
[root@lqz ~]# setfacl -m o::rw passwd

//增加组权限
[root@lqz ~]# setfacl -m g:jack:r passwd


注意: 如果用户同时属于不同的两个组，并且两个组设定了acl访问控制
    1.根据acl访问控制优先级进行匹配规则
    2.如有用户拥有多个组的权限不同的权限，优先使用最高权限（模糊匹配）
```

#### 2.查看 acl 权限

```bash
[root@lqz ~]# ll passwd
-rw-rw-rw-+ 1 root root 1531 Jan 26 07:52 passwd

[root@lqz ~]# getfacl passwd
# file: passwd
# owner: root
# group: root
user::rw-
user:bgx:---
user:alice:rw-
group::r--
group:jack:r--
mask::rw-
other::rw-
```

#### 3.移除 acl 权限

```bash
//移除jack组的acl权限
[root@lqz ~]# setfacl -x g:jack passwd

//移除bgx用户的acl权限
[root@lqz ~]# setfacl -x u:bgx passwd

//移除文件和目录所有acl权限
[root@lqz ~]# setfacl -b passwd

//移除默认的acl
[root@lqz ~]# setfacl -k dir
```

#### 4.查看 acl 帮助

```bash
//EXAMPLES 示例文档
[root@lqz ~]# man setfacl

//复制 file1 的 ACL 权限给 file2
[root@lqz ~]# setfacl -m u:alice:rw,u:bgx:r,g:jack:rw file1
[root@lqz ~]# getfacl file1 |setfacl --set-file=- file2
```

### 2.ACL 高级特性 MASK

`mask`用于临时降低用户或组的权限，但不包括文件的所有者和其他人。`mask`最主要的作用是用来决定用户的最高权限。

`mask`默认不会对匿名用户降低权限，所以为了便于管理文件的访问控制，建议匿名用户的权限置为空

```bash
//临时降低用户或组权限
[root@lqz ~]# setfacl -m mask::rw filename
```

小结 1.`mask`会影响哪些用户，除了所有者和其他人。 2.`mask`权限决定了用户访问文件时的最高权限。(如何影响) 3.`mask`用于临时降低用户访问文件的权限。(mask 做什么) 4.任何重新设置`acl`访问控制会清理`mask`所设定的权限。

### 3.ACL 高级特性 Default

default: 继承(默认)
`alice`能够对`/opt`目录以及以后在`/opt`目录下新建的文件有读、写、执行权限

```bash
//赋予 alice 对/home 读写执行权限
[root@lqz ~]## setfacl -R -m u:alice:rwX /opt
//赋予 alice 对以后在/home 下新建的文件有读写执行权限(使 alice 的权限继承)
[root@lqz ~]## setfacl -m d:u:alice:rwX /opt

//检查对应的权限
[root@linux-node1 ~]# getfacl /opt/
getfacl: Removing leading '/' from absolute path names
# file: opt/
# owner: root
# group: bgx
user::rwx
user:alice:rwx
group::rwx
mask::rwx
other::rwx
default:user::rwx
default:user:alice:rwx
default:group::rwx
default:mask::rwx
default:other::rwx
```

### 4.ACL 访问控制实践案例

案例 1: 将新建文件的属性修改`tom:admin`, 权限默认为 644 要求: `tom`对该文件有所有的权限, `mary`可以读写该文件, `admin`组可以读写执行该文件, `jack`只读该文件, 其他人一律不能访问该文件

```bash
//实验前, 建立几个普通用户
[root@lqz ~]# useradd tom
[root@lqz ~]# useradd bean
[root@lqz ~]# useradd mary
[root@lqz ~]# useradd jack
[root@lqz ~]# useradd sutdent
[root@lqz ~]# groupadd admin
[root@lqz ~]# gpasswd -a mary admin
[root@lqz ~]# gpasswd -a bean admin

//检查用户属性
[root@linux-node1 ~]# id tom
uid=1004(tom) gid=1004(tom) groups=1004(tom)
[root@linux-node1 ~]# id mary
uid=1006(mary) gid=1006(mary) groups=1006(mary),1007(admin)
[root@linux-node1 ~]# id bean
uid=1005(bean) gid=1005(bean) groups=1005(bean),1007(admin)
[root@linux-node1 ~]# id jack
uid=1002(jack) gid=1002(jack) groups=1002(jack)
[root@linux-node1 ~]# id sutdent
uid=1007(sutdent) gid=1008(sutdent) groups=1008(sutdent)

//准备相关文件
[root@linux-node1 ~]# cp /etc/passwd /root/
[root@linux-node1 ~]# chown tom:admin passwd
[root@linux-node1 ~]# chmod 644 passwd

//检查设定前的acl列表
[root@linux-node1 ~]# getfacl passwd
# file: passwd
# owner: tom
# group: admin
user::rw-
group::r--
other::r--

//设定acl权限
[root@linux-node1 ~]# setfacl -m u::rwx,u:mary:rw,u:jack:r,g:admin:rwx,o::- passwd

//检查acl权限
[root@linux-node1 ~]# getfacl passwd
# file: passwd
# owner: tom
# group: admin
user::rwx
user:jack:r--
user:mary:rw-
group::r--
group:admin:rwx
mask::rwx
other::---
```

acl 的控制规则是从上往下匹配 1.`tom`由于是文件的拥有者，所以直接按照`user::rwx`指定的权限去操作 2.`mary`用户从上往下寻找匹配规则，发现`user:mary:rw-`能够精确匹配`mary`用户，尽管`mary`属于`admin`组，同时`admin`组有`rwx`的权限，但是由于`mary`用户的规则在前面，所有优先生效。 3.`bean`由于找不到精确匹配的规则，而`bean`是属于`admin`组，根据文件的定义，该文件是属于`admin`组，所以`bean`的权限是按照`group:admin:rwx`的权限去操作。 4.`jack`用户从上往下寻找匹配规则，发现`user:jack:r--`能够精确匹配`jack`用户。 5.`student`用户找不到精确匹配的`user`定义规则, 也找不到相关组的定义规则，最后属于`other`。

案例 2: `lab acl setup`

```bash
controller组成员有:student
sodor组成员有:thomas,james

目录: /shares/steamies
文件: /shares/steamies/file
脚本: /shares/steamies/test.sh

controller属于该目录的所属组, 新建文件必须属于controller组
sodor组的成员对该目录拥有rwx权限
sodor组成员james对该目录及子目录(包括以后新建立的文件)没有任何权限
```

实际操作

```bash
//准备用户
[root@linux-node1 ~]# groupadd controller
[root@linux-node1 ~]# groupadd sodor
[root@linux-node1 ~]# useradd student -G controller
[root@linux-node1 ~]# useradd thomas -G sodor
[root@linux-node1 ~]# useradd james -G sodor

//准备目录
[root@linux-node1 ~]# mkdir /shares/steamies -p
[root@linux-node1 ~]# echo "file" >> /shares/steamies/file
[root@linux-node1 ~]# echo "echo 123" >> /shares/steamies/test.sh
[root@linux-node1 ~]# chmod 755 /shares/steamies/test.sh
[root@linux-node1 ~]# chown -R  :controller /shares/steamies/
[root@linux-node1 ~]# chmod g+s /shares/steamies/


//设定权限(X表示,如果原本有执行权限就保留,如果没有则不添加)
[root@linux-node1 ~]# setfacl -R -m g:sodor:rwX,u:james:- /shares/steamies/

//设定继承规则
[root@linux-node1 ~]# setfacl -R -m d:g:sodor:rwX,d:u:james:- /shares/steamies/


[root@linux-node1 steamies]# getfacl /shares/steamies/
getfacl: Removing leading '/' from absolute path names
# file: shares/steamies/
# owner: root
# group: controller
# flags: -s-
user::rwx
user:james:---
group::r-x
group:sodor:rwx
mask::rwx
other::r-x
default:user::rwx
default:group::r-x
default:group:sodor:rwx
default:mask::rwx
default:other::r-x
```

### 4 Linux 输入输出

#### 1.重定向概述

##### 1.什么是重定向

将原本要输出到屏幕的数据信息，重新定向到某个指定的文件中。比如：每天凌晨定时备份数据，希望将备份数据的结果保存到某个文件中。这样第二天通过查看文件的内容就知道昨天备份的数据是成功还是失败。

##### 2.为何要使用重定向

1.当屏幕输出的信息很重要，而且希望保存重要的信息时；2.后台执行中的程序，不希望他干扰屏幕正常的输出结果时；3.系统的例行命令, 例如定时任务的执行结果，希望可以存下来时；4.一些执行命令，我们已经知道他可能出现错误信息, 想将他直接丢弃时;5.错误日志与正确日志需要分别输出至不同的文件保存时;

##### 3.学习重定向的预备知识，标准输入与输出

当运行一个程序时通常会自动打开三个标准文件，分别是标准输入、标准输出、错误输出

| 名称               | 文件描述符 | 作用                                       |
| ------------------ | ---------- | ------------------------------------------ |
| 标准输入（STDIN）  | 0          | 默认是键盘，也可以是文件或其他命令的输出。 |
| 标准输出（STDOUT） | 1          | 默认输出到屏幕。                           |
| 错误输出（STDERR） | 2          | 默认输出到屏幕。                           |

文件名称（filename）
3+

进程将从标准输入中得到数据，将正常输出打印至屏幕终端，将错误的输出信息也打印至屏幕终端。PS: 进程是使用文件描述符`(file descriptors)`来管理打开的文件

![img](https://img2023.cnblogs.com/blog/1770854/202502/1770854-20250209232105086-1678156299.png)
以 cat 命令为例, cat 命令的功能是从命令行给出的文件中读取数据，并将这些数据直接送到标准输出。若使用如下命令：

```bash
#会把文件/etc/passwd的内容输出显示到屏幕上
[root@lqz ~]# cat /etc/passwd
```

但如果 使用 cat 命令没有跟上输入的文件名，那么 cat 命令则会通过命令行标准输入中读取数据, 并将其送到标准输出。

```bash
[root@lqz ~]# cat
hello   #标准输入
hello   #标准输出
^C
#用户输入的每一行都立刻被cat命令输出到屏幕上。
```

下面了解一下标准输入输出过程

```bash
#持续追踪查看文件内容
[root@lqz ~]# tail -f /etc/passwd
ctrl+z 将进程转到后台

#查看运行的进程
[root@lqz ~]# ps
PID TTY          TIME CMD
5848 pts/1    00:00:00 bash
6885 pts/1    00:00:00 tail
6888 pts/1    00:00:00 ps

#查看tail命令的pid，6885进程下的文件描述符
[root@lqz ~]# ls -l /proc/6885/fd
total 0
lrwx------ 1 root root 64 Dec  3 06:57 0 -> /dev/pts/1
lrwx------ 1 root root 64 Dec  3 06:57 1 -> /dev/pts/1
lrwx------ 1 root root 64 Dec  3 06:56 2 -> /dev/pts/1
lr-x------ 1 root root 64 Dec  3 06:57 3 -> /etc/passwd
lr-x------ 1 root root 64 Dec  3 06:57 4 -> inotify

#Linux查看标准输入输出设备
[root@lqz ~]# ls -l /dev/std
lrwxrwxrwx 1 root root 15 Dec  2 22:30 /dev/stderr -> /proc/self/fd/2
lrwxrwxrwx 1 root root 15 Dec  2 22:30 /dev/stdin -> /proc/self/fd/0
lrwxrwxrwx 1 root root 15 Dec  2 22:30 /dev/stdout -> /proc/self/fd/1
```

#### 2.输出重定向

输出重定向，改变输出内容的位置。输出重定向有如下几种方式，如表格所示

| 类型               | 操作符 | 用途                                                         |
| ------------------ | ------ | ------------------------------------------------------------ |
| 标准覆盖输出重定向 | >      | 将程序输出的正确结果输出到指定的文件中,会覆盖文件原有的内容  |
| 标准追加输出重定向 | >>     | 将程序输出的正确结果以追加的方式输出到指定文件，不会覆盖原有文件 |
| 错误覆盖输出重定向 | 2>     | 将程序的错误结果输出到执行的文件中，会覆盖文件原有的内容     |
| 错误追加输出重定向 | 2>>    | 将程序输出的错误结果以追加的方式输出到指定文件，不会覆盖原有文件 |
| 标准输入重定向     | <<     | 将命令中接收输入的途径由默认的键盘更改为指定的文件或命令     |

案例 1: 标准输出重定向(每次都会覆盖文件)

![img](https://img2023.cnblogs.com/blog/1770854/202502/1770854-20250209232105646-1509929475.png)

```bash
#标准输出重定向, 先清空,后写入, 如果文件不存在则创建
[root@lqz ~]# ifconfig eth0 > abc
```

案例 2: 标准输出重定向(会往文件的尾部在添加内容)

![img](https://img2023.cnblogs.com/blog/1770854/202502/1770854-20250209232106190-1626418621.png)

```bash
#标准追加输出重定向, 向配置文件末尾追加内容
[lqz@lqz ~]$ echo "This is network conf" >> if
```

案例 3: 错误输出重定向

![img](https://img2023.cnblogs.com/blog/1770854/202502/1770854-20250209232106759-1695092020.png)

```bash
#正确输出以及错误输出重定向至一个文件
[root@lqz ~]# useradd lqz
[root@lqz ~]# su - lqz

#将标准输出和标准错误输出重定向到不同文件
[lqz@lqz ~]$ find /etc -name ".conf" 1>a 2>b
```

案例 4: 正确和错误都输入到相同位置
![img](https://img2023.cnblogs.com/blog/1770854/202502/1770854-20250209232107292-2100542751.png)

```bash
#将标准输出和标准错误输出重定向到同一个文件, 混合输出
[lqz@lqz ~]$ find /etc -name ".conf" &>ab

#合并两个文件内容至一个文件
[lqz@lqz ~]$ cat a b > c
```

案例 5: 正确和错误都输入到相同位置
![img](https://img2023.cnblogs.com/blog/1770854/202502/1770854-20250209232107837-2069008296.png)

```bash
#重定向到相同的位置
[root@lqz ~]# ls /root /error >ab  2>&1
```

案例 6: 重定向到空设备/dev/null

![img](https://img2023.cnblogs.com/blog/1770854/202502/1770854-20250209232108383-1866178044.png)

```bash
#将产生的任何数据放入黑洞设备，则视为丢弃。
[root@lqz ~]# ls /root /error >ab 2>/dev/null
[root@lqz ~]# ls /root /error >ab &>/dev/null
```

案例 7: 脚本中使用重定向 (了解即可)

```bash
[root@lqz ~]# vim ping.sh
ping -c1 10.0.0.1
if [ $? -eq 0 ];then
    echo "10.0.0.1 is up."
else
    echo "10.0.0.1 is down."
fi
[root@lqz ~]# chmod +x ping.sh
[root@lqz ~]# ./ping.sh

#改进后版
[root@lqz ~]# vim ping.sh
ping -c1 10.0.0.1 &>/dev/null
if [ $? -eq 0 ];then
    echo "10.0.0.1 is up."
else
    echo "10.0.0.1 is down."
fi
```

案例 8: 脚本中使用重定向 (了解即可)

```python
[root@lqz ~]# vim ping2.sh
ping -c1 10.0.0.1 &>/dev/null
if [ $? -eq 0 ];then
    echo "10.0.0.1 is up." >>up.txt
else
    echo "10.0.0.1 is down." >>down.txt
fi
[root@lqz ~]# chmod +x ping2.sh
[root@lqz ~]# ./ping2.sh
```

#### 3.输入重定向

输入重定向，即原本从键盘等上获得的输入信息，重定向由命令的输出作为输入。< 等价 0<
案例 1: 从文件中读入输入的操作

```bash
#没有改变输入的方向，默认键盘
[root@lqz ~]# mail alice
Subject: hello
1111
2222
3333
.   #结束
EOT

#检查是否收到邮件
[root@lqz ~]# su - alice
[root@lqz ~]# mail

#输入重定向，来自于文件
[root@lqz ~]# mail -s "test01" alice < /etc/hosts
```

案例 2: 无法形容案例，请看实际操作

```bash
#没有改变输入的方向，默认键盘，此时等待输入
[root@lqz ~]# grep 'root'
xxx
xxx

[root@lqz ~]# grep 'root' < /etc/passwd
root:x:0:0:root:/root:/bin/bash
```

案例 3: 无法形容案例，请看实际操作

```bash
[root@lqz ~]# dd if=/dev/zero of=/file1.txt bs=1M count=20
[root@lqz ~]# dd </dev/zero >/file2.txt bs=1M count=20
```

案例 4: mysql 如何恢复备份，了解即可，不用关注。

```bash
[root@lqz ~]# mysql -uroot -p123 < bbs.sql
```

案例 5: 利用重定向建立多行数据的文件

```bash
#手动执行 shell 命令
[root@lqz ~]# echo "111" > file1.txt
[root@lqz ~]# cat file1.txt
111
[root@lqz ~]# cat >file2.txt
111
222
333
^D

[root@lqz ~]# cat >>file3.txt
aaa
bbb
ccc
^D
```

案例 6: 脚本中打印菜单的一种使用方法。

```bash
[root@lqz ~]# vim vm.sh
cat <<-EOF
+------------------- --- ---- --- ---- --- --- ---- --- --+ ||
| ====================== |
| 虚拟机基本管理 v5.0 |
| by lqz |
| ====================== |
| 1. 安装 KVM |
| 2. 安装或重置 CentOS-6.9 |
| 3. 安装或重置 CentOS-7.4 |
| 5. 安装或重置 Windows-7  |
| 6. 删除所有虚拟机 |
| q. 退出管理程序 |
+------------------- --- ---- --- ---- --- --- ---- --- --+
EOF
```

案例 7: 两条命令同时重定向

```bash
[root@lqz ~]# ls; date &>/dev/null
[root@lqz ~]# ls &>/dev/null; date &>/dev/null
[root@lqz ~]# (ls; date) &>/dev/null

#后台执行
[root@lqz ~]# (while :; do date; sleep 2; done) &
[1] 6378
[root@lqz ~]# (while :; do date; sleep 2; done) &>date.txt &
[root@lqz ~]# jobs
[1]+ 运行中 ( while :; do date; sleep 2;
done ) &>/date.txt &
```

扩展点: subshell 了解即可

```bash
[root@lqz ~]# cd /boot; ls

//subshell 中执行
[root@lqz ~]# (cd /boot; ls)

#如果不希望某些命令的执行对当前 shell 环境产生影响，请在subshell中执行
```

#### 4.进程管道技术

##### 1.什么是管道

管道操作符号 “|” ，主要用来连接左右两个命令, 将左侧的命令的标准输出, 交给右侧命令的标准输入 PS: 无法传递标准错误输出至后者命令

##### 2.管道流程示意图

![img](https://img2023.cnblogs.com/blog/1770854/202502/1770854-20250209232108987-626007163.png)格式: `cmd1 | cmd2 [...|cmdn]`

##### 3.管道使用案例

案例 1: 将/etc/passwd 中的用户按 UID 大小排序

```bash
[root@lqz ~]# sort -t":" -k3 -n /etc/passwd
[root@lqz ~]# sort -t":" -k3 -n /etc/passwd -r
[root@lqz ~]# sort -t":" -k3 -n /etc/passwd |head
```

案例 2: 统计当前/etc/passwd 中用户使用的 shell 类型

```bash
#思路:取出第七列(shell) | 排序(把相同归类)| 去重
[root@lqz ~]# awk -F: '{print $7}' /etc/passwd
[root@lqz ~]# awk -F: '{print $7}' /etc/passwd |sort
[root@lqz ~]# awk -F: '{print $7}' /etc/passwd |sort |uniq
[root@lqz ~]# awk -F: '{print $7}' /etc/passwd |sort |uniq -c
```

案例 4: 统计网站的访问情况 top 20

```bash
#思路: 打印所有访问的连接 | 过滤访问网站的连接 | 打印用户的 IP | 排序 | 去重

[root@lqz ~]# yum -y install httpd
[root@lqz ~]# systemctl start httpd
[root@lqz ~]# systemctl stop firewalld

[root@lqz ~]# ss -an |grep :80 |awk -F":" '{print $8}' |sort |uniq -c
[root@lqz ~]# ss -an |grep :80 |awk -F":" '{print $8}' |sort |uniq -c |sort -k1 -rn |head -n 20
```

案例 5: 打印当前所有 IP

```bash
[root@lqz ~]# ip addr |grep 'inet ' |awk '{print $2}' |awk -F"/" '{print $1}'
127.0.0.1
192.168.69.112
```

案例 6: 打印根分区已用空间的百分比(仅打印数字)

```bash
[root@lqz ~]# df |grep '/$' |awk '{print $5}' |awk -F"%" '{print $1}'
```

PS: 管道命令符能让大家能进一步掌握命令之间的搭配使用方法，进一步提高命令输出值的处理效率。

##### 4.管道中的 tee 技术

![img](https://img2023.cnblogs.com/blog/1770854/202502/1770854-20250209232109540-635143161.png)

```bash
#选项: -a追加
[root@lqz ~]# ip addr |grep 'inet ' |tee ip.txt |awk -F"/" '{print $1}' |awk '{print $2}'
127.0.0.1
10.0.0.100

[root@lqz ~]# cat ip.txt
inet 127.0.0.1/8 scope host lo
inet 10.0.0.100/24 brd 192.168.69.255 scope global ens32
```

重定向与 tee 有他们在使用过程中有什么区别

```bash
[root@lqz ~]# date > date.txt    #直接将内容写入date.txt文件中
[root@lqz ~]# date |tee date.txt #命令执行会输出至屏幕，但会同时保存一份至date.txt文件中
```

5.xargs 参数传递，主要让一些不支持管道的命令可以使用管道技术

```bash
# which cat|xargs ls- l
# ls |xargs rm -fv
# ls |xargs cp -rvt /tmp/ -或-> ls | xargs -I {} cp -rv {} /tmp/
# ls |xargs mv -t /tmp/   -或-> ls | xargs -I {}  mv {} /tmp
```