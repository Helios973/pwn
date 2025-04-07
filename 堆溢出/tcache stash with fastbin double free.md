# tcache stash with fastbin double free

这个主要就是吧fastbin中的double free把他修改到tcahe中

![image-20250404233437720](./../images/image-20250404233437720.png)

但是要在fastbin中构造一个double free

![image-20250404233924239](./../images/image-20250404233924239.png)

这里主要的想法就是使用堆块把tcache填满使得数据写入到fastbin中从而在fastbin中构造一个double free