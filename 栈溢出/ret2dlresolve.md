# ret2dlresolve

这个方法的主要特征就是该题目是不提供libc。另外如果使用ret2dlresolve则不能使用patchelf来修改elf文件，主要原因是因为会移动到延迟绑定的相关结构

## 相关结构

主要使用到.dynamic、dynstr、dynsym和.rel.plt重要的section

```tex
dynamic:
这里主要放了几个比较重要的
1 dynstr存放了string table 也就是部分函数的字符串
2.dynsym存放了elf的符号表，存放了重定位类型
3.rel.plt 重定位偏移
```

