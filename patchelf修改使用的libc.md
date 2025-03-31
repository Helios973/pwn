# patchelf修改使用的libc

现在只在buu上做一些题，所以用本地默认的libc也能跑起来，但在做一些其他的比赛的题的时候发现都会提供libc，这种情况下需要我们修改libc，使用给定的libc，这种情况下就需要使用patchelf来修改libc，以实现本地和远程与题目的环境相同，这样也可以避免使用libcsearcher，这个有时候不好用，下面记录一下是怎么做的。

首先需要安装glibc-all-in-one，patchelf，安装就不介绍了，glibc-all-in-one通过github安装，patchelf直接apt install就行，安装好以后进入glibc-all-in-one的文件夹：

![img](https://pic4.zhimg.com/v2-d194502036df5fa41199af6de662d49b_1440w.jpg)

然后使用python运行update_list，然后list和old_list就会更新，cat可以查看：

![img](https://picx.zhimg.com/v2-cb8c111e6739e8a43ad2b149a9461889_1440w.jpg)

到这里就是glibc-all-in-one安装完成了，现在开始看看怎么使用可以把libc做修改，我们随便找一道题，可以查看他现在使用的libc情况：

![img](https://pic3.zhimg.com/v2-048e16981d6e24e63b1cbe9c0e627320_1440w.jpg)

这里用的题目前后不太一样，只是举个例子

我们要对他进行修改，首先，我们要看一下题目给的libc对应的是哪个版本：

![img](https://pica.zhimg.com/v2-e4d7f22174167a2d8f80e029e0e04fd8_1440w.jpg)

```text
./libc-x.xxx
or
strings ./libc-x.xx | grep ubuntu
```

通过这样就可以看到其使用的glibc版本了，这里的是使用的2.23-0ubuntu11，我们在glibc-all-in-one的list和old-list里看有没有这一个版本，我这道题是32位的所以用i386,64位就用上面那个：

![img](https://pic1.zhimg.com/v2-6ffe53eece1b9d84a6c25620e5c95f64_1440w.jpg)

可以看到是有的，找到以后就在glibc-all-in-one的文件节里通过命令来下载：

```text
./download 2.23-0ubuntu11.3_i386
```

下载完成后就可以在当前目录下的libs里找到我们下载完成的libc包。接下来就可以使用patchelf来替换了。

进入下载好的glibc文件夹，可以看到里面有很多文件：

![img](https://pic2.zhimg.com/v2-8341429dbfef88f7ba0366d270d203e3_1440w.jpg)

用两个patchelf命令就可以完成了，我这里是在题目的文件夹下操作的，具体路径自己换一下就好了：

先使用下面这个命令来把ld替换掉，[pwd命令](https://zhida.zhihu.com/search?content_id=237918708&content_type=Article&match_order=1&q=pwd命令&zhida_source=entity)查看当前的绝对路径，就可以直接复制粘贴了：

```text
patchelf --set-interpreter /home/ahh/Tools/glibc-all-in-one/libs/2.23-0ubuntu11.3_i386/ld-2.23.so ./axb_2019_fmt32
```

再使用下面这个命令来直接换path，这里的参数注意一下，是直接把整个文件夹设给了题目，用网上其他的方法似乎不是很好，这是我滴舍友教我的方法：

```text
patchelf --set-rpath /home/ahh/Tools/glibc-all-in-one/libs/2.23-0ubuntu11.3_i386/ ./axb_2019_fmt32
```

这样就设置完成了，我们再通过ldd看一下：

![img](https://pic3.zhimg.com/v2-bc9bcc6ac3ba7623a56c6a5a2c048488_1440w.jpg)

替换成功了，到这里就结束了，尝试运行题目，可以正常运行，这样的话对于栈题，在写exp的时候就可以直接指定libc了，偏移啥的也很好找了，不用再libcsearcher了，一般来说如果题目给的libc不能调试，为了方便可以把glibc-all-in-one下好的这个文件夹里的[libc.so](https://zhida.zhihu.com/search?content_id=237918708&content_type=Article&match_order=1&q=libc.so&zhida_source=entity)文件放到题目文件夹里来用，应该是可以调试的、

------

有一些时候会出现要使用的libc无法在glibc-all-in-one里找到，这种情况也有解决办法，我还不太会，到时候遇上了问问，能解决了再来更新

这种情况已经遇到了，其实glibc-all-in-one也就是写了个脚本来自动下载我们想要的版本，学了一下手动下载和配置的方法，这里记录一下。

首先我们确定我们需要的版本：

![img](https://pic4.zhimg.com/v2-f1382fff5235194b1a0759a633f7c4c1_1440w.jpg)

2.35-0ubuntu3.4

我需要2.35-0ubuntu3.4，但glibc-all-in-one里并没有，我们直接搜索这个版本，直接进官方网站下载，看是32位还是64位，点进去：

![img](https://pic2.zhimg.com/v2-a5a4db1e9631731cfdacc95c9e30cae7_1440w.jpg)

下载下面的两个文件：

![img](https://picx.zhimg.com/v2-1c804577eec2bd71ddf9eb733b688853_1440w.jpg)

放到[虚拟机](https://zhida.zhihu.com/search?content_id=237918708&content_type=Article&match_order=1&q=虚拟机&zhida_source=entity)中，把libc里的和glibc-all-in-one中一样的这些放到我们创建的这个版本的libc文件夹中：

![img](https://pic3.zhimg.com/v2-3e72821eb7ebe2f21c131f515547543a_1440w.jpg)

![img](https://pic2.zhimg.com/v2-c81670a01cf7f85808c40b004e8cd3db_1440w.jpg)

到这里后看dbg那个文件，如果里面的东西和libc的一样，就在外面创建的libc文件夹下创建一个`.debug`文件夹，把里面的东西放到这个文件夹里，这种情况一般是libc版本比较老的时候会出现。

第二种情况就是dbg里的东西和libc里的不一样，在`/./usr/lib/debug/.build-id/` 里是这样的一些文件夹：

![img](https://picx.zhimg.com/v2-8ce2dcc5cb1ada67cdd70337550565eb_1440w.jpg)

那就不要放在我们创建的文件夹里，而是把这些文件夹全都复制到`/usr/lib/debug/.build-id`这个目录下。

先把这些全提取到一个临时文件夹下，再通过[cp命令](https://zhida.zhihu.com/search?content_id=237918708&content_type=Article&match_order=1&q=cp命令&zhida_source=entity)就可以全部复制过去了（注意命令输对，刚刚输错了少了个.直接给硬盘干爆了，哈哈哈）：

![img](https://pic2.zhimg.com/v2-07568015dbdd78c06990cfbb3b455a65_1440w.jpg)