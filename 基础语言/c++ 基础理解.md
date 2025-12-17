# c++ 基础理解

## 基础程序理解

这里我们用hello world来理解程序

```c++
#include "iostream"
//using namespace std;
int main(){
    std::cout<<"hello world"<<std::endl;

    return 0;
}
```

但是在ida中的程序反编译的就有很大的区别这里我们上ida的程序

```cpp
__int64 __fastcall main()
{
  __int64 v0; // rax

  _main();
  //c++的底层原理是要通过底层硬件的方式来编写程序的因此这里的意思是 开辟一个空间::操作员 refptr__ZSt4cout这个代表的是std::cout这里代表的是一个cout输出
  v0 = std::operator<<<std::char_traits<char>>(refptr__ZSt4cout, "hello world");
  //下面也是同样的道理使用了一个寄存器
  std::ostream::operator<<(v0, refptr__ZSt4endlIcSt11char_traitsIcEERSt13basic_ostreamIT_T0_ES6_);
  return 0LL;
}
```

