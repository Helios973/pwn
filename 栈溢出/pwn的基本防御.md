## pwn的基本防御

| TYPE                                                         | gcc选项                                                      | 编译器默认情况                                           |
| ------------------------------------------------------------ | ------------------------------------------------------------ | -------------------------------------------------------- |
| **RELRO** (relocation read only)                             | ”-z norelro”, “-z lazy”, “-z now”                            | “-z lazy”(gcc-4.9) "-z now"(gcc-7.5) “-z lazy”(clang-10) |
| **NX** (no-execute)                                          | “-z execstack”(关闭) "-z noexecstack"(开启)                  | 开启                                                     |
| CANARY (又称 stack-protector)	“-fstack-protector-all”(全部开启) | "-fno-stack-protector"(关闭)	“-fstack-protector”(gcc-4.9开启) | "-fno-stack-protector"(clang-10关闭                      |
| **PIE** (position-independent executables)                   | “-no-pie”(关闭) "-fPIE -pie"(开启)                           | 关闭(gcc-4.9) 开启(gcc-7.5) 关闭(clang-10)               |

这个是对pwn的基本的防护体系

