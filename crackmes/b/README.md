# b.exe

> crackmes.one | 难度 1.0 | Windows PE32+(stripped)| 知识点: XOR 字符串加密 + 自实现 strcmp + x64dbg 调用栈定位 + Patch 字节数陷阱

## 题目简介

单个 `b.exe`,无配套数据文件。运行后提示输入密码,输入任意字符串都输出 `no`。出题人提示"用了一些 xor 运算"。

最终密码:**`Yippie-Ki-Yay`**(致敬《虎胆龙威》John McClane 的台词)。

但找密码不是这道题最有价值的部分。**整个解题路径暴露了 4 个常见技术点**:字符串加密、stripped 程序定位 main、自实现 strcmp 识别、Patch 字节数陷阱。

## 核心知识点

- Ghidra 反编译 stripped PE32+,函数名全部丢失
- 字符串 XOR 加密存储的反字符串搜索手法
- **三种定位 main 的通用方法**(导入函数反查 / EntryPoint 顺藤摸瓜 / x64dbg 动态断点)
- Windows x64 调用约定:RCX/RDX/R8/R9
- 区分系统库 strcmp 和程序自实现的字符串比较函数
- x64dbg Patch 字节数对齐规则(否则崩溃)

## 走过的弯路(最有价值的部分)

### 弯路 1:误以为是 VM 解释器型

之前做过 `bvessel.exe`(也是 stripped PE32+,配套 `cm.bvs` 字节码文件,内部是 VM 解释器),所以看到 `b.exe` x64dbg 搜不到字符串时,直觉以为也是 VM 型,准备找配套数据文件。

**实际:** 目录里只有 `b.exe` 一个文件,**没有配套数据**。字符串就在 exe 内部,只是被 XOR 加密了。

**教训:** 不要急于套用之前题目的模板。每道新题先确认基本事实:目录文件列表、运行交互、反编译关键函数,再下结论。

### 弯路 2:JNE → NOP 让程序崩溃

找到关键跳转后第一反应是把 `JNE` 直接改成 `NOP`。在 x64dbg 里按空格输入 `nop`,程序变成卡死然后超时退出。

**原因:** `JNE` 的近跳转占 **6 字节**(`0F 85 XX XX XX XX`),但 `NOP` 只有 1 字节(`90`)。x64dbg 的空格修改**不会自动用 NOP 填充剩余字节**,剩下 5 字节被 CPU 当成下一条指令解析,变成垃圾指令崩溃。

**修复:** 改为 `TEST EAX, EAX` → `XOR EAX, EAX`(都是 2 字节 `85 C0` / `33 C0`),完美等长替换。

## 二进制侦察

```bash
# Ghidra 打开后:
# File → Info: PE32+, x86-64, stripped(no debug info)
```

```
程序运行:
> b.exe
请输入密码: aaaa
no
```

x64dbg 搜索字符串:
- 搜 `"no"` → 找不到
- 搜 `"wrong"` / `"correct"` → 找不到
- 任何输出字符串都搜不到 ← **关键诊断**

## 字符串加密反搜索手法

反编译关键函数(用导入函数反查找到的)里有这种代码:

```c
local_d0 = DAT_14000401e ^ 0xaaaa;   // 失败消息 "no" 的密文
local_d8 = DAT_140004020 ^ 0xaaaa;   // 成功消息密文
local_48  = _DAT_140004030 ^ 0xaaaaaaaa;   // 正确密码片段 1 (4 字节)
uStack_44 = uRam0000000140004034 ^ 0xaaaaaaaa;   // 片段 2
uStack_40 = uRam0000000140004038 ^ 0xaaaaaaaa;   // 片段 3
uStack_3c = uRam000000014000403c ^ 0xaaaaaaaa;   // 片段 4
```

XOR key 是常量 `0xaaaa`(2 字节)或 `0xaaaaaaaa`(4 字节)。

**反向计算 "no" 的密文:**

```
明文 "no" = 0x6E 0x6F (ASCII)
小端 ushort = 0x6F6E
0x6F6E ^ 0xAAAA = 0xC5C4
内存中存储 (小端): C4 C5
```

所以 `DAT_14000401e` 处的原始字节是 `C4 C5`,搜 "no" 自然搜不到。

**这是 1.0 难度 crackme 的常见反搜索手法**——零开销,只在加载时做一次 XOR 就足够骗过初学者。

## 如何定位 main(没有评论区提示时)

stripped 程序函数名全部丢失,通常只能看到 `FUN_140003420` 这种自动命名。三种通用方法:

### 方法 1:导入函数反查(Ghidra)

```
Symbol Tree → Imports → strcmp
右键 → Show References to
```

看哪些函数调用了 strcmp。同时调用 `puts` / `strcmp` / `scanf` 的那个就是 main。

### 方法 2:EntryPoint 顺藤摸瓜(Ghidra)

Windows PE 启动固定链:

```
entry → __security_init_cookie → __scrt_common_main → main
```

从 entry 反编译开始跟踪调用链,最后一个非 CRT 函数就是 main。

### 方法 3:x64dbg 动态断点 + 调用栈(最快)

```
bp strcmp        # 在系统库 strcmp 下断点
F9               # 运行,输入任意密码触发
Alt+K            # 看调用栈
```

调用栈会显示:

```
ntdll.strcmp
ucrtbase.strcmp+xx
b.exe+0x3528     <-- 这就是 main 里调用 strcmp 的位置
b.exe+0x2A10
...
```

右键 `b.exe+0x3528` → **Follow in Disassembler**,直接跳到 main 的关键代码。

**这个方法对任何带字符串比较的 crackme 都通用**,不需要静态分析。

## x64dbg 自动识别字符串(最大彩蛋)

`bp strcmp` 断下后,寄存器面板显示:

```
RCX = 用户输入指针 ("aaaa")
RDX = 0x00007FF...  rdx:"Yippie-Ki-Yay"
```

**x64dbg 自动检测 RDX 指向的内存是 ASCII 字符串,在寄存器名旁边直接显示了内容**。密码秒现。

这利用了:
1. Windows x64 调用约定:第 1 参数 → RCX,第 2 参数 → RDX
2. `strcmp(用户输入, 正确密码)` 的参数顺序
3. x64dbg 对指针的自动解引用 + ASCII 识别

## 识别"自实现 strcmp"

按 `bp strcmp` 断下后,在内部按 F8 单步,**发现里面有大量 JE/JNE 循环**:

```asm
loop:
    cmp byte ptr [rcx], 0
    je end
    cmp byte ptr [rcx], byte ptr [rdx]
    jne not_equal
    inc rcx
    inc rdx
    jmp loop
```

这说明 b.exe **自己实现了一个逐字节比较函数**,而不是调用系统库 strcmp(系统库通常是 SIMD 优化的几条指令)。

**这种情况下 patch 比较函数内部的 JE 不可行**(有几十条循环跳转)。必须回到调用点改主函数里的逻辑。

## 关键 Patch:让 JNE 永远不跳

按 **Ctrl+F9**(执行到返回)从比较函数返回到 main,看到:

```asm
CALL b.exe.140001770    ; 调用自实现 strcmp
TEST EAX, EAX           ; 测试返回值(2 字节: 85 C0)
JNE 失败分支地址        ; 不相等(密码错)跳到 "no"
                        ; 顺序执行 = 成功分支
```

### 失败尝试:JNE → NOP

JNE 是 6 字节,NOP 是 1 字节,剩下 5 字节变垃圾指令崩溃(详见上文"弯路 2")。

### 成功方法:TEST EAX, EAX → XOR EAX, EAX

```
原指令: TEST EAX, EAX  = 85 C0  (2 字节)
新指令: XOR  EAX, EAX  = 33 C0  (2 字节)
```

**操作:**

1. 选中 `TEST EAX, EAX` 那一行
2. 按 **空格**
3. 输入:
   ```
   xor eax, eax
   ```
4. **OK**

**原理:** `xor eax, eax` 把 EAX 清零。EAX = 0 时,后续 `JNE`(Jump if Not Equal)检查 ZF 标志位永远为 1,跳转条件不成立,程序顺序执行成功分支。

## 保存 patch 生成可分发的 exe

1. **Ctrl+P** 打开 Patches 窗口
2. 右键 → **Patch File**
3. 选原始 `b.exe`,保存为 `b_patched.exe`
4. 双击 `b_patched.exe`,输入任意密码,输出成功消息

注意:`.1337` 文件**不是可执行**,只是补丁记录文本。要生成 exe 必须走 Patch File 流程。

## x64dbg Patch 字节数对照表

| 指令 | 字节数 | 机器码 |
|---|---|---|
| `TEST EAX, EAX` | 2 | 85 C0 |
| `XOR EAX, EAX` | 2 | 33 C0 |
| `JE rel8`(短跳) | 2 | 74 XX |
| `JNE rel8`(短跳) | 2 | 75 XX |
| `JE rel32`(近跳) | 6 | 0F 84 XX XX XX XX |
| `JNE rel32`(近跳) | 6 | 0F 85 XX XX XX XX |
| `JMP rel8`(短跳) | 2 | EB XX |
| `JMP rel32`(近跳) | 5 | E9 XX XX XX XX |
| `NOP` | 1 | 90 |
| `CALL rel32` | 5 | E8 XX XX XX XX |

**Patch 经验:** 改之前先看右侧十六进制列确认字节数,用同字节数指令替换。如果必须用短指令替换长指令,用 **右键 → Binary → Edit** 手动把剩余字节填 `90`(NOP)。

## 学到的东西

- **字符串加密反搜索**是 1.0 难度常见手法,看到 x64dbg 搜不到字符串时立刻怀疑加密,不要瞎找配套文件
- **`bp strcmp` + Alt+K 调用栈** 是定位 stripped 程序 main 的最快方法,对所有带字符串比较的题通用
- **自实现 strcmp** 的识别特征:`bp strcmp` 后内部出现大量 JE/JNE 循环。这时候 patch 调用点而不是实现点
- **Patch 字节数对齐**是新手必踩的坑,x64dbg 空格修改不自动填充 NOP,长换短必须 Binary Edit
- **Windows x64 调用约定**和 Linux 不同(RCX/RDX/R8/R9 vs RDI/RSI/RDX/RCX/R8/R9),做 Windows crackme 时不要混

## 参考

- crackmes.one: <https://crackmes.one/>
- Windows x64 调用约定: <https://learn.microsoft.com/cpp/build/x64-calling-convention>
- x64dbg 文档: <https://x64dbg.com/>
