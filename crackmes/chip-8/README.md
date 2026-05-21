# chip-8

> crackmes.one | 难度 1.2 | .NET 9.0 Console App | 知识点: .NET IL 结构 + UTF-16LE 字符串 + 工具选择

## 题目简介

.NET 9.0 控制台 crackme。运行后提示输入 serial,输入正确显示 `"Correct!"`,错误显示 `"Try Again."`。

文件组成:
- `chip-8.exe` — .NET Host/Runtime Loader(原生 x64 PE)
- `chip-8.dll` — .NET IL 程序集(实际代码)
- `chip-8.runtimeconfig.json` — runtime 版本配置

**密码: `password`**

但这道题的**真正价值不是找密码**,而是理解 .NET 程序的结构和工具选择。

## 核心知识点

- .NET IL(中间语言)与原生机器码的区别
- .NET 字符串以 **UTF-16LE** 编码存储,`strings -e l` 才能搜到
- .NET 程序结构: exe(host loader) + dll(IL 代码 + 元数据) + JIT 编译
- `runtimeconfig.json` 的向后兼容性(降级到 .NET 8 运行)
- **工具选择**: .NET 程序用 dnSpyEx/ILSpy,原生 PE 用 x64dbg/Ghidra

## 走过的弯路(最有价值的部分)

### 弯路 1: 用 x64dbg 分析 .NET 程序

直觉上用 x64dbg 打开 `chip-8.exe`,尝试:
- 搜字符串 `"Try Again."` → 搜不到
- 搜字符串 `"password"` → 搜不到
- Memory Map 里右键找搜索 → 没有

**原因:** .NET 字符串字面量存储在 DLL 的**元数据表**中,运行时 JIT 编译后才被复制到**托管堆**。x64dbg 的字符串搜索只在 PE 静态段(`.rdata`/`.text`)中查找,自然搜不到 .NET 元数据中的字符串。

**教训:** .NET 程序不要用原生调试器做主力分析工具。

### 弯路 2: Ghidra 默认分析 .NET DLL 失败

用 Ghidra 导入 `chip-8.dll`,分析报错:
```
AggressiveInstructionFinder Not Run. Too few functions defined.
```

**原因:** Ghidra 默认把文件当成 x86-64 机器码解析。但 `chip-8.dll` 里是 .NET IL 字节码,不是机器码。IL 的操作码(如 `0x72` ldstr)被当成 x86 指令解析,结果一团乱码,找不到函数序言。

**修复:** Ghidra 导入时需要手动选 `.NET` 语言,或启用 `DotNet` 分析器插件。但即使修复,Ghidra 的 .NET 支持也远不如 dnSpyEx,只能看到 IL 汇编。

**教训:** Ghidra 可以分析 .NET,但需要额外配置,效果不如专用工具。

## 二进制侦察

### 文件类型确认

```bash
file chip-8.exe
# PE32+ executable for MS Windows 6.00 (console), x86-64

file chip-8.dll
# PE32 executable for MS Windows 4.00 (console),
# Intel i386 Mono/.Net assembly, 3 sections
```

`chip-8.exe` 是原生 x64 PE,`chip-8.dll` 是 .NET IL 程序集。

### 运行时障碍

```bash
dotnet chip-8.dll
# Framework 'Microsoft.NETCore.App', version '9.0.15' (x64)
# Found: 8.0.11, 8.0.14, 9.0.0, 10.0.1
```

缺少 .NET 9.0.15 runtime。

### 非预期解法: runtimeconfig.json 降级

修改 `chip-8.runtimeconfig.json`:
```json
{
  "runtimeOptions": {
    "framework": {
      "name": "Microsoft.NETCore.App",
      "version": "8.0"
    }
  }
}
```

利用 .NET 的向后兼容性,用已安装的 .NET 8 runtime 运行。程序只用了基本 API(`Console.ReadLine`/`WriteLine`/`==`),.NET 8 完全兼容。

### 字符串搜索

```bash
# .NET 字符串是 UTF-16LE,需要 -e l 参数
strings -e l chip-8.dll | sort | uniq

# 输出:
# Correct!
# Enter Serial:
# Try Again.
# password
```

密码在 1 秒内暴露。

## 反编译代码

用 dnSpyEx 打开 `chip-8.dll`,找到 `Program.Main`:

```csharp
private static void Main()
{
    Console.Write("Enter Serial: ");
    string text = Console.ReadLine();
    bool flag = text == "password";   // ← 明文比较
    if (flag)
    {
        Console.WriteLine("Correct!");
        Console.ReadLine();
    }
    else
    {
        Console.WriteLine("Try Again.");
        Console.ReadLine();
    }
}
```

Debug 编译保留了 `bool flag` 中间变量。Release 模式下会优化成 `if (text == "password")`。

## .NET 程序结构详解

```
chip-8.exe ─────────┐
                    │ 运行时加载
chip-8.dll ─────────┘
```

### 文件分工

| 文件 | 内容 | 分析工具 |
|---|---|---|
| `chip-8.exe` | .NET Host Loader(原生 x64 机器码) | x64dbg(调试进程)、Ghidra(原生分析) |
| `chip-8.dll` | C# 代码编译的 IL 字节码 + 元数据 | dnSpyEx(看源码)、ILSpy(反编译) |

### 运行时流程

```
chip-8.exe 启动
    │
    ▼
加载 .NET Runtime(coreclr.dll)
    │
    ▼
加载 chip-8.dll 到内存
    │
    ▼
JIT 编译器把 IL → 机器码
(此时才有 x86-64 机器码)
    │
    ▼
CPU 执行机器码
```

### 为什么 x64dbg 搜不到字符串

| 阶段 | 字符串位置 | x64dbg 能否搜到 |
|---|---|---|
| 编译后 | DLL 元数据表(UTF-16LE) | ❌ 不在 PE 静态段 |
| JIT 编译时 | 被复制到托管堆 | ❌ 堆地址动态分配 |
| 运行时 | 寄存器/栈(临时) | ⚠️  fleeting,难抓 |

x64dbg 的字符串搜索只在模块的静态段中查找,自然找不到 .NET 元数据中的字符串。

## 多种破解方法对比

### 方法 1: 改 config + strings(最快)

```bash
# 1. 修改 runtimeconfig.json: "9.0.15" → "8.0"
# 2. 运行程序
dotnet chip-8.dll
# 3. 输入 password → Correct!
```

时间: < 1 分钟。

### 方法 2: strings -e l(不用运行)

```bash
strings -e l chip-8.dll | grep password
```

不需要运行程序,静态提取密码。`-e l` 是提取 little-endian 16-bit 字符的关键。

### 方法 3: dnSpyEx(最直观)

1. dnSpyEx → File → Open → `chip-8.dll`
2. 左边展开 `chip-8` → `Program` → 双击 `Main`
3. 直接看到 C# 源码和明文密码

### 方法 4: dnSpyEx Patch(改逻辑)

1. 右键 `Main` → Edit Method (C#)
2. 把 `text == "password"` 改成 `true`
3. File → Save Module
4. 任意输入都显示 "Correct!"

### 方法 5: x64dbg(最绕,不推荐)

理论上可行:
1. x64dbg 打开 `chip-8.exe`
2. 运行到 "Enter Serial:"
3. 在 `WriteConsoleW` 等底层 API 下断点
4. 回溯调用栈找到 JIT 编译后的比较代码
5. 在比较处改寄存器或 patch

但 .NET JIT 编译后的代码地址每次运行不同,定位极其困难。这是用螺丝刀敲钉子。

## 关键细节

### UTF-16LE 的 hex 形式

`"password"` 在 DLL 中的原始字节:
```
p  \0  a  \0  s  \0  s  \0  w  \0  o  \0  r  \0  d  \0
70 00 61 00 73 00 73 00 77 00 6F 00 72 00 64 00
```

`strings` 默认按 ASCII(1 字节)解析,会跳过这些 `\0` 间隔的字符。`-e l` 告诉 `strings` 按 2 字节 little-endian 解析,正好匹配 UTF-16LE。

### Debug vs Release 编译差异

Debug 模式下编译器保留中间变量:
```csharp
bool flag = text == "password";  // Debug 保留
if (flag) { ... }
```

Release 模式下优化掉:
```csharp
if (text == "password") { ... }  // Release 直接比较
```

这道题是 Debug 编译(Assembly 属性里有 `[assembly: Debuggable(...)]`),所以看到了 `flag` 变量。

### .NET 向后兼容性

`runtimeconfig.json` 中的 `"version": "9.0.15"` 是一个**最低版本要求**。如果系统没有 9.0.15,但有兼容的低版本(如 8.0),降级 version 后可以运行。

但注意:这只对**基本 API**有效。如果程序用了 .NET 9 的新 API,降级后会报 `MissingMethodException`。

## 学到的东西

- **`.NET 字符串用 UTF-16LE`**: `strings -e l` 是搜 .NET 字符串的正确方式
- **`.NET IL ≠ 机器码`**: Ghidra/x64dbg 不是 .NET 的主力分析工具,dnSpyEx/ILSpy 才是
- **`.NET 程序结构`**: exe 是 host,dll 是代码,JIT 编译后才变机器码
- **工具选择比技术更重要**: 用错工具分析 .NET 程序,1.2 难度的题也能卡 30 分钟
- **`runtimeconfig.json` 降级**: 绕过 .NET runtime 版本缺失的实用技巧

## Flag

```
Correct!
```
(输入 `password` 后显示)

## 参考

- crackmes.one: <https://crackmes.one/>
- dnSpyEx: <https://github.com/dnSpyEx/dnSpy>
- .NET Runtime 下载: <https://dotnet.microsoft.com/en-us/download/dotnet/9.0>
