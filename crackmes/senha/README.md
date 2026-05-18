# senha.exe

> crackmes.one | 难度 1.0 | Windows PE32(MinGW)| 葡萄牙语提示 | 知识点: 明文密码比较 + x32dbg 三种 patch 方法

## 题目简介

`senha` 是葡萄牙语"密码"的意思。程序提示 `Digite a senha:`(请输入密码),输入正确密码输出 `Acesso Liberado`(访问通过),错误输出 `Acesso Negado`(访问拒绝)。密码硬编码在二进制里。

这道题最大的价值不在"找密码"(密码就是 `1234`,明文写着),而在练习三种 x32dbg 动态修改技巧:**改返回值 / 改控制流 / 改输入**。

## 核心知识点

- Ghidra 反编译 C++ 二进制(MinGW 编译,`std::__cxx11` 风格符号)
- `__cdecl` 调用约定 = 32 位 Windows 标志
- C++ `std::string` 对象的内存布局(占 24~40 字节,**不是** `char[N]`)
- x32dbg 三种 patch 技巧:
  - 改函数返回值(运行时,临时)
  - Patch 条件跳转(永久,生成新 exe)
  - 改输入字符串内存(运行时,临时)

## 二进制侦察

```bash
# Windows PowerShell
Get-ItemProperty senha.exe | Select-Object Length, LastWriteTime
# 看大小、时间

# Ghidra 打开后,顶部:
# File → Info → Imported Symbols
# 看到 std::__cxx11 → MinGW 编译
# 看到 __cdecl → 32 位
```

## Ghidra 反编译关键代码

```c
int __cdecl main(int _Argc, char **_Argv, char **_Env)
{
    undefined8 uVar1;
    string local_38 [40];

    __main();
    std::__cxx11::string::string(local_38);
    std::operator<<((longlong *)&std::cout, "Digite a senha: ");
    std::operator>>(&std::cin, local_38);
    uVar1 = std::operator==(local_38, "1234");           // <-- 关键
    if ((char)uVar1 == '\0') {
        std::operator<<((longlong *)&std::cout, "Acesso Negado\n");
    } else {
        std::operator<<((longlong *)&std::cout, "Acesso Liberado\n");
    }
    ...
}
```

密码 `"1234"` 明文写在第 4 个参数。`std::operator==` 返回 `bool`(`true` = 相等)。

## 解法一:直接输入密码

```
Digite a senha: 1234
Acesso Liberado
```

但这不是"破解"。下面三种 patch 才是练习目的。

## 解法二:x32dbg 改返回值(运行时临时)

### 步骤

1. x32dbg 打开 senha.exe(32 位用 x32dbg,不是 x64dbg)
2. **右键 → Search for → All Modules → String references**
3. 搜 `Digite a senha`,双击定位到 main 函数
4. 在附近找 `CALL <std::operator==>` 后面的 `TEST AL, AL`
5. 在 `TEST AL, AL` 那一行按 **F2** 下断点
6. **F9** 运行,程序提示输入密码,输入任意字符串(如 `abcd`),回车
7. x32dbg 停在 `TEST AL, AL`
8. 寄存器面板找 **EAX**(或 **AL**),双击,改成 `1`
9. **F9** 继续,程序输出 `Acesso Liberado`

### 原理

`std::operator==` 返回值在 EAX。返回 `0` 表示不相等,`1` 表示相等。强行把 EAX 改成 `1`,后续判断会认为相等。

## 解法三:Patch 条件跳转(永久,生成新 exe)

### 步骤

1. 同上定位到 `TEST AL, AL` 后面的条件跳转(`JE` 或 `JZ`)
2. 选中跳转指令,按 **空格**
3. 改成 `JMP <成功分支地址>`(无条件跳到成功分支)
4. **Ctrl+P** 打开 Patches 窗口
5. 右键 → **Patch File**
6. 保存为 `senha_patched.exe`
7. 双击 `senha_patched.exe`,输入任意密码,输出 `Acesso Liberado`

### 字节数注意

`JE rel8`(短跳)= 2 字节(`74 XX`),`JMP rel8`(短跳)= 2 字节(`EB XX`),完美替换。
`JE rel32`(近跳)= 6 字节(`0F 84 XX XX XX XX`),`JMP rel32` = 5 字节(`E9 XX XX XX XX`),改完要补 1 个 `NOP`。

## 解法四:改输入内存(运行时临时)

### 步骤

1. 在 `std::operator>>` 调用**之后**下断点
2. **F9** 运行,输入任意字符串(如 `aaaa`)
3. 程序断住,在内存窗口里 **Ctrl+B** 搜 `aaaa`
4. 找到后右键 → **Edit → ASCII**,改成 `1234`
5. **F9** 继续,程序认为输入是 `1234`,输出 `Acesso Liberado`

### 原理

把内存里的"用户输入"直接换成正确密码。`std::operator==` 比较的是内存内容,不知道你已经偷偷换过了。

## 关键细节

### C++ `std::string` 不等于 `char[]`

反编译里的 `string local_38 [40]` 容易让人误以为是 40 字节字符数组。实际上:

- `local_38` 是一个 `std::string` 对象,本身占 40 字节(GCC 64 位 + 对齐填充,GCC 32 位通常 24 字节)
- 对象内部有指针、长度、容量
- 短字符串可能用 **SSO(Short String Optimization)**直接存在对象内部,长字符串存在堆上

**不能像 `char buf[40]` 那样简单栈溢出**。这道题用了 `std::operator>>` 不会溢出,但要记住这个区别——以后碰到 C++ 程序时不要直接套 C 风格栈溢出模板。

### Windows x86 调用约定(`__cdecl`)

- 参数从右往左压栈
- 调用者负责清理栈
- 返回值在 EAX

这就是为什么改 EAX 能修改 `std::operator==` 的返回值。

### `__main()` 是什么

MinGW / GCC 编译的 Windows 程序入口前会调用 `__main()`,负责调用全局对象的构造函数(C++ 静态初始化)。可以理解为"main 之前的 C++ 准备工作"。看到它别紧张,不是漏洞函数。

## 总结对比

| 方法 | 难度 | 永久修改 | 适用场景 |
|---|---|---|---|
| 解法二:改 EAX | 低 | 否 | 快速验证,不想改文件 |
| 解法三:Patch JMP | 中 | 是 | 想生成"破解版"分发 |
| 解法四:改输入 | 中 | 否 | 理解内存布局 |

## 学到的东西

- 1.0 难度的 crackme 通常密码明文,Ghidra 反编译几秒钟能看出来
- x32dbg / x64dbg 的本质能力:**程序运行时,寄存器和内存都是可见可改的**
- 同一个目的可以从"返回值"、"控制流"、"输入数据"三个层面突破,理解这三层比"知道密码"重要得多

## 参考

- crackmes.one: <https://crackmes.one/>
- x64dbg 文档: <https://x64dbg.com/>
