# ROP Emporium Writeups

> [ROP Emporium](https://ropemporium.com/) 全 8 题的解题过程与知识点记录,以及部分 [crackmes.one](https://crackmes.one/) 的 Windows crackme 分析。学习二进制安全 / 漏洞利用方向的入门练习,目标是建立 x86-64 ROP + Windows 逆向的完整心智模型。

## 关于这个仓库

- **作者**: 胡智明(23 级软件工程, 金陵科技学院)
- **学习起点**: 2026-05-09
- **方向**: 二进制安全 / 漏洞研究 / 恶意代码分析(2026 秋招准备)
- **进度**: ROP Emporium 6/8 + Crackme 2 题

每道题独立目录,目录里有:
- `README.md`: 知识点 + 攻击思路 + 栈布局图 + 关键细节 + 踩过的坑
- `exploit.py`(ROP 题): 可直接运行的 pwntools 脚本(详细注释)

## 完成进度

### ROP Emporium

| 题 | 难点 | 知识点 | 状态 |
|---|---|---|---|
| [ret2win](./ret2win/) | 基础栈溢出 + x64 栈对齐 | ELF, padding, p64, movaps 对齐 | done |
| [split](./split/) | 调 system + 找字符串 | x64 调用约定, pop rdi, PLT | done |
| [callme](./callme/) | 链式函数调用 | 三件套 pop, 参数重置, .so 动态库 | done |
| [write4](./write4/) | write-what-where | mov gadget, .bss 利用, 小端序 | done |
| [badchars](./badchars/) | 字符过滤绕过 | XOR 编码, 四连 pop, 重叠 gadget, 对齐算法 | done |
| [fluff](./fluff/) | 没有 pop rdi | xlatb + BEXTR + stosb, AL 间接控制 | done |
| pivot | 栈翻转 | xchg rsp + 二级 ROP + GOT 懒解析 | 80%(对齐卡壳) |
| ret2csu | 用 csu_init 喂参数 | 通用 gadget chain, 万能调用器 | pending |

### Crackmes(Windows PE 逆向)

| 题 | 来源 | 难度 | 知识点 | 状态 |
|---|---|---|---|---|
| [senha](./crackmes/senha/) | crackmes.one | 1.0 | C++ std::string, x32dbg 三种 patch 方法 | done |
| [b](./crackmes/b/) | crackmes.one | 1.0 | XOR 字符串加密, 调用栈定位 main, Patch 字节数陷阱 | done |

## 我的关键经验总结(踩坑换来的)

### 1. padding 计算公式

看 Ghidra 反编译里 `char acStack_XX[N]`,padding 直接 = **`0xXX`**(十六进制 XX 的值)。**不要再 +8**。

理由: Ghidra 的 `acStack_XX` 中 XX 是 buffer 起始**距离函数入口 RSP**(即 saved RIP 在栈上的位置)的偏移。GCC 永远把 buffer 紧贴 saved RBP,所以 buffer 顶端 = saved RBP,buffer 起始到 saved RIP 的距离正好是 `0xXX`。

不确定时用 `cyclic` 实测:

```python
io.sendline(cyclic(100))
io.wait()
core = io.corefile
print(cyclic_find(p64(core.pc)[:6]))
```

### 2. 栈对齐通用算法

数从 pwnme ret 后到进入目标函数前的**所有 `+8` 操作总数 N**(每个 `pop` 和每个 gadget 末尾的 `ret` 都算):

- **N 奇数** → 进函数 RSP 末位 = 8 → 对齐 → 不要 ret_gadget
- **N 偶数** → 进函数 RSP 末位 = 0 → 不对齐 → 补一个 ret_gadget

旧版"奇偶 pop"规律(只数 pop 个数)只在"全 pop + 一个目标函数"的简单链里成立,链里夹 mov / xor 等非 pop gadget 时会漏算它们的 ret。

### 3. 调试 ROP 链的快速分诊

`Thank you!` 输出 + EOF(看到这个组合时):
- pwnme 末尾的 puts 跑完了 → ROP 链跳转前 / 中崩了
- 先怀疑 saved RIP 没被覆盖到正确地址(padding 错)
- 再怀疑 gadget 地址 typo
- 最后怀疑对齐错(进 PLT 函数时 movaps 崩)

90% 的崩溃都是这三个之一。

## 环境

- WSL2 Ubuntu 22.04
- Python 3 + pwntools + ROPgadget + GDB
- Ghidra(Windows 侧, GUI 反编译)

## 运行 exploit

每个题目目录:

```bash
cd <题目>
LD_LIBRARY_PATH=. python3 exploit.py    # 题目带 .so 时用这个
# 或
python3 exploit.py                       # 不带 .so 的题(ret2win/split)
```

二进制需要自己从 [ropemporium.com](https://ropemporium.com/) 下载(本仓库出于版权原因不收录原始二进制)。

## 学习参考

- ROP Emporium 官方: <https://ropemporium.com/>
- 计划下一步:
  - [pwn.college](https://pwn.college/) - 系统化 pwn 教学
  - HackTheBox / TryHackMe pwn 类
  - CTFtime - 跟踪国内 CTF 赛事

## 学习日志

完整的逐日学习记录(包括每个题踩的坑、概念修正、未巩固点)放在本地累积日志,不公开此仓库(含未来题目剧透 + 个人计划)。如需面试参考片段可邮件联系。

---

**License**: MIT(代码) / CC BY 4.0(文档)
