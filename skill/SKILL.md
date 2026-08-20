---
name: stream-cipher-security
description: >-
  序列密码（流密码）安全性分析。当用户要对某个流密码算法（自研或对比，含元胞自动机/LFSR/NFSR/ARX）或其
  密钥流做随机性测试（NIST SP800-22 / TESTU01）、Berlekamp-Massey 线性复杂度、统计分析、区分/代数/立方体/
  相关攻击、前向/后向安全、可证明安全与后量子(Grover)评估、性能与对比分析，或撰写论文级（IEEE TIFS）
  安全性分析报告时使用。工具位于 D:\hardness\stream-cipher-analyzer。
license: MIT
metadata:
  version: "0.1.0"
  created: "2026-08-20"
  tool: D:\hardness\stream-cipher-analyzer
---

# 序列密码（流密码）安全性分析

> 本技能驱动 `D:\hardness\stream-cipher-analyzer` 下的 Python 工具，对任意流密码执行从黑盒随机性
> 到可证明/后量子安全的完整分析，产出论文级英文报告（默认 IEEE TIFS）。

## 工具位置与调用

```bash
cd D:\hardness\stream-cipher-analyzer
python cli.py list                                  # 内置参考密码
python cli.py ca-screen --rules 90 30 150 110       # CA 线性退化筛查（第一道安全检查）
python cli.py compare                                # 文献对比表 + CA 攻击面清单
python cli.py empirical --nbits 20000               # 实测黑盒对比
python cli.py analyze <密码> --nseq 10 --nbits 1000000
python cli.py report  <密码> --rule 30 --cells 64 --key-bits 128   # 完整管线 + 报告
python cli.py testu01 <密码> --battery smallcrush                  # TESTU01（需 WSL，金标准）
python cli.py testu01 --keystream-file 文件 --battery bigcrush     # 直接读密钥流文件
```

`<密码>` 为内置名（`chacha20`/`trivium`/`grain128`/`salsa20`/`a51`）或 `路径/文件.py:类名`。
输出在 `results/`（图 PDF+PNG、表 LaTeX+CSV、报告 report.md）。

## 分析管线（7 层）

1. 算法接入 → 适配器（黑盒 `keystream`；可选结构 `init`/`step`/`output_function`）
2. 黑盒随机性 → NIST SP800-22（15/15）+ TESTU01（SmallCrush/Crush/BigCrush，需 WSL）
3. 线性与统计 → B-M 线性复杂度曲线 + 频率/自相关/χ²/游程
4. 结构攻击 → 代数（XL/SAT/Gröbner）+ 立方体 + 相关 + 区分
5. 安全性质 → 前向/后向 + 可证明脚手架 + 后量子 Grover
6. 性能对比 → 软件 + 定频 FPGA 估算 + 文献对比表（带引用）
7. 报告 → 图/表/正文（IEEE TIFS 结构）

只有黑盒接口 → 执行 ②③⑥；补了结构接口 → 解锁 ④⑤。

## 适配器契约（接入新密码）

```python
from analyzer.ingest import CipherAdapter
class MyCipher(CipherAdapter):
    name = "my-cipher"; key_size = 128; iv_size = 96
    def keystream(self, key, iv, nbits): ...   # 唯一必需，返回 0/1 的 list
    # 可选结构接口：init(key,iv) / step(state) / output_function(state)
```

- **MATLAB 源码**：逐运算翻译为 Python/numpy（保持算法与运算不变），并**必须**与用户提供的
  "同一 seed 前若干胞元/bit 密钥流"逐 bit 交叉验证，一致才继续。
- 模板见 `docs/example_cipher.py`（可运行的 rule-30 最小示例）。

## 判定阈值

- **NIST SP800-22 已于 2022-11 被 NIST 撤回**：照跑满足惯例，但报告须注明并配 TESTU01。
- **线性复杂度**：随机序列 ≈ n/2；线性 CA 规则（90/150/105 等）LC 极低 → 立即判不安全。
- **多 p 值测试**（非重叠 148 值 / 偏移 8 值 / 变体 18 值）按 **min p** 判定（=所有子测试通过），
  故随机数据下非重叠通过率 ≈ (1−α)^148 ≈ 0.23，属正常而非失败。

## 结构攻击方法

- **代数**：CA→ANF→GF(2) 方程组；`algebraic.py` 的 XL 线性化求解（缩减轮/小规模可解），z3 做 SAT。
- **立方体**（Dinur–Shamir）：cube 求和 → 超多项式线性检验 → 恢复；适合低代数次数密码。
- **相关**：combiner 偏置、最佳线性逼近（Walsh 谱）、快速相关攻击复杂度（~n/c²）。
- **区分**：线性区分器信噪比 z=c√N，数据复杂度 ~1/c²；优势-vs-数据曲线。

## 前向/后向 + 可证明 + 后量子

- **后向安全** ⟺ 密钥流下一位不可预测性；**前向安全**看状态更新是否双射（双射→不安全）。
- **可证明**：Tier1 归约（PRF/数论/格，仅当架构嵌入困难问题）或 Tier2 严格安全论证（eSTREAM 方法）。
  **证明是人 + agent 协作的数学工作，工具只给脚手架，不伪造定理。**
- **后量子**：Grover 使 128→64、256→128 位等效；Shor 型攻击仅当含数论/格结构。

## 已知边界（诚实告知用户）

- NIST 已撤回；纯 Python 完整 battery（100×10⁶）较慢（BM 为 O(n²)），完整跑用 C STS/TestU01。
- FPGA 数据为定频估算模型，非真实综合；真实综合数据由用户本机回填。
- 参考密码适配器 5 个（ZUC-256 因无法逐 bit 验证而跳过）。

## 模块速查（analyzer/）

`ingest`(契约) `rng_nist`(15项+battery) `rng_testu01`(封装) `linear`(B-M) `stats`
`ca_model`(ANF/Walsh) `algebraic`(GF2+XL) `cube` `correlation` `distinguisher`
`security`(前向后向/可证明/Grover) `performance`(FPGA) `comparison`(文献对比) `report`/`report_builder`(图/表/报告)
