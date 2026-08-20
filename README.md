# Stream Cipher Security Analyzer

一个**可移植、通用、带说明文档**的序列密码（流密码）安全性分析工具 + Skill 组合。

面向三类对象（算法类型）通用，而非绑定某个具体算法：

- 基于元胞自动机（CA）的自研流密码；
- 传统 LFSR/NFSR/ARX 流密码（用于对比）；
- 任意能产生密钥流的算法（纯黑盒）。

## 能力总览

| 层 | 内容 | 自动化程度 |
|---|---|---|
| 黑盒随机性 | NIST SP 800-22、TESTU01（SmallCrush/Crush/BigCrush） | 全自动 |
| 线性与统计 | Berlekamp-Massey 线性复杂度、频率/自相关/χ²/游程 | 全自动 |
| 结构攻击 | 代数攻击（SAT/Gröbner/XL）、立方体、相关、区分攻击 | 半自动（缩减轮/小规模可解） |
| 安全性质 | 前向/后向安全、可证明安全脚手架、后量子 Grover 估算 | 半自动 |
| 性能对比 | 软件吞吐 + 定频 FPGA 估算 + 带文献引用的对比表 | 半自动 |
| 报告 | 论文级图表 + LaTeX 表 + 英文报告模板（默认 IEEE TIFS） | 模板化自动 |

## 目录结构

```
stream-cipher-analyzer/
├── skill/stream-cipher-security.md   # 方法论（如何分析、判什么、写什么）
├── analyzer/                         # Python 工具包
│   ├── ingest.py                     # 密钥流读取 + 密码适配器契约
│   ├── linear.py                     # Berlekamp-Massey / 线性复杂度
│   ├── stats.py                      # 基础统计分析
│   ├── rng_nist.py                   # NIST SP 800-22（纯 Python）
│   ├── rng_testu01.py                # TESTU01 封装（需 WSL/C）
│   ├── ca_model.py                   # CA → ANF / GF(2) 方程组建模
│   ├── algebraic.py                  # SAT / Gröbner / XL
│   ├── cube.py                       # 立方体攻击
│   ├── correlation.py                # 相关 / 快速相关攻击
│   ├── security.py                   # 前向/后向、可证明脚手架、Grover
│   ├── performance.py                # 软件基准 + 定频 FPGA 估算
│   └── report.py                     # 图 / 表 / 报告模板
├── ciphers/                          # 内置参考密码适配器（Trivium/Grain/ZUC/ChaCha/...）
├── tests/                            # 单元测试 + 冒烟测试
├── docs/                             # 报告模板、期刊模板说明
└── results/                          # 输出（LaTeX 表、PDF/PNG 图、报告）
```

## 安装

纯 Python 依赖（Python ≥ 3.10，推荐 3.12）：

```bash
pip install numpy scipy sympy matplotlib pycryptodome pandas statsmodels galois z3-solver
```

TESTU01 / C 软件基准需要 **WSL（Ubuntu）+ gcc**，见 `docs/environment.md`（规划中）。

## 快速开始

```python
from analyzer.ingest import CipherAdapter

class MyCipher(CipherAdapter):
    name = "my-cipher"
    key_size = 128
    iv_size  = 96
    def keystream(self, key, iv, nbits):
        ...  # 返回 0/1 的 list 或 bytes
        return bits
```

只需实现 `keystream(key, iv, nbits)` 即可解锁全部黑盒测试。要解锁结构攻击，
再实现 `init` / `step` / `output_function`（见 skill 文档第 3 节）。

## 可移植性

本项目**零宿主机依赖**（除 Python 解释器与可选 WSL）：整个目录复制/解压到任意
机器的 harness 工作目录即可用，无需重新构建。发布到 GitHub 后他人 `git clone` 即可。

## 当前状态

- [x] 脚手架 + 适配器契约 + ingest/linear/stats
- [ ] NIST SP 800-22 / TESTU01 / 结构层 / 安全层 / 性能层 / 报告层（开发中）
- [ ] 内置参考密码适配器（开发中）
