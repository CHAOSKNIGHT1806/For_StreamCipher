# Stream Cipher Security Analyzer

一个**可移植、通用、带说明文档**的序列密码（流密码）安全性分析工具 + Skill 组合。

面向任意能产生密钥流的算法通用（不绑定某个具体密码）：基于元胞自动机（CA）的自研流密码、
传统 LFSR/NFSR/ARX 流密码（对比基线）、或纯黑盒算法。

> 📖 **完全使用与部署手册**（傻瓜式，含全部功能范例 + 离线/在线移植 + 避坑指南）：
> [`docs/MANUAL.md`](docs/MANUAL.md)

## 能力总览

| 需求 | 模块 | 自动化 |
|---|---|---|
| NIST SP 800-22 / TESTU01 | `rng_nist` / `rng_testu01` | 全自动（NIST 已实测；TestU01 需 WSL） |
| Berlekamp-Massey 线性复杂度 | `linear` | 全自动 |
| 统计分析 | `stats`（频率/自相关/χ²/游程） | 全自动 |
| 区分 / 代数 / 立方体 / 相关攻击 | `distinguisher` / `algebraic` / `cube` / `correlation` | 半自动（缩减轮/小规模可解） |
| 前向 / 后向安全 | `security`（状态双射性/单向性） | 半自动 |
| 可证明安全 / 后量子 | `security`（Tier1/2 脚手架 + Grover） | 脚手架（证明=人+agent 协作） |
| 性能（软件 + FPGA） | `performance`（定频 FPGA 估算 + C 基准脚手架） | 半自动 |
| 带文献引用的对比分析 | `comparison`（10 个参考密码 + CA 攻击面清单） | 全自动 |
| 论文级图表 + 报告 | `report` / `report_builder`（IEEE TIFS 结构） | 模板化自动 |

## 目录结构

```
stream-cipher-analyzer/
├── skill/stream-cipher-security.md   # 方法论（管线/契约/阈值/攻击套路/证明工作流/MATLAB 翻译）
├── analyzer/                         # 工具包（见上表）
├── ciphers/                          # 内置参考密码适配器
├── docs/                             # environment.md、literature-scan.md、example_cipher.py
├── tests/                            # 冒烟测试（smoke1..4）
├── cli.py                            # 命令入口
├── requirements.txt / pyproject.toml / LICENSE
└── results/                          # 输出（图/表/报告，已 gitignore）
```

## 安装

**Tier 0（必需，纯 Python）**：
```bash
pip install numpy scipy sympy matplotlib pycryptodome
```

**Tier 1（可选，需 WSL）**：`gcc` + TestU01（BigCrush）、C 软件基准、SAT/Gröbner —— 见
[`docs/environment.md`](docs/environment.md)。

## 快速开始

```bash
python cli.py list                              # 列出内置密码
python cli.py ca-screen --rules 90 30 150 110   # CA 线性退化筛查
python cli.py compare                            # 生成参考密码对比表
python cli.py analyze chacha20 --nseq 10 --nbits 1000000
python cli.py analyze 你的算法.py:类名 --nseq 10 --nbits 1000000
python cli.py report  你的算法.py:类名 --rule 30 --cells 64 --key-bits 128
```

最后一条命令跑完整管线并产出 `results/report.md` + 全部图/表。

## 接入一个自己的密码（5 分钟）

只需继承 `CipherAdapter` 并实现 `keystream(key, iv, nbits) -> list[int]`：

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

实现 `keystream` 即可解锁全部黑盒测试；再实现 `init` / `step` / `output_function`
解锁结构攻击与安全层。完整可运行示例见 [`docs/example_cipher.py`](docs/example_cipher.py)；
契约与方法论详见 [`skill/stream-cipher-security.md`](skill/stream-cipher-security.md)。

## 可移植性

本项目**零宿主机依赖**（除 Python 解释器与可选 WSL）：整个目录复制/解压到任意机器的
harness 工作目录即可用，无需重新构建。发布到 GitHub 后他人 `git clone` 即可；也可
`pip install -e .` 得到 `stream-analyzer` 命令。

## 当前状态

- [x] 全部 8 层能力（黑盒 / 结构 / 安全 / 性能 / 对比 / 报告）
- [x] NIST SP 800-22 **15/15**（含 148 模板非重叠、重叠、随机偏移、偏移变体）
- [x] 参考密码适配器：ChaCha20 / Trivium / Grain-128 / Salsa20 / A5/1（ZUC-256 因无法逐 bit 验证而跳过）
- [x] 4 冒烟套件 + 密码健全性 + NIST15 测试全绿
- [ ] TESTU01 端到端 + C 软件基准（待 WSL）
- [ ] GitHub 发布（待账号/PAT）
