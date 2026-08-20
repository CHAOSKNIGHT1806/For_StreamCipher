# 使用说明 / Usage Guide

一个可移植、通用的序列密码（流密码）安全性分析工具。零宿主机依赖（除 Python 与可选 WSL），
整个目录复制/解压即可用。

## 环境

```bash
# Tier 0（必需）
pip install numpy scipy sympy matplotlib pycryptodome

# Tier 1（可选，需 WSL）：gcc + TestU01、C 软件基准、SAT/Gröbner
# 见 docs/environment.md
```

## 快速开始（3 条命令）

```bash
# 1. 列出内置参考密码
python cli.py list
#   chacha20   key=256 bits  iv=64 bits
#   trivium    key=80 bits   iv=80 bits
#   salsa20    key=256 bits  iv=64 bits
#   a51        key=64 bits   iv=22 bits
#   grain128   key=128 bits  iv=96 bits

# 2. 元胞自动机线性退化筛查（第一道安全检查）
python cli.py ca-screen --rules 90 30 150 110
#   rule  90: LC=    1  ratio=0.000  DEGENERATE (linear)
#   rule  30: LC= 2048  ratio=1.000  ok
#   ...

# 3. 对某个密码跑完整黑盒分析
python cli.py analyze chacha20 --nseq 10 --nbits 1000000
```

## 实例：分析你自己的算法

把你的密码实现成一个 `CipherAdapter`（模板见 `docs/example_cipher.py`），
假设存为 `my_cipher.py`，类名 `MyCipher`：

```bash
# 黑盒全分析：NIST + 线性复杂度 + 统计 + 图
python cli.py analyze my_cipher.py:MyCipher --nseq 10 --nbits 1000000 --outdir results

# 若它是 CA 结构，加结构/安全/性能分析 + 生成报告
python cli.py report my_cipher.py:MyCipher --rule 30 --cells 64 --key-bits 128
#   → results/report.md（IEEE TIFS 结构）+ 全部图/表
```

`docs/example_cipher.py` 是一个**可直接跑**的最小 CA 流密码（rule-30），
复制改 `keystream`/`init`/`step` 即可：

```bash
python cli.py analyze docs/example_cipher.py:Rule30Cipher --nseq 5 --nbits 20000
```

## 实例：对比分析

```bash
# 文献对比表（10 个参考密码带引用）+ CA 攻击面清单
python cli.py compare
#   → results/comparison.csv/.tex, results/ca_attack_surface.csv/.tex

# 实测对比（对已注册密码跑黑盒指标）
python cli.py empirical --nbits 20000
#   ChaCha20  LC= 1024  monobit_z=  0.368  ...
#   Trivium   LC= 1024  ...
```

## 接入新密码的契约（最小实现）

```python
from analyzer.ingest import CipherAdapter

class MyCipher(CipherAdapter):
    name = "my-cipher"
    key_size = 128
    iv_size  = 96
    def keystream(self, key, iv, nbits):
        ...  # 返回 0/1 的 list 或 bytes，长度 nbits
        return bits
```

只实现 `keystream` 即可解锁全部黑盒测试；再实现 `init`/`step`/`output_function`
解锁代数/立方体/相关攻击与前后向安全。完整契约与分析方法论见
`skill/stream-cipher-security.md`。

## 输出

| 产物 | 位置 |
|---|---|
| 图（PDF 矢量 + PNG） | `results/*.pdf` `results/*.png` |
| 表（LaTeX + CSV） | `results/*.tex` `results/*.csv` |
| 报告（markdown，IEEE TIFS 结构） | `results/report.md` |

## 测试

```bash
python tests/run_all.py        # 4 套冒烟测试
python tests/test_ciphers.py   # 参考密码健全性
python tests/test_nist15.py    # NIST 15 项 battery
```

## 已知边界（诚实说明）

- NIST SP 800-22 已于 2022-11 被 NIST **撤回**；报告中已注明，建议配 TESTU01（需 WSL）。
- 纯 Python 完整 battery（100×10⁶）较慢（线性复杂度测试 BM 为 O(n²)）；完整跑用 C STS/TestU01。
- FPGA 数据为**定频估算模型**，非真实综合。
- 可证明安全为**脚手架**（Tier1/2 模板 + 检查清单），证明本身是人 + agent 协作的数学工作。
