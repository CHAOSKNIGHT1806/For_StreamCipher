# 序列密码安全性分析 Skill + Python 工具 —— 完全使用与部署手册

> 傻瓜式、逐步可复制的完整手册。目标是：**在另一台电脑的 DeepSeekHarness 上，一个新 agent 照着做，
> 无需任何调试就能装好并用起来。**

---

## 一、这是什么

一个**可移植、通用**的序列密码（流密码）安全性分析工具，由两部分组成：

1. **Python 工具**（`D:\hardness\stream-cipher-analyzer`，或你解压到的任意目录）：负责"算"——
   随机性测试、线性复杂度、统计、结构攻击、安全评估、性能对比、报告生成。
2. **DSH skill**（`stream-cipher-security`）：负责"教 agent 怎么用"——注册进 DSH 后，
   任何会话 `skill stream-cipher-security` 即可加载方法论。

面向**任意能产生密钥流的算法**：元胞自动机（CA）、LFSR/NFSR/ARX 自研密码、或纯黑盒数据。

---

## 二、全部功能与使用范例

### 2.1 CLI 命令（共 7 个）

统一约定：`<密码>` 可以是**内置名**（`chacha20` / `trivium` / `grain128` / `salsa20` / `a51`），
也可以是**自定义适配器** `路径/文件.py:类名`。所有命令都在工具根目录下运行：

```bash
cd D:\hardness\stream-cipher-analyzer
```

#### ① `list` —— 列出内置参考密码
```bash
python cli.py list
# 输出：
#   chacha20   key=256 bits  iv=64 bits
#   trivium    key=80 bits   iv=80 bits
#   salsa20    key=256 bits  iv=64 bits
#   a51        key=64 bits   iv=22 bits
#   grain128   key=128 bits  iv=96 bits
```

#### ② `ca-screen` —— 元胞自动机线性退化筛查（第一道安全检查）
作用：对 CA 规则跑 Berlekamp-Massey，线性规则（rule 90/150/105 等）会秒判不安全。
```bash
python cli.py ca-screen --rules 90 30 150 110
# 输出示例：
#   rule  90: LC=    1  ratio=0.000  DEGENERATE (linear)
#   rule  30: LC= 2048  ratio=1.000  ok
#   rule 150: LC=    1  ratio=0.000  DEGENERATE (linear)
#   rule 110: LC=  519  ratio=0.253  ok
```
参数：`--rules`（规则号列表）、`--n`（胞元数，默认 64）、`--nbits`（默认 4096）。

#### ③ `compare` —— 文献对比表（10 个参考密码带引用）+ CA 攻击面清单
```bash
python cli.py compare
# 生成 results/comparison.csv/.tex 和 results/ca_attack_surface.csv/.tex
```

#### ④ `empirical` —— 实测黑盒对比（对已注册密码跑黑盒指标）
```bash
python cli.py empirical --nbits 20000
# 输出示例：
#   ChaCha20  LC= 1024  monobit_z=  0.368  runs_z=  0.142  ones=0.5013
#   Trivium   LC= 1024  ...
```
（注：内部用**非零**默认 key 0xA5，避免 A5/1、rule-30 这类全零 key 退化。）

#### ⑤ `analyze` —— 黑盒全分析（NIST + 线性复杂度 + 统计 + 图）
```bash
# 内置密码
python cli.py analyze chacha20 --nseq 10 --nbits 1000000

# 自定义算法
python cli.py analyze my_cipher.py:MyCipher --nseq 10 --nbits 1000000 --key 0123456789abcdef --outdir results
```
参数：`--nseq`（序列条数，NIST 默认 100 条才够显著）、`--nbits`（每条位数）、
`--key`（hex 密钥，缺省全零）、`--iv-mode`（counter/random/none）、`--profile-len`、`--outdir`。
输出：NIST 15 项通过率表 + 线性复杂度曲线 + 自相关图（`results/` 下 PDF/PNG/CSV/tex）。

#### ⑥ `testu01` —— TESTU01 电池（金标准，需 WSL + 驱动）
```bash
# 从密码生成密钥流跑 SmallCrush（快速筛查，~320 Mbit）
python cli.py testu01 chacha20 --battery smallcrush

# 直接读密钥流文件（.bits/.hex/.bin）
python cli.py testu01 --keystream-file keystream.bin --battery smallcrush

# BigCrush（金标准，~274 Gbit，建议云端）
python cli.py testu01 my_cipher.py:MyCipher --battery bigcrush
```
参数：`--battery`（smallcrush/crush/bigcrush/rabbit/alphabit）、`--keystream-file`、
`--nbits`（不填则按电池默认量）、`--key`、`--timeout`。

#### ⑦ `report` —— 完整管线 + 论文级报告（默认 IEEE TIFS 结构）
```bash
python cli.py report my_cipher.py:MyCipher --rule 30 --cells 64 --key-bits 128
# 输出 results/report.md + 全部图/表
```
`--rule`/`--cells` 用于 CA 结构分析；`--key-bits` 用于 Grover 后量子估算；
`--construction`（heuristic/prf/number_theory/lattice）决定可证明安全脚手架。

### 2.2 接入一个自己的密码（5 分钟）

继承 `CipherAdapter`，实现 `keystream`（唯一必需）：
```python
from analyzer.ingest import CipherAdapter

class MyCipher(CipherAdapter):
    name = "my-cipher"
    key_size = 128
    iv_size  = 96
    def keystream(self, key, iv, nbits):
        ...  # 返回 0/1 的 list（长度 nbits）
        return bits
    # 可选结构接口（解锁代数/立方体/前后向/可证明分析）：
    # def init(self, key, iv): ...
    # def step(self, state): ...
    # def output_function(self, state): ...
```
可运行模板：`docs/example_cipher.py`（rule-30 最小示例）。
```bash
python cli.py analyze docs/example_cipher.py:Rule30Cipher --nseq 5 --nbits 20000
```

### 2.3 Python API（analyzer/ 下 15 个模块）

| 模块 | 作用 | 一句话范例 |
|---|---|---|
| `ingest` | 适配器契约 + 密钥流读取 | `read_bits_file('k.bin')` |
| `linear` | Berlekamp-Massey 线性复杂度 | `berlekamp_massey(bits)` → `(L, C)` |
| `stats` | 频率/自相关/χ²/游程 | `summary_stats(bits)` |
| `rng_nist` | NIST 15 项 + 多序列 battery | `run_battery(seqs)` |
| `rng_testu01` | TESTU01 封装 | `run_testu01(bits, 'smallcrush')` |
| `ca_model` | CA→ANF、线性判别、Walsh | `screen_linear_degeneration(30)` |
| `algebraic` | GF(2)+XL 求解 + CA 方程组 | `solve_ca(rule, n, steps, taps, ks)` |
| `cube` | 立方体攻击 | `recover_linear_superpoly(f, cube, nvars)` |
| `correlation` | 相关攻击 | `best_linear_approximation(table)` |
| `distinguisher` | 区分攻击 | `distinguisher_curve(c, n_max)` |
| `security` | 前向/后向 + 可证明脚手架 + Grover | `forward_backward_summary(rule=30, n=64, key_bits=128)` |
| `performance` | 定频 FPGA 估算 + 软件基准脚手架 | `ca_fpga_estimate(n_cells, out_bits)` |
| `comparison` | 参考密码 + CA 攻击面（带引用） | `comparison_table()` |
| `report` | 图（PDF/PNG）+ 表（LaTeX/CSV） | `nist_report_table(battery)` |
| `report_builder` | 报告组装（IEEE TIFS） | `build_report(name, ...)` |

### 2.4 DSH skill 的用法

注册成功后，在任何 DSH 会话里：
```text
用户：帮我分析这个流密码的安全性
agent：（调用 skill stream-cipher-security，加载方法论，然后跑上面的 CLI 命令）
```
skill 只是"方法论 + 命令速查"；真正的计算由 Python 工具完成。

---

## 三、依赖与环境

### 3.1 Tier 0 —— 必需（纯 Python，几乎所有功能都靠它）

```bash
pip install numpy scipy sympy matplotlib pycryptodome
```
> DeepSeekHarness 通常已预装这五个（本机就是预装的）。装之前可先 `python -c "import numpy, scipy, sympy, matplotlib, Crypto"` 验证。

### 3.2 可选 —— 增强包（z3 做 SAT、galois 做 GF、pandas 做表）

```bash
pip install pandas statsmodels galois z3-solver
```
> 这些是**便利项，非必需**：不装也能跑全部核心功能（表格用 stdlib csv 生成、XL 用纯 Python）。
> **在 DeepSeekHarness 的沙箱里，`pip install` 会因临时目录写入被拒而失败** —— 见 §5.1 的绕过方案。

### 3.3 Tier 1 —— 可选（TESTU01 / C 软件基准 / SAT / Gröbner，需 WSL）

仅当你需要 **TESTU01 金标准**、**C 语言软件吞吐基准**、或更快的 SAT 求解时：
见 `docs/environment.md`（WSL 装 Ubuntu → `apt install testu01-bin libtestu01-0-dev` → 编译驱动）。

---

## 四、移植到另一台电脑的 DeepSeekHarness

> 先搞清楚两个目标位置：
> 1. **工具目录** → 解压到 harness 的**会话工作区**（agent 的 working directory；本机是 `D:\hardness`）。
> 2. **skill 目录** → 放到用户技能根 `C:\Users\<用户名>\.dsh\skills\`（**不是**工作区）。

### 4.1 离线安装（复制压缩包）

**打包（在原电脑）**：
```powershell
# 在 D:\hardness 下，把整个工具目录打包（可含 vendor/ 让新电脑免装增强包）
Compress-Archive -Path D:\hardness\stream-cipher-analyzer -DestinationPath D:\stream-cipher-analyzer.zip
```

**解压（在新电脑）**：
```powershell
# 1. 解压到 harness 会话工作区（本机示例是 D:\hardness，换成新电脑的实际工作区）
Expand-Archive -Path D:\stream-cipher-analyzer.zip -DestinationPath D:\hardness
# 2. 验证
cd D:\hardness\stream-cipher-analyzer
python cli.py list
```

**注册 skill（在新电脑）**：
```powershell
# 把仓库里现成的 skill/SKILL.md 复制到用户技能根（目录名必须叫 stream-cipher-security）
New-Item -ItemType Directory -Force -Path "$HOME\.dsh\skills\stream-cipher-security" | Out-Null
Copy-Item "D:\hardness\stream-cipher-analyzer\skill\SKILL.md" "$HOME\.dsh\skills\stream-cipher-security\SKILL.md"
# ⚠️ 关键：打开 SKILL.md，把里面所有 "D:\hardness\stream-cipher-analyzer" 改成新电脑的实际工具路径！
```
> 仓库里已含带 YAML 前端的 `skill/SKILL.md`（可直接注册），§4.3 也给了完整模板作对照。

### 4.2 在线安装（GitHub 拉取）

```powershell
# 1. 克隆到会话工作区
cd D:\hardness
git clone https://github.com/CHAOSKNIGHT1806/For_StreamCipher.git stream-cipher-analyzer
# 2. 装 Tier 0 依赖（若 harness 没预装）
cd stream-cipher-analyzer
pip install -r requirements.txt
# 3. 验证
python cli.py list
```

### 4.3 注册 DSH skill（离线/在线都要做）

在 `$HOME\.dsh\skills\stream-cipher-security\SKILL.md` 放下面这个文件（注意把 `D:\hardness\stream-cipher-analyzer` 改成你的实际路径）：

```markdown
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
---

# 序列密码（流密码）安全性分析

工具在 D:\hardness\stream-cipher-analyzer。命令：
python cli.py list / ca-screen / compare / empirical / analyze <密码> / testu01 <密码> --battery smallcrush / report <密码>
接入新密码：继承 analyzer.ingest.CipherAdapter，实现 keystream(key,iv,nbits)。
判定：B-M 线性复杂度≈n/2 为随机，线性 CA 规则 LC 极低→不安全；NIST 已撤回需配 TestU01。
详见仓库 docs/MANUAL.md 与 skill/stream-cipher-security.md。
```

### 4.4 验证安装成功（一条命令）

```bash
cd D:\hardness\stream-cipher-analyzer
python tests/run_all.py        # 4 套冒烟测试全 PASS
python tests/test_ciphers.py   # 参考密码健全性
python tests/test_nist15.py    # NIST 15 项 battery
python cli.py list             # 列出 5 个内置密码
```
全部无报错即安装成功。

---

## 五、避坑指南（我们踩过的弯路，新 agent 必读，照做零调试）

1. **pip 在沙箱里装不上增强包**（报 `Permission denied ... .whl.metadata`）。
   原因：沙箱禁止向 `tempfile.mkdtemp()` 建的临时目录写文件。**不要反复试 pip**。
   方案：用仓库里的 `scripts/install_deps.py`（urllib 直接下 wheel + zipfile 解压到 `vendor/`）：
   ```bash
   python scripts/install_deps.py
   ```
   `cli.py` 会自动把 `vendor/` 加入 sys.path。或者直接打包时把 `vendor/` 一起拷过去。

2. **WSL 命令报 `E_ACCESSDENIED`**：沙箱进程默认无法触达 WSL 服务。运行任何 `wsl ...` 都要
   带 `sandbox_permissions: danger-full-access`（并附一句 justification），用户批准后即可。

3. **TestU01 别从源码下载**（`simul.iro.umontreal.ca` 的 tar.gz 已 404）。用 apt：
   ```bash
   sudo apt update && sudo apt install -y testu01-bin libtestu01-0-dev
   ```
   电池程序在库函数 `bbattery_*` 里，需编译仓库自带的驱动：
   ```bash
   gcc -O2 -o /root/testu01_driver /mnt/d/hardness/stream-cipher-analyzer/analyzer/testu01_driver.c \
       -ltestu01 -ltestu01mylib -ltestu01probdist -lm
   ```

4. **PowerShell 引号坑**：在 `wsl bash -lc "..."` 里别写 `$(nproc)`（PowerShell 会当子表达式执行而报错），
   用固定 `-j4`；整条 bash 命令里避免出现 `$`（否则被 PowerShell 插值）。

5. **GitHub PAT 要写权限**：细粒度 PAT（`github_pat_` 开头）需把仓库 `Contents` 设为 **Read and write**；
   或直接用经典 PAT（`ghp_` 开头）勾 `repo` scope。读权限会导致 `push` 报 403。

6. **skill 里硬编码了工具路径**：换电脑后必须把 SKILL.md 里的 `D:\hardness\stream-cipher-analyzer`
   改成实际路径，否则 skill 加载后 agent 会去错目录。

7. **全零 key 退化**：A5/1 和 rule-30 CA 在全零 key 下会输出全零密钥流（LC=0）。
   这是真实弱密钥现象，工具会正确报告；做**公平对比**时用非零 key（`empirical` 已内置 0xA5）。

8. **测试规模**：NIST 默认 100 条×10⁶ bit 才够显著；`testu01 smallcrush` 需 ~320 Mbit、
   `bigcrush` 需 ~274 Gbit（云端）。纯 Python 完整 NIST battery 较慢（BM O(n²)），属正常。

---

## 六、一键验证脚本

把下面存成 `verify.py` 放工具目录，跑一遍全绿即万事俱备：
```bash
python tests/run_all.py && python tests/test_ciphers.py && python tests/test_nist15.py && python cli.py list && echo ALL_OK
```
