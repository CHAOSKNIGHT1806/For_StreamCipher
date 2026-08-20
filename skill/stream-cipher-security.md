# Skill：序列密码（流密码）安全性分析

> 本文件是**方法论 + 编排手册**：指导任意会话中的 agent 对任意流密码执行从黑盒随机性
> 到可证明/后量子安全的全套分析，并产出论文级英文报告（默认 IEEE TIFS）。
> 计算由 `../analyzer/` 下的 Python 工具完成；本文件管"怎么分析、判什么、写什么"。

---

## 1. 分析管线总览

按顺序执行，每层产物都沉淀到 `results/`，最终汇入报告：

```
① 算法接入        → 适配器（黑盒 keystream；可选结构 init/step/output）
② 黑盒随机性      → NIST SP800-22 + TESTU01 三个 battery
③ 线性与统计      → B-M 线性复杂度曲线 + 频率/自相关/χ²/游程
④ 结构攻击        → 代数(SAT/Gröbner/XL) + 立方体 + 相关 + 区分
⑤ 安全性质        → 前向/后向 + 可证明安全脚手架 + 后量子(Grover)
⑥ 性能与对比      → 软件吞吐 + 定频 FPGA 估算 + 文献对比表(带引用)
⑦ 报告           → 图/表/正文，IEEE TIFS 模板
```

- **只有黑盒接口** → 执行 ②③⑥（性能黑盒部分），并诚实注明结构层未做。
- **补了结构接口** → 解锁 ④⑤ 及 ⑥ 的 FPGA 估算。

---

## 2. 关键判据（阈值速查）

### 2.1 NIST SP 800-22
- **⚠️ 该标准已于 2022-11 被 NIST 撤回**。照跑（满足惯例），但报告中注明撤回事实，
  并补 TESTU01 BigCrush 作为金标准。
- 默认 100 条 × 10⁶ bit 序列；每条 15 项测试；通过率阈值（二项分布，显著性 0.01）：
  `[ p̂-3√(p̂(1-p̂)/m) , p̂+3√(p̂(1-p̂)/m) ]`，p̂=1-0.01=0.99，m=序列数。
- p 值均匀性：对每条测试的 100 个 p 值做 χ² 均匀性检验（10 组）。
- **15 项已全部实现**（含 148 模板非重叠、重叠模板、随机偏移、偏移变体，常量来自 NIST STS 2.1.2）。
- 多 p 值测试（非重叠 148 值 / 偏移 8 值 / 变体 18 值）按 NIST 判据取 **min p**（=所有子测试通过），
  故随机数据下非重叠通过率 ≈ (1−α)^148 ≈ 0.23，属正常而非失败。
- ⚠️ 纯 Python 完整 battery（100×10⁶）较慢（线性复杂度测试 BM 为 O(n²)）；完整跑用 C STS / TestU01（WSL），
  Python 版用于快速筛查。

### 2.2 TESTU01
- SmallCrush（快筛）→ Crush → **BigCrush**（金标准，~2³⁸ bit 量级，耗时以小时计）。
- 判定：p 值落在 (1e-10, 1-1e-10) 之外即"明显失败"。

### 2.3 线性复杂度（B-M）
- 随机序列长度 n 的期望线性复杂度 ≈ n/2；曲线应贴近 n/2 直线。
- **线性规则退化**（CA 用 rule 90/150/105 等线性规则）→ B-M 秒出极低 LC → 立即判不安全。

---

## 3. 密码适配器契约（接入新密码）

```python
class CipherAdapter:
    name = "unnamed"
    key_size = 0      # bits
    iv_size  = 0      # bits
    state_size = 0    # bits

    # 黑盒层唯一必需接口：nbits → 0/1 list 或 bytes
    def keystream(self, key, iv, nbits): ...

    # ---- 结构层（可选，解锁 ④⑤⑥-FPGA）----
    def init(self, key, iv): ...                 # -> state
    def step(self, state): ...                   # -> (state', output_bits)
    def output_function(self, state): ...        # -> output_bits（若与 step 分离）
    # CA 额外提供（供 ca_model 自动建模）：
    # rule_table: 8 个 3-邻域输入 → 输出；neighborhood_radius: r
    # boundary: 'periodic' | 'null' | 'reflective'
```

**接入流程（5 分钟）：**
1. 新建 `ciphers/<name>.py`，继承 `CipherAdapter`，实现 `keystream`（必）与结构接口（可选）。
2. 若算法源码是 **MATLAB**：先由 agent 逐运算翻译为等价的 Python/numpy（**保持算法与运算
   过程不变**），再包成适配器。
3. **翻译正确性验证**（见 §8）：向用户索要"同一 seed + 前若干胞元/bit 的密钥流"，比对
   翻译版输出，完全一致才继续。

**内置参考密码**（`ciphers/`，用于对比基线）：Trivium、Grain-128(AEAD)、ZUC-256、
SNOW 3G、HC-128、Rabbit、Salsa20/12、ChaCha20、RC4、A5/1。

---

## 4. 结构攻击方法论

### 4.1 代数攻击
1. `ca_model`：把 CA/LFSR/NFSR 写成 GF(2) 上方程组（未知=初态/密钥位，已知=密钥流位）；
   CA 局部规则 → 稀疏低次 ANF。
2. 求解器三级：SAT（CryptoMiniSat，经 `pycryptosat`）→ Gröbner（Sage）→ XL（`galois` 线性化）。
3. **只对缩减轮/小规模可解**；完整规模输出"求解时间/复杂度 vs 轮数"增长曲线。

### 4.2 立方体攻击（Dinur–Shamir）
- 对输出 ANF 求 cube 和 → 判断 superpoly 线性 → 恢复超多项式。
- 适合低代数次数密码（缩减轮 Trivium/Grain、低次 CA）。
- cube 搜索：随机 + 启发式；报告"cube 大小 vs 成功恢复率"。

### 4.3 相关/快速相关攻击
- 检测抽头偏置、组合器与状态位的线性/低次相关；对"单胞元抽头"重点查信息泄漏。

### 4.4 区分攻击
- 实现**文献已知区分器**（针对具体密码）或**用户自定义统计区分器**；
- 输出"优势 ε vs 数据量 D"曲线。

---

## 5. 前向 / 后向安全

- **后向安全**（历史→未来）：等价于密钥流作为 PRG 的**下一位不可预测性**。
- **前向安全**（未来→历史）：看状态更新是否**双射（可逆）**——可逆则"由未来推过去"在
  信息论上不安全；看状态更新是否**不可逆丢熵**；看**重同步/IV 注入**是否泄漏状态差分。
- 工具动作：`security.py` 检验状态更新在 GF(2) 上的双射性（可逆矩阵）、熵变化、重同步差分实验。

---

## 6. 可证明安全 & 后量子

### 6.1 两层目标（诚实原则）
- **Tier 1 — 归约证明**：安全归约到公认困难问题（LWE/LPN/二次剩余/离散对数，或
  PRG/PRF 标准定义 + Yao/HILL/Goldreich–Levin 定理）。**仅当架构嵌入困难问题时才可能**。
- **Tier 2 — 严格安全论证 + 充分密码分析**：eSTREAM 方法论，AES/ChaCha/Trivium 实际拥有的
  形态，**这是更现实的目标**。

### 6.2 推导管线（人 + agent 协作）
1. 形式化 F:(K,IV)→密钥流；用 sympy 在 GF(2) 上符号化推导状态更新 T 与输出函数 O。
2. 验证 T 双射性 / 熵压缩 / ANF 代数次数增长。
3. 把每个密钥流位表达为 seed 的函数，判断是否落入已知困难函数族（能归约走 Tier 1）。
4. 归约不成 → 把 Tier 2 做严格：列全部攻击类别 → 逐一"抵抗性论证 + 实验数据" → 标注未决问题。

> 用户原需求的三项（密钥流→初态、历史→未来、已知密钥→历史）**恰好对应标准 PRG 安全定义**
> （下一位不可预测性 ⟺ 伪随机性，Yao），须按此框架陈述，不可声称不成立的定理。

### 6.3 后量子
- 分类底层困难问题：Shor 型（因子/离散对数/格）→ 不安全；否则 Grover 平方加速。
- Grover 表：128 位 → ~64 位等效；256 位 → ~128 位等效。结论落点"建议 ≥256 位密钥"。

---

## 7. 性能 & 对比

- **软件吞吐**：必须 C 实现（`performance.py` 调 WSL 下 gcc 编译后的可执行），Python 不作为吞吐基准。
- **FPGA/ASIC**：**定频估算模型**（默认 100 MHz 表头注明）：从结构推 LUT/寄存器/关键路径/面积，
  归一化横向对比；真实综合数据由用户本机回填。
- **文献对比**：`web_search`/`arxiv` 取先验 + 攻击记录；`kb_ingest`/`kb_search`/`kb_rag`
  检索"X 的最佳已知攻击/吞吐/面积"带引用；`zotero` 管理文献 → `export_bibliography` 出 BibTeX。
- **对比指标默认**：安全级别、状态/密钥/IV 位宽、吞吐、面积、延迟、最佳攻击复杂度、代数次数增长。

---

## 8. 验证协议 & 运行管理

### 8.1 MATLAB 翻译正确性
- agent 翻译 MATLAB→Python 后，**必须**向用户索要：同一 seed 下"前若干胞元/bit 的密钥流"，
  与翻译版输出逐 bit 比对，完全一致方视为翻译通过。

### 8.2 密钥流生成与磁盘
- 流式生成、**测完即删**（本地省空间）；种子策略与位序（MSB/LSB-first）**每算法分析时与用户确认**。
- 位序在 `ingest.py` 做参数化（默认 LSB-first 字节打包）。

### 8.3 云运行
- 本地过慢 → 询问用户是否切云（付费大平台，agent **逐步协助配置**）；
  运行中用户可询问进度与预计完成时间。

---

## 9. 报告结构（默认 IEEE TIFS，可随投稿期刊模板调整）

```
1. Introduction & Related Work（含 CA 先验定位）
2. Algorithm Specification（形式化 F:(K,IV)→keystream）
3. Randomness & Statistical Analysis（NIST/TestU01/B-M 图表）
4. Structural Cryptanalysis（代数/立方体/相关/区分 + 复杂度曲线）
5. Forward/Backward Security（状态更新性质）
6. Security Argument（Tier 1 归约 或 Tier 2 论证；Post-Quantum/Grover）
7. Performance & Comparison（软件 + FPGA 估算 + 文献对比表带引用）
8. Conclusion
```

每章产出的表格用 LaTeX + CSV 双份、图用 PDF 矢量 + PNG。

---

## 10. MATLAB 源码的翻译与验证（用户算法常为 MATLAB）

用户算法多以 MATLAB 编写（矩阵运算快）。agent 必须：

1. **逐运算翻译**为等价 Python/numpy，**保持算法与运算过程不变**：
   - 数组 → numpy 数组（MATLAB 默认 double，位运算需显式 `uint8`/`uint64` 语义）；
   - 逐元素运算（`.+ .- .* ./ .^`）→ numpy 向量化（`+ - * / **`；注意 MATLAB `/` 是右除、`./` 才是逐元素）；
   - 位运算（`bitand bitor bitxor bitget bitset`）→ Python `& | ^`（先转 int）；
   - **1-based（MATLAB）→ 0-based（Python）索引**是最常见 bug 源；
   - `mod(a,m)` 对负数结果两者不同，密码学里须用 `(a % m + m) % m`；
   - 循环体先原样保留（保真优先），避免"优化"改变运算顺序。
2. **翻译正确性验证（强制）**：向用户索要「同一 seed 下前若干胞元/bit 的密钥流」，与翻译版输出**逐 bit 比对**，完全一致才继续（用户明确要求以此判定翻译是否准确）。
3. 通过后再包成 `CipherAdapter`（见 §3），先跑 `ca-screen` 与黑盒测试。

---

## 11. 接入新密码模板

见 `docs/example_cipher.py`（一个可运行的 CA 流密码适配器示例）。复制后改
`keystream` / `init` / `step` 即可，然后：

```bash
python cli.py analyze docs/example_cipher.py:Rule30Cipher
```
