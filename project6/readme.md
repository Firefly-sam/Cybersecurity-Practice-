### Private Intersection-Sum-with-Cardinality协议实现

**Private Intersection-Sum-with-Cardinality** 协议（由 Google 团队提出），用于安全计算广告转化率等场景。该协议的核心是 **DDH-based Private Intersection-Sum Protocol**，协议目标是：两方（P1 和 P2）安全计算交集大小（Cardinality）和关联值总和（Sum），而不泄露其他信息。

------

### 1. 协议概述

协议基于 **Decisional Diffie-Hellman (DDH)** 假设和 **加性同态加密**，实现半诚实安全模型（Semi-Honest Security）。核心流程分 4 个回合：

- **Setup**: 初始化群、哈希函数和加密密钥。
- **Round 1 (P1)**: P1 发送哈希值并加密。
- **Round 2 (P2)**: P2 处理数据并返回加密结果。
- **Round 3 (P1)**: P1 计算交集和总和。
- **Output (P2)**: P2 解密得到结果。
   协议输出：P1 获交集大小，P2 获交集大小和总和。

------

### 2. 关键参数

实现前需配置以下组件：

- **群 (Group G)**: 使用 NIST 椭圆曲线 `prime256v1`（secp256r1），质数阶，确保 DDH 假设成立。Python 库：`cryptography` 或 `ecdsa`。

- **哈希函数 (H)**: SHA-256，映射标识符到群元素（需哈希到曲线，Hashing-to-Curve）。使用随机种子防时序攻击。

- **加性同态加密 (AHE)**: Paillier 加密（Section 3.2），768 位素数，Damgård-Jurik 优化（s=3）。Python 库：`phe`（Paillier 库）。

- 

  输入参数

  - P1 输入集: `V = {v_i}`（标识符，e.g., 用户 ID）。
  - P2 输入集: `W = {(w_j, t_j)}`（标识符和整数值，e.g., 广告点击次数）。
  - 安全参数: λ = 128（标准）。

- **其他**: 数据需随机洗牌（Shuffle）以隐藏顺序。

------

### 3. 分步实现

分步实现逻辑如下。假设 P1 和 P2 为独立模块，通信通过函数调用模拟。

#### **Step 0: Setup**

- P1 和 P2 协商群 `G`、哈希函数 `H`，和标识符空间 `U`。
- P1 生成随机指数 `k1` ∈ `G`。
- P2 生成随机指数 `k2` ∈ `G`，并生成 Paillier 密钥对 `(pk, sk)`，发送 `pk` 给 P1。

```
from cryptography.hazmat.primitives.asymmetric import ec
from phe import paillier

# P2 初始化
curve = ec.SECP256R1()
private_key_p2 = ec.generate_private_key(curve)  # 实际协议中 k2 为标量，此处简化
k2 = private_key_p2.private_numbers().private_value  # 获取标量值
public_key_phe, private_key_phe = paillier.generate_paillier_keypair(n_length=768)  # Paillier 密钥
```

#### **Step 1: Round 1 (P1)**

- P1 对每个 `v_i` 计算 `H(v_i) → g_i ∈ G`，然后计算 `g_i^{k1}`。
- 将结果洗牌后发送给 P2。

```
import hashlib
import random

def hash_to_curve(identifier, seed):
    # 简化示例: SHA-256 哈希并映射到曲线点 (实际需完整 Hashing-to-Curve)
    h = hashlib.sha256((str(seed) + str(identifier)).encode()).digest()
    # 此处省略完整映射逻辑 (参考文档: 使用 OpenSSL 实现)
    return h  # 返回字节串，代表点

# P1 逻辑
k1 = random.randint(1, curve.order)  # 随机 k1
seed = random.randint(1, 1000000)  # 公共随机种子
hashed_points = [hash_to_curve(v_i, seed) for v_i in V]
exponentiated_points = [pow(int.from_bytes(point, 'big'), k1, curve.order) for point in hashed_points]  # 计算 g_i^{k1}
random.shuffle(exponentiated_points)  # 洗牌
send_to_p2(exponentiated_points)  # 发送给 P2
```

#### **Step 2: Round 2 (P2)**

- P2 对收到的每个元素计算 `(received)^{k2} → H(v_i)^{k1 k2}`，洗牌后发送给 P1。
- P2 对每个 `(w_j, t_j)` 计算 `H(w_j)^{k2}` 和 `AEnc(t_j)`，洗牌后发送给 P1。

```
# P2 逻辑
received_from_p1 = receive_from_p1()  # 接收 P1 数据
exponentiated_k2 = [pow(point, k2, curve.order) for point in received_from_p1]
random.shuffle(exponentiated_k2)
send_to_p1(exponentiated_k2)  # 发送 H(v_i)^{k1 k2}

# 处理 W 集
hashed_w = [hash_to_curve(w_j, seed) for w_j, _ in W]
exponentiated_w = [pow(int.from_bytes(point, 'big'), k2, curve.order) for point in hashed_w]  # H(w_j)^{k2}
encrypted_t = [public_key_phe.encrypt(t_j) for _, t_j in W]  # AEnc(t_j)
combined_w = list(zip(exponentiated_w, encrypted_t))
random.shuffle(combined_w)
send_to_p1(combined_w)  # 发送 {(H(w_j)^{k2}, AEnc(t_j))}
```

#### **Step 3: Round 3 (P1)**

- P1 对收到的 `(H(w_j)^{k2}, AEnc(t_j))` 计算 `(H(w_j)^{k1 k2}, AEnc(t_j))`。
- 计算交集 `J = {j: H(w_j)^{k1 k2} ∈ Z}`（`Z` 是 P2 返回的 `H(v_i)^{k1 k2}` 集合）。
- 对交集 `J` 中的 `AEnc(t_j)` 同态求和 `S_J = AEnc(Σ t_j)`，随机化后发送给 P2。

```
# P1 逻辑
z_set = receive_exponentiated_k2()  # 接收 Z = {H(v_i)^{k1 k2}}
w_set = receive_combined_w()  # 接收 {(H(w_j)^{k2}, AEnc(t_j))}

# 计算 H(w_j)^{k1 k2}
processed_w = [(pow(h_wj, k1, curve.order), enc_t) for h_wj, enc_t in w_set]

# 计算交集 J
intersection_indices = []
for h_wj_k1k2, enc_t in processed_w:
    if h_wj_k1k2 in z_set:  # 简化: 实际需处理点比较
        intersection_indices.append(enc_t)

# 同态求和
if intersection_indices:
    sum_enc = intersection_indices[0]
    for enc in intersection_indices[1:]:
        sum_enc += enc  # 同态加法
    refreshed_sum = sum_enc * public_key_phe.encrypt(0)  # 随机化 (ARefresh)
    send_to_p2(refreshed_sum)
else:
    send_to_p2(None)  # 空交集处理
```

#### **Step 4: Output (P2)**

- P2 解密 `S_J` 得到总和，并输出交集大小（通过 `J` 计数）和总和。

```
# P2 逻辑
encrypted_sum = receive_from_p1()
if encrypted_sum is not None:
    s_j = private_key_phe.decrypt(encrypted_sum)  # 解密总和
    cardinality = len(intersection_indices)  # 假设 P2 从流程中计数
    print(f"Intersection Cardinality: {cardinality}, Sum: {s_j}")
```

