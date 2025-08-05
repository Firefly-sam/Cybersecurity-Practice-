import random
import hashlib
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from phe import paillier

# 辅助函数: 简化哈希到曲线 (生产环境需完整实现)
def hash_to_curve(identifier, seed):
    h = hashlib.sha256(f"{seed}{identifier}".encode()).digest()
    return int.from_bytes(h, 'big')  # 返回整数用于指数运算

# 初始化参数
curve = ec.SECP256R1()
seed = random.randint(1, 1000000)
n_length = 768  # Paillier 模长

# P1 输入
V = ["user1", "user2", "user3"]  # P1 标识符集
k1 = random.randint(1, curve.order)

# P2 输入
W = [("user2", 10), ("user3", 20), ("user4", 30)]  # (标识符, 值)
k2 = random.randint(1, curve.order)
public_key_phe, private_key_phe = paillier.generate_paillier_keypair(n_length=n_length)

# Round 1: P1 发送 {H(v_i)^k1}
hashed_v = [hash_to_curve(v, seed) for v in V]
exp_v_k1 = [pow(h, k1, curve.order) for h in hashed_v]  # g_i^{k1}
random.shuffle(exp_v_k1)

# Round 2: P2 处理
# 计算 Z = {H(v_i)^{k1 k2}
z_set = [pow(point, k2, curve.order) for point in exp_v_k1]
random.shuffle(z_set)

# 计算 {H(w_j)^k2, AEnc(t_j)}
hashed_w = [hash_to_curve(w, seed) for w, _ in W]
exp_w_k2 = [pow(h, k2, curve.order) for h in hashed_w]  # H(w_j)^k2
enc_t = [public_key_phe.encrypt(t) for _, t in W]  # AEnc(t_j)
combined_w = list(zip(exp_w_k2, enc_t))
random.shuffle(combined_w)

# Round 3: P1 处理
# 计算 H(w_j)^{k1 k2}
processed_w = [(pow(h_wj, k1, curve.order), enc_t) for h_wj, enc_t in combined_w]

# 计算交集 J
intersection_enc = []
for h_wj_k1k2, enc_t in processed_w:
    if h_wj_k1k2 in z_set:  # 简化比较 (实际需处理点对象)
        intersection_enc.append(enc_t)

# 同态求和
if intersection_enc:
    sum_enc = intersection_enc[0]
    for enc in intersection_enc[1:]:
        sum_enc += enc
    refreshed_sum = sum_enc * public_key_phe.encrypt(0)  # 随机化
else:
    refreshed_sum = None

# Output: P2 解密
if refreshed_sum:
    s_j = private_key_phe.decrypt(refreshed_sum)
    cardinality = len(intersection_enc)
    print(f"Result: Cardinality = {cardinality}, Sum = {s_j}")
else:
    print("No intersection found.")