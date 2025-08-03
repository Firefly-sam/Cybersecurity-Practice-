# 1. SM2签名泄露k（Leaking k）的POC验证
import ecdsa
from ecdsa.curves import SM2
from hashlib import sha256
import secrets

# 初始化SM2参数 (文档中的值)
curve = SM2.curve
G = ecdsa.ecdsa.generator_secp256k1  # 使用标准基点，文档中G未提供完整坐标，简化处理
n = G.order()  # 阶n

# 生成密钥对
dA = secrets.randbelow(n-1) + 1  # 私钥dA ∈ [1, n-1]
PA = dA * G  # 公钥PA

# SM2签名函数 (文档PART2)
def sm2_sign(dA, message, k=None):
    ZA = b'user_id'  # 简化ZA计算（文档中ZA需H256计算）
    M_bar = ZA + message
    e = int.from_bytes(sha256(M_bar).digest(), 'big') % n

    if k is None:
        k = secrets.randbelow(n-1) + 1  # 随机k
    kG = k * G
    x1 = kG.x() % n
    r = (e + x1) % n
    if r == 0 or r + k == n:
        return sm2_sign(dA, message)  # 重试

    s = pow(1 + dA, -1, n) * (k - r * dA) % n
    if s == 0:
        return sm2_sign(dA, message)  # 重试
    return (r, s), k

# 泄露k场景POC
message = b"Test message"
(r, s), k_leaked = sm2_sign(dA, message)  # 生成签名并泄露k
print(f"实际私钥 dA: {dA}")

# 推导dA (使用泄露的k)
dA_calculated = pow(s + r, -1, n) * (k_leaked - s) % n
print(f"推导私钥 dA: {dA_calculated}")
print(f"推导结果验证: {'成功' if dA == dA_calculated else '失败'}")

# 2. SM2签名重用k（Reusing k）的POC验证

# 重用k场景POC
message1 = b"Message 1"
message2 = b"Message 2"

# 使用相同k签名
k_reused = secrets.randbelow(n-1) + 1
(r1, s1), _ = sm2_sign(dA, message1, k=k_reused)
(r2, s2), _ = sm2_sign(dA, message2, k=k_reused)

# 推导dA
numerator = (s2 - s1) % n
denominator = (s1 - s2 + r1 - r2) % n
dA_calculated = numerator * pow(denominator, -1, n) % n
print(f"实际私钥 dA: {dA}")
print(f"推导私钥 dA: {dA_calculated}")
print(f"推导结果验证: {'成功' if dA == dA_calculated else '失败'}")

# 3. 不同用户重用相同k（Reusing k by Different Users）的POC验证

# 不同用户重用k场景POC
dB = secrets.randbelow(n-1) + 1  # User B私钥
PB = dB * G

# 相同k用于两个用户
k_shared = secrets.randbelow(n-1) + 1
(rA, sA), _ = sm2_sign(dA, b"Msg from A", k=k_shared)
(rB, sB), _ = sm2_sign(dB, b"Msg from B", k=k_shared)

# 假设k被泄露（如侧信道），推导dA和dB
dA_calculated = pow(sA + rA, -1, n) * (k_shared - sA) % n
dB_calculated = pow(sB + rB, -1, n) * (k_shared - sB) % n

print(f"User A实际私钥 dA: {dA}, 推导 dA: {dA_calculated}")
print(f"User B实际私钥 dB: {dB}, 推导 dB: {dB_calculated}")
print(f"推导结果: User A {'成功' if dA == dA_calculated else '失败'}, User B {'成功' if dB == dB_calculated else '失败'}")

# 4. SM2与ECDSA使用相同d和k的POC验证
# ECDSA签名函数
def ecdsa_sign(d, message, k=None):
    if k is None:
        k = secrets.randbelow(n-1) + 1
    kG = k * G
    r1 = kG.x() % n
    e1 = int.from_bytes(sha256(message).digest(), 'big') % n
    s1 = pow(k, -1, n) * (e1 + r1 * d) % n
    return (r1, s1), k

# 相同d和k场景POC
d = secrets.randbelow(n-1) + 1  # 共享私钥
message1 = b"ECDSA message"
message2 = b"SM2 message"

# 使用相同d和k生成签名
k_shared = secrets.randbelow(n-1) + 1
(r1, s1), _ = ecdsa_sign(d, message1, k=k_shared)
(r2, s2), _ = sm2_sign(d, message2, k=k_shared)

# 推导d
e1 = int.from_bytes(sha256(message1).digest(), 'big') % n
numerator = (s1 * s2 - e1) % n
denominator = (r1 - s1 * s2 - s1 * r2) % n
d_calculated = numerator * pow(denominator, -1, n) % n

print(f"实际私钥 d: {d}")
print(f"推导私钥 d: {d_calculated}")
print(f"推导结果验证: {'成功' if d == d_calculated else '失败'}")
