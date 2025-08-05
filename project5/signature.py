from Crypto.Util.number import bytes_to_long, long_to_bytes
from hashlib import sha256
import random

# 1. 定义SM2参数（简化版）
n = 0x8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7  # 文档中的阶n
a = 0x787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498
b = 0x63E4C6D3B23B0C849CF84241484BFE48F61059A5B16BA06E6E12D1DA27C5249A
Gx = 0x421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D
Gy = 0x0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2

# 2. 模拟用户私钥和签名（假设k重复使用）
d_A = random.randint(1, n-1)  # 目标私钥（未知，需破解）
M1 = b"Message1"
M2 = b"Message2"
k = random.randint(1, n-1)  # 重复使用的k

# 计算Z_A（用户标识哈希）
def compute_ZA():
    # 简化：ENTL_A, ID_A等省略，实际需按文档计算
    return sha256(b"ENTL_A_ID_A_a_b_xG_yG_xA_yA").digest()

ZA = compute_ZA()
e1 = bytes_to_long(sha256(ZA + M1).digest()) % n
e2 = bytes_to_long(sha256(ZA + M2).digest()) % n

# 模拟签名生成
def sm2_sign(M, k, d_A):
    ZA = compute_ZA()
    e = bytes_to_long(sha256(ZA + M).digest()) % n
    # 简化：省略点乘计算，假设kG = (x1, y1)
    x1 = (k * Gx) % n  # 实际需椭圆曲线点乘
    r = (e + x1) % n
    s = ((1 + d_A)**(-1) * (k - r * d_A)) % n
    return r, s

# 获取两个签名（同一k）
r1, s1 = sm2_sign(M1, k, d_A)
r2, s2 = sm2_sign(M2, k, d_A)

# 3. 破解私钥d_A
def recover_private_key(r1, s1, r2, s2, n):
    numerator = (s2 - s1) % n
    denominator = (s1 - s2 + r1 - r2) % n
    if denominator == 0:
        raise ValueError("无效签名（分母为零），k可能未重复使用")
    d_A_recovered = (numerator * pow(denominator, -1, n)) % n
    return d_A_recovered

try:
    d_A_recovered = recover_private_key(r1, s1, r2, s2, n)
    print(f"恢复的私钥 d_A: {hex(d_A_recovered)}")
    print(f"原始私钥 d_A: {hex(d_A)}")
    print(f"验证结果: {'成功' if d_A_recovered == d_A else '失败'}")
except Exception as e:
    print(f"破解失败: {e}")