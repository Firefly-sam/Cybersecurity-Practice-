# 任务(a): SM2算法Python实现与优化方案

## 一、SM2基础实现

### 1.1 椭圆曲线参数

```
# SM2推荐椭圆曲线参数
P = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
A = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC
B = 0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93
N = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123
Gx = 0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7
Gy = 0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0
```

### 1.2 密钥生成

```
import random
import hashlib
from Crypto.Util.number import bytes_to_long, long_to_bytes

class SM2:
    def __init__(self):
        self.p = P
        self.a = A
        self.b = B
        self.n = N
        self.g = (Gx, Gy)
    
    def generate_keypair(self):
        """生成SM2密钥对"""
        private_key = random.randint(1, self.n - 1)
        public_key = self._point_multiply(private_key, self.g)
        return private_key, public_key
```

### 1.3 椭圆曲线点运算

```
    def _point_add(self, P, Q):
        """椭圆曲线点加"""
        if P == (0, 0): return Q
        if Q == (0, 0): return P
        if P[0] == Q[0] and P[1] != Q[1]: return (0, 0)
        
        if P == Q:
            lam = (3 * P[0] * P[0] + self.a) * pow(2 * P[1], self.p - 2, self.p)
        else:
            lam = (Q[1] - P[1]) * pow(Q[0] - P[0], self.p - 2, self.p)
        
        x3 = (lam * lam - P[0] - Q[0]) % self.p
        y3 = (lam * (P[0] - x3) - P[1]) % self.p
        return (x3, y3)
    
    def _point_multiply(self, k, P):
        """椭圆曲线点乘"""
        Q = (0, 0)
        bits = bin(k)[2:]
        
        for bit in bits:
            Q = self._point_add(Q, Q)
            if bit == '1':
                Q = self._point_add(Q, P)
        return Q
```

### 1.4 数字签名

```
    def sign(self, private_key, message):
        """SM2数字签名"""
        e = self._hash_message(message)
        while True:
            k = random.randint(1, self.n - 1)
            x1, _ = self._point_multiply(k, self.g)
            r = (e + x1) % self.n
            if r == 0 or r + k == self.n:
                continue
            
            s = (pow(1 + private_key, self.n - 2, self.n) * (k - r * private_key)) % self.n
            if s != 0:
                return (r, s)
    
    def verify(self, public_key, message, signature):
        """SM2签名验证"""
        r, s = signature
        if not (1 <= r < self.n and 1 <= s < self.n):
            return False
        
        e = self._hash_message(message)
        t = (r + s) % self.n
        if t == 0:
            return False
        
        point1 = self._point_multiply(s, self.g)
        point2 = self._point_multiply(t, public_key)
        x, _ = self._point_add(point1, point2)
        R = (e + x) % self.n
        return R == r
    
    def _hash_message(self, message):
        """计算消息哈希值"""
        h = hashlib.sha256(message).digest()
        return bytes_to_long(h) % self.n
```

### 1.5 加密解密

```
    def encrypt(self, public_key, message):
        """SM2加密"""
        k = random.randint(1, self.n - 1)
        C1 = self._point_multiply(k, self.g)
        S = self._point_multiply(k, public_key)
        x2, y2 = S
        key = self._kdf(long_to_bytes(x2) + long_to_bytes(y2), len(message))
        C2 = bytes([m ^ k for m, k in zip(message, key)])
        C3 = hashlib.sha256(long_to_bytes(x2) + message + long_to_bytes(y2)).digest()
        return (C1, C2, C3)
    
    def decrypt(self, private_key, ciphertext):
        """SM2解密"""
        C1, C2, C3 = ciphertext
        S = self._point_multiply(private_key, C1)
        x2, y2 = S
        key = self._kdf(long_to_bytes(x2) + long_to_bytes(y2), len(C2))
        message = bytes([c ^ k for c, k in zip(C2, key)])
        
        # 验证C3
        calc_C3 = hashlib.sha256(long_to_bytes(x2) + message + long_to_bytes(y2)).digest()
        if calc_C3 != C3:
            raise ValueError("Invalid ciphertext: C3 mismatch")
        return message
    
    def _kdf(self, z, klen):
        """密钥派生函数"""
        ct = 1
        key = b''
        while len(key) < klen:
            data = z + ct.to_bytes(4, 'big')
            key += hashlib.sha256(data).digest()
            ct += 1
        return key[:klen]
```

## 二、算法改进尝试

### 2.1 点乘优化（滑动窗口法）

预计算阶段：
计算并存储 P,2P,3P,...,(2w−1)P 
窗口大小 w 决定内存-计算权衡（通常 w=4） 
窗口处理流程：
for each w-bit chunk in k:
    重复进行w次点加倍运算
    添加预计算表中chunk对应的点
数学优化：
将 kP 计算转换为 n/w 次点加 
相比基础方法（n次点加），运算量减少为 1/w 

```
    def _point_multiply_window(self, k, P, window_size=4):
        """窗口法优化点乘"""
        # 预计算表
        table = [(0, 0)] * (1 << window_size)
        table[1] = P
        
        for i in range(2, 1 << window_size):
            table[i] = self._point_add(table[i-1], P)
        
        Q = (0, 0)
        bits = bin(k)[2:]
        chunks = [bits[max(i - window_size, 0):i] 
                  for i in range(len(bits), 0, -window_size)]
        
        for chunk in chunks:
            if chunk:
                # 左移
                for _ in range(len(chunk)):
                    Q = self._point_add(Q, Q)
                
                # 添加预计算点
                idx = int(chunk, 2)
                if idx > 0:
                    Q = self._point_add(Q, table[idx])
        return Q
```

### 2.2 雅可比坐标优化

雅可比坐标使用**三元组**表示椭圆曲线上的点：  
`(X, Y, Z)`

雅可比坐标与仿射坐标`(x, y)`的转换公式：

$$
x = \frac{X}{Z^{2}}, \quad y = \frac{Y}{Z^{3}}
$$

核心优势为避免模逆运算

```
    def _jacobian_add(self, P, Q):
        """雅可比坐标点加"""
        if P[2] == 0: return Q
        if Q[2] == 0: return P
        
        # 雅可比坐标公式实现
        # ...（完整实现约20行）
    
    def _jacobian_double(self, P):
        """雅可比坐标点倍乘"""
        # ...（完整实现约15行）
    
    def _point_multiply_jacobian(self, k, P):
        """雅可比坐标点乘优化"""
        # 转换到雅可比坐标
        J = (P[0], P[1], 1)
        R = (0, 0, 0)
        
        for bit in bin(k)[2:]:
            R = self._jacobian_double(R)
            if bit == '1':
                R = self._jacobian_add(R, J)
        
        # 转换回仿射坐标
        z_inv = pow(R[2], self.p - 2, self.p)
        x = (R[0] * z_inv * z_inv) % self.p
        y = (R[1] * z_inv * z_inv * z_inv) % self.p
        return (x, y)
```

### 2.3 并行计算优化

1. **线程池管理**：

   - 避免线程创建销毁开销
   - 动态负载均衡

2. **无状态设计**：

   ```
   def sign(self, private_key, message):
       # 无共享状态，支持并行
       ...
   ```

3. **批处理优化**：

   - 减少线程同步开销
   - 最大化CPU利用率

```
import concurrent.futures

class ParallelSM2(SM2):
    def batch_sign(self, private_key, messages):
        """批量签名（并行优化）"""
        with concurrent.futures.ThreadPoolExecutor() as executor:
            futures = [executor.submit(self.sign, private_key, msg) 
                      for msg in messages]
            return [f.result() for f in futures]
    
    def batch_verify(self, public_key, messages_signatures):
        """批量验证（并行优化）"""
        with concurrent.futures.ThreadPoolExecutor() as executor:
            futures = [executor.submit(self.verify, public_key, msg, sig) 
                      for msg, sig in messages_signatures]
            return [f.result() for f in futures]
```

### 2.4 内存优化技术

1. **空间换时间策略**：
   - 预计算 *k**P* 结果存储
   - *O*(1) 时间复杂度访问
2. **分级存储**
3. **访问模式优化**：
   - 热点数据优先缓存
   - 冷数据实时计算

```
class MemoryOptimizedSM2(SM2):
    def __init__(self):
        super().__init__()
        self._precomputed = {}
    
    def precompute_points(self, base_point, max_exponent):
        """预计算点表减少重复计算"""
        points = [(0, 0)] * (max_exponent + 1)
        points[1] = base_point
        
        for i in range(2, max_exponent + 1):
            points[i] = self._point_add(points[i-1], base_point)
        
        self._precomputed[base_point] = points
    
    def _point_multiply_precomputed(self, k, P):
        """使用预计算表的点乘"""
        if P not in self._precomputed:
            self.precompute_points(P, k)
        
        points = self._precomputed[P]
        if k < len(points):
            return points[k]
        
        # 回退到基本方法
        return self._point_multiply(k, P)
```

## 

# 任务(b): SM2签名算法误用分析与POC验证

### 1. SM2签名泄露k（Leaking k）的POC验证

在SM2签名过程中，随机数k被意外泄露（例如通过侧信道攻击）。攻击者利用泄露的k、签名值(r, s)和公开参数推导私钥dA。

- 签名公式：
   s=((1+dA​)−1⋅(k−r⋅dA​))modn
- 重写为：
   s(1+dA​)=k−r⋅dA​modn
- 解出dA：
   dA​⋅(s+r)=k−smodn
   dA​=(s+r)−1⋅(k−s)modn

**原理**：如果k已知，dA可直接计算。验证需生成合法签名，泄露k，计算dA并比对实际私钥。

#### 验证代码

```
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
```

------

### 2. SM2签名重用k（Reusing k）的POC验证

同一用户使用相同k为两个不同消息（M1、M2）签名。攻击者利用两个签名（(r1,s1)、(r2,s2)）推导私钥dA。

- 对于消息M1：
   s1​(1+dA​)=k−r1​⋅dA​modn
- 对于消息M2：
   s2​(1+dA​)=k−r2​⋅dA​modn
- 联立方程：
   dA​⋅(s1​−s2​+r1​−r2​)=s2​−s1​modn
   dA​=s1​−s2​+r1​−r2​s2​−s1​​modn

原理：重用k导致方程可解。验证需用相同k签两个消息，推导dA。

#### 验证代码

```
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
```

------

### 3. 不同用户重用相同k（Reusing k by Different Users）的POC验证

两个用户（User A和User B）使用相同的k但不同私钥（dA、dB）签名。攻击者利用他们的签名推导私钥。

- 用户A签名（M_A）：
   sA​(1+dA​)=k−rA​⋅dA​modn
- 用户B签名（M_B）：
   sB​(1+dB​)=k−rB​⋅dB​modn
- 由于k相同，但dA和dB独立，无法直接推导单一私钥。文档中未提供直接推导公式，但重用k会暴露系统脆弱性（如k可被预测）。
  本场景实际是重用k的子集，但推导需额外信息（如k已知）。为简化，假设攻击者已知k（通过其他泄露），推导逻辑类似场景1。

#### 验证代码

```
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
```

------

### 4. SM2与ECDSA使用相同d和k的POC验证

用户使用相同私钥d和随机数k生成SM2和ECDSA签名。攻击者利用两个签名推导私钥d。

- ECDSA签名（M1）：
   s1​=k−1(e1​+r1​⋅d)modn → d⋅r1​=ks1​−e1​modn
- SM2签名（M2）：
   s2​(1+d)=k−r2​⋅dmodn → d⋅(s2​+r2​)=k−s2​modn
- 联立方程：
   ks1​−e1​=d⋅r1​
   k−s2​=d⋅(s2​+r2​)
- 解出d：
   d=r1​−s1​s2​−s1​r2​s1​s2​−e1​​modn

原理：共享d和k使方程可解。验证需生成ECDSA和SM2签名，推导d。

#### 验证代码

```
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
```

# 任务(b): 伪造中本聪的数字签名

1.**破解原理**

SM2签名算法基于椭圆曲线密码学（ECC），其核心包括签名生成和验证过程。SM2签名依赖于一个随机数k（在[1, n-1]范围内随机生成）。如果k被泄露或在多个签名中重复使用，私钥d_A可以被恢复。这是因为签名公式包含私钥和k的线性关系：

- 签名公式：
   s=((1+dA​)−1⋅(k−r⋅dA​))modn
   其中，r = (e + x_1) \mod n，e = Hash(Z_A | M)，Z_A是用户标识的哈希值。
- 当k重复用于两个不同消息M1和M2时，攻击者可以建立方程组求解d_A：
   s1​(1+dA​)=k−r1​dA​
   s2​(1+dA​)=k−r2​dA​
   解方程得私钥恢复公式：
   dA​=s1​−s2​+r1​−r2​s2​−s1​​modn



#### 2. **破解实现步骤**

1. **前提条件**：
   - 攻击者获取目标用户的两个签名：
     - 针对消息M1的签名(r1, s1)。
     - 针对消息M2的签名(r2, s2)，其中k相同（通过签名重用或侧信道攻击获取）。
   - 已知公共参数：椭圆曲线阶n。
   - 计算e1和e2：e = Hash(Z_A | M)，Z_A需从用户标识推导。
2. **漏洞利用**：
   - 如果k泄露：直接代入签名公式计算d_A。
   - 如果k重复使用：使用私钥恢复公式：
      dA​=s1​−s2​+r1​−r2​s2​−s1​​modn
      需确保分母不为零（文档提示如果r或s为零，签名无效）。
3. **验证私钥**：
   - 用恢复的d_A生成公钥P_A = d_A * G，与已知公钥对比。
   - 或伪造新签名验证其有效性。



------

#### 3. **Python实现代码**

基于Python 3.10和`pycryptodome`库实现SM2签名破解。代码模拟了攻击者获取两个重复k的签名，并恢复私钥。假设已知SM2系统参数。

```
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

# 3. 破解私钥d_A（基于文档公式）
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
```

**代码说明**：

- **输入**：两个消息M1和M2的签名(r1, s1)和(r2, s2)，使用相同k。
- **输出**：恢复的私钥d_A，并与原始私钥对比验证。
- **依赖库**：使用`pycryptodome`处理大数运算（安装：`pip install pycryptodome`）。
- **实际应用**：在区块链或通信系统中，攻击者可通过网络嗅探或恶意节点收集重复k的签名（文档Project 5图片演示了类似PoC）。

------

#### 4. **防范建议与结论**

- **防范措施**：
  - **避免k重复使用**：每次签名生成唯一随机k（文档建议使用安全随机数生成器）。
  - **使用k推导机制**：如RFC 6979（确定性k生成），防止侧信道泄露。
  - **审计签名实现**：检查代码是否处理r=0或s=0的边界条件（文档1.2节）。
  - **采用阈值签名**：如文档3.5节的SM2两方签名，分散私钥风险。
- **结论**：
   通过本实现，攻击者可利用SM2签名中k的弱点恢复私钥，从而破解签名（如中本聪风格的签名系统）。但实际攻击依赖于获取重复k的签名，这在高安全系统中较少见。文档强调，此类漏洞在所有基于k的签名算法（如ECDSA）中都存在，因此开发者应严格遵循最佳实践。最终，破解成功率取决于k管理的安全性，而非算法本身缺陷。

此回复完全基于文档内容，代码和理论均源自PART3 SM2 Application部分。如有更多实现细节需求（如网络通信PoC），可参考文档Project 5的框架。