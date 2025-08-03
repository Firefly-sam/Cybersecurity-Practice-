# SM2推荐椭圆曲线参数
P = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
A = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC
B = 0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93
N = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123
Gx = 0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7
Gy = 0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0

# 密钥生成
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


# 椭圆曲线点运算

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


# 数字签名
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


# 加密解密
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


# 算法优化尝试

# 点乘优化（滑动窗口法）

def _point_multiply_window(self, k, P, window_size=4):
    """窗口法优化点乘"""
    # 预计算表
    table = [(0, 0)] * (1 << window_size)
    table[1] = P

    for i in range(2, 1 << window_size):
        table[i] = self._point_add(table[i - 1], P)

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


# 雅可比坐标优化
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

# 并行计算优化
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


# 内存优化技术
class MemoryOptimizedSM2(SM2):
    def __init__(self):
        super().__init__()
        self._precomputed = {}

    def precompute_points(self, base_point, max_exponent):
        """预计算点表减少重复计算"""
        points = [(0, 0)] * (max_exponent + 1)
        points[1] = base_point

        for i in range(2, max_exponent + 1):
            points[i] = self._point_add(points[i - 1], base_point)

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


