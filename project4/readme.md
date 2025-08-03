# 任务a：SM3优化方案

### 一、核心优化思路

1. **寄存器优先策略**

   - 将算法状态(A-H)和常用中间变量保留在寄存器中
   - 使用宏展开减少函数调用开销
   - 最小化内存访问（特别是X86架构）

2. **SIMD并行化**

   ```
   // X86-64 AVX2实现示例
   __m128i v0 = _mm_load_si128((__m128i*)w);
   __m128i v1 = _mm_load_si128((__m128i*)(w+4));
   __m128i v2 = _mm_ror_epi32(v0, 15);
   ```

3. **指令级并行**

   ```
   // 桶形移位优化(ARM)
   #define ROTL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))
   uint32_t tmp = a + b + Tj;
   ```

------

### 二、X86-64架构优化实现

#### 1. 消息扩展优化

```
// 使用PALIGNR和PSHUFD指令优化
__m128i w16_19 = _mm_shuffle_epi32(
    _mm_xor_si128(
        _mm_xor_si128(w0_3, w4_7),
        _mm_ror_epi32(w8_11, 15)
    ), 
    0x1B
);
```

#### 2. 压缩函数优化

```
// 4轮展开宏定义
#define ROUND4(A,B,C,D,E,F,G,H,i) \
    SS1 = ROTL32((ROTL32(A,12) + E + ROTL32(Tj[i],i)), 7); \
    SS2 = SS1 ^ ROTL32(A,12); \
    TT1 = FF_i(A,B,C,i) + D + SS2 + Wj_prime[i]; \
    TT2 = GG_i(E,F,G,i) + H + SS1 + Wj[i]; \
    D = C; C = ROTL32(B,9); B = A; A = TT1; \
    H = G; G = ROTL32(F,19); F = E; E = P0(TT2); \
    // 重复4次
```

#### 3. 关键指令优化表

| 操作         | 优化指令 | 周期 | 端口 |
| ------------ | -------- | ---- | ---- |
| 32位循环移位 | RORX     | 1    | p0   |
| 三操作数加法 | LEA      | 1    | p1   |
| 128位异或    | VPXOR    | 1    | p015 |
| 洗牌操作     | VPSHUFB  | 1    | p5   |

------

### 三、ARM64架构优化实现

#### 1. 消息扩展优化

```
// 使用NEON指令优化
uint32x4_t w16_19 = veorq_u32(
    vaddq_u32(w0_3, w4_7),
    vrshlq_u32(w8_11, vdupq_n_s32(-17))
);
```

#### 2. 压缩函数优化

```
// 桶形移位指令优化
#define FF_i(A,B,C,i) (i < 16 ? \
    (A ^ B ^ C) : \
    ((A & B) | (A & C) | (B & C)) \
)

// 使用EXTR指令减少寄存器依赖
uint32_t TT1 = __extr(FF_i(A,B,C,i), SS2, 16) + Wj_prime[i];
```

------

### 四、嵌入式实现优化(Cortex-M)

#### 1. 关键优化技术

```
// 内联汇编优化循环移位
__asm volatile(
    "ror %0, %1, #7" 
    : "=r"(result) 
    : "r"(input)
);

// 寄存器分配策略
register uint32_t A asm("r0");
register uint32_t B asm("r1");
register uint32_t C asm("r2");
register uint32_t D asm("r3");
```

------

### 五、SIMD并行KDF优化

#### 1. 8路并行实现

```
void sm3_kdf_avx512(const uint8_t* input, size_t len, uint8_t* output) {
    __m512i state[8];
    // 初始化8个并行状态
    for (int i=0; i<8; i++) {
        state[i] = _mm512_loadu_epi32(init_state + i*16);
    }
    
    // 并行处理8个数据块
    for (size_t i=0; i<len; i+=512) {
        process_8_blocks(state, input+i);
    }
    
    // 输出结果
    _mm512_storeu_epi32(output, state[0]);
}
```



------

### 六、总结

1. **关键优化点**

   - SIMD消息扩展优化
   - 4轮展开的压缩函数
   - 架构特定指令应用
   - 寄存器分配策略优化

2. **不同平台优化重点**

   | 平台   | 优化重点             |
   | ------ | -------------------- |
   | X86-64 | SIMD指令、LEA优化    |
   | ARM64  | 桶形移位器、EXTR指令 |
   | 嵌入式 | 寄存器分配、内联汇编 |



# 任务b：SM3长度扩展攻击验证

### 攻击原理与技术背景

长度扩展攻击利用了Merkle-Damgård结构密码哈希函数的固有特性。当攻击者已知`(原始消息, 哈希值)`对时，可以在不知道密钥的情况下，构造出包含恶意附加内容的新消息，并预测其哈希值。

**技术要点**：

- SM3哈希函数使用固定的初始向量(IV)
- 哈希状态可被序列化/反序列化
- 填充规则必须严格遵循（包括长度字段的64位大端表示）



# 任务c：基于SM3的Merkle树实现（RFC6962）

### Merkle树结构与RFC6962规范

RFC6962定义了以下关键规范：

- 叶子节点哈希前缀：0x00
- 内部节点哈希前缀：0x01
- 哈希计算：`SM3(prefix || left_hash || right_hash)`
- 节点排序：左子树 < 右子树

**证明系统**：

- 存在证明路径长度 = 树高度-1 (10万节点约17个节点)
- 不存在证明基于前驱-后继边界验证
