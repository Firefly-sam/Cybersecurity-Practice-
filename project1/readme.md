# SM4软件实现与优化技术文档

## 1. 引言

SM4算法是中国国家密码管理局发布的商用分组密码标准（GB/T 32907-2016），采用128位分组和密钥长度。本文档详述其软件实现的核心优化策略，涵盖基础实现、T-Table加速、指令集优化（AES-NI/GFNI/AVX512），以及SM4-GCM工作模式的高效实现方案。  

## 2. SM4基础实现

### 2.1 核心组件

• S盒（非线性层）：8位输入→8位输出的置换表（256字节）。  

• 线性变换L：L(B) = B ⊕ (B<<<2) ⊕ (B<<<10) ⊕ (B<<<18) ⊕ (B<<<24)  

• 轮函数：  
  F(X0, X1, X2, X3, RK) = X0 ⊕ L( SBOX(X1 ⊕ X2 ⊕ X3 ⊕ RK) )  
    
• 32轮迭代：每轮更新状态寄存器(X0, X1, X2, X3)  

### 2.2 参考代码

uint32_t sm4_round(uint32_t x0, uint32_t x1, uint32_t x2, uint32_t x3, uint32_t rk) {  
    uint32_t temp = x1 ^ x2 ^ x3 ^ rk;  
    temp = SBOX[temp >> 24] << 24 | ... ; // 4次S盒查表  
    return x0 ^ L_transform(temp); // 线性变换  
}  
  
性能瓶颈：单区块处理、32轮迭代、频繁查表与移位操作（约25 cycles/byte）。  

## 3. SM4软件优化策略

### 3.1 T-Table预计算

原理：合并S盒和线性变换L，预计算为4个32位表（T0-T3）  
// 预计算T-Table（初始化代码略）  
const uint32_t T0[256] = L(SBOX[i]) 的0-8位;  
const uint32_t T1[256] = L(SBOX[i]) 的8-16位;  
// ... T2、T3同理  

// 优化轮函数  
uint32_t sm4_round_opt(uint32_t x0, x1, x2, x3, rk) {  
    uint32_t temp = x1 ^ x2 ^ x3 ^ rk;  
    return x0 ^ T0[temp >> 24]   
               ^ T1[(temp >> 16) & 0xFF]  
               ^ T2[(temp >> 8) & 0xFF]  
               ^ T3[temp & 0xFF];  
}  
  
优势：  
• 减少80%的移位/位操作  

• 性能提升：从25 cpb → 8 cpb（≈3倍加速）  

### 3.2 AES-NI指令优化（x86平台）

原理：复用AES-NI的aesenc指令计算S盒的仿射变换部分  
__m128i sse_sbox(__m128i x) {  
    __m128i inv = _mm_aesinv_si128(x); // GF(2^8)求逆  
    return _mm_aesenc_si128(inv, AFFINE_MAT) ^ AFFINE_CONST;  
}  
  
限制：需将SM4 S盒分解为仿射变换组合，仅部分替代查表操作。  

### 3.3 AVX512 + GFNI + VPROLD指令集

目标：16个分组的并行处理（512位寄存器）  
关键指令：

• GFNI（Galois Field New Instructions）：  
  __m512i sbox = _mm512_gf2p8affine_epi64_epi8(input, M1, 0); // 单周期S盒仿射变换  
    
• VPROLD（AVX512旋转）：  
  __m512i L = _mm512_xor_epi32(x, _mm512_rol_epi32(x, 2)); // 并行循环移位  
    

完整轮函数：

void sm4_avx512_round(__m512i *s0, *s1, *s2, *s3, rk) {  
    __m512i x = _mm512_xor_epi32(*s1, *s2, *s3, _mm512_set1_epi32(rk));  
    x = gfni_sbox(x);                  // GFNI加速S盒  
    x = L_transform_avx512(x);          // VPROLD加速线性变换  
    *s3 = _mm512_xor_epi32(*s0, x);    // 更新状态  
    // 寄存器轮转: s0←s1, s1←s2, s2←s3  
}  
  
性能：≈0.7 cpb（较基础实现提升35倍）  

## 4. SM4-GCM优化实现

### 4.1 GCM模式结构

• 加密：CTR模式 + SM4加密  

• 认证：GHASH（Galois哈希）  
  
  GHASH(H, AAD, Ciphertext) = (AAD×H + Ciphertext×H) × H  
    

### 4.2 GHASH优化（PCLMULQDQ指令）

原理：利用pclmulqdq实现GF(2^128)上的快速乘法  
__m128i gfmul(__m128i a, __m128i b) {  
    __m128i t1 = _mm_clmulepi64_si128(a, b, 0x00);  
    __m128i t2 = _mm_clmulepi64_si128(a, b, 0x11);  
    // ... 中间结果处理  
    return _mm_xor_si128(t2, reduced); // 模约简结果  
}  
  

### 4.3 完整SM4-GCM优化流程

void sm4_gcm_encrypt_opt(..., aad, ciphertext_len) {  
    // 1. 并行CTR加密 (AVX512)  
    __m512i ctr = _mm512_set1_epi32(ctr_val);  
    for (int i=0; i<blocks; i+=16) {  
        __m512i enc = sm4_avx512_encrypt(ctr);  
        _mm512_storeu_epi32(out+i*16, enc ^ plaintext);  
        ctr = _mm512_add_epi32(ctr, _mm512_set1_epi32(16)); // 向量化计数器  
    }  

  // 2. 多区块GHASH流水线 (8路并行)  
    __m128i H = compute_H();           // 预计算H  
    __m128i acc = _mm_setzero_si128();  
    for (int i=0; i<aad_len; i+=128) {  
        __m128i block[8] = load_8_blocks(aad+i);  
        for (int j=0; j<8; j++) {  
            acc = _mm_xor_si128(acc, block[j]);  
            acc = gfmul(acc, H);       // PCLMULQDQ加速  
        }  
    }  
    // ... 生成认证标签  
}  
  
性能：加密+认证 ≈1.1 cpb  

  
