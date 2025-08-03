// 1. ​​基础GCM模式
void sm4_gcm_encrypt(..., const uint8_t* aad, size_t aad_len) {
    // 初始化计数器
    uint32_t ctr[4] = { ... };

    // 计算加密计数器
    for (int i = 0; i < len; i += 16) {
        sm4_encrypt(ctr, ek, buf_out);
        xor_blocks(out + i, in + i, buf_out);  // CTR加密
        inc_counter(ctr);
    }

    // GHASH认证
    uint128_t tag = ghash(aad, aad_len, out, len, H);
}
//2. ​​GHASH优化
#include <pclmulqdqintrin.h>

// GF(2^128)乘法 (Intel算法)
__m128i gfmul(__m128i a, __m128i b) {
    const __m128i p = _mm_set_epi32(0, 0, 0, 0x87);
    __m128i t1 = _mm_clmulepi64_si128(a, b, 0x00);
    __m128i t2 = _mm_clmulepi64_si128(a, b, 0x11);
    __m128i t3 = _mm_clmulepi64_si128(a, b, 0x01);
    __m128i t4 = _mm_clmulepi64_si128(a, b, 0x10);
    t3 = _mm_xor_si128(t3, t4);
    t4 = _mm_slli_si128(t3, 8);
    t3 = _mm_srli_si128(t3, 8);
    t1 = _mm_xor_si128(t1, t4);
    t2 = _mm_xor_si128(t2, t3);

    // 模约简
    __m128i t5 = _mm_clmulepi64_si128(t1, p, 0x01);
    __m128i t6 = _mm_shuffle_epi32(t1, 78);
    t1 = _mm_xor_si128(t6, t5);
    t5 = _mm_clmulepi64_si128(t1, p, 0x01);
    t6 = _mm_shuffle_epi32(t1, 78);
    return _mm_xor_si128(t2, _mm_xor_si128(t6, t5));
}

// 完整优化方案
// 步骤1: 使用AVX512并行CTR加密
__m512i ctr_block = _mm512_set1_epi32(...);
for (int i = 0; i < 4; i++) {
    __m512i enc = sm4_encrypt_avx512(ctr_block);
    __m512i data = _mm512_loadu_si512(in + i * 64);
    _mm512_storeu_si512(out + i * 64, _mm512_xor_epi8(enc, data));
    ctr_block = inc_counter_avx512(ctr_block);
}

// 步骤2: 聚合GHASH输入
__m128i aad_acc = _mm_setzero_si128();
__m128i H = compute_H();
while (aad_len >= 16) {
    __m128i block = _mm_loadu_si128(aad);
    aad_acc = gfmul(_mm_xor_si128(aad_acc, block), H);
    aad += 16; aad_len -= 16;
}
// ...处理尾部数据...

// 步骤3: 并行GHASH计算 (8区块流水线)
for (int i = 0; i < len; i += 128) {
    __m128i* blocks = (__m128i*)(out + i);
    __m128i acc = _mm_load_si128(&aad_acc);
    for (int j = 0; j < 8; j++) {
        acc = gfmul(_mm_xor_si128(acc, blocks[j]), H);
    }
    _mm_store_si128(&aad_acc, acc);
}