// 优化之前
// SM4 S盒（8位输入->8位输出）
const uint8_t SBOX[256] = { ... };

// 线性变换L
static uint32_t sm4_L_transform(uint32_t data) {
    return data ^ ROTL(data, 2) ^ ROTL(data, 10) ^
        ROTL(data, 18) ^ ROTL(data, 24);
}

// 轮函数
static uint32_t sm4_round(uint32_t x0, uint32_t x1, uint32_t x2, uint32_t x3, uint32_t rk) {
    uint32_t temp = x1 ^ x2 ^ x3 ^ rk;
    temp = SBOX[temp >> 24] << 24 | SBOX[(temp >> 16) & 0xFF] << 16 |
        SBOX[(temp >> 8) & 0xFF] << 8 | SBOX[temp & 0xFF];
    return x0 ^ sm4_L_transform(temp);
}

// 主加密函数（未优化）
void sm4_encrypt(const uint32_t rk[32], const uint8_t in[16], uint8_t out[16]) {
    uint32_t buf[36];
    memcpy(buf, in, 16);
    for (int i = 0; i < 32; i++) {
        buf[i + 4] = sm4_round(buf[i], buf[i + 1], buf[i + 2], buf[i + 3], rk[i]);
    }
    memcpy(out, &buf[35], 16);  // 最后4个字为密文
}

// 1. T-Table优化​
// 预计算T-table（合并S盒和L变换）
const uint32_t T0[256], T1[256], T2[256], T3[256];  // 初始化代码略

// 优化轮函数
static uint32_t sm4_round_opt(uint32_t x0, uint32_t x1, uint32_t x2, uint32_t x3, uint32_t rk) {
    uint32_t temp = x1 ^ x2 ^ x3 ^ rk;
    return x0 ^ T0[temp >> 24] ^
        T1[(temp >> 16) & 0xFF] ^
        T2[(temp >> 8) & 0xFF] ^
        T3[temp & 0xFF];
}

//​ 2. AES-NI指令优化
#include <wmmintrin.h>

// 使用AES-NI加速S盒计算（需提前转换S盒为仿射形式）
__m128i sse_sbox(__m128i x) {
    const __m128i aff_mat = _mm_set_epi32(...); // S盒仿射矩阵
    const __m128i aff_c = _mm_set_epi32(...);   // 仿射常量
    __m128i inv = _mm_aesinv_si128(x);          // GF(2^8)求逆
    return _mm_aesenc_si128(inv, aff_mat) ^ aff_c;
}

// 3. AVX2+GFNI指令集（现代x86）
#include <immintrin.h>
#include <gfni.h>

// GFNI指令计算32字S盒
__m512i gfni_sbox(__m512i x) {
    const __m512i M1 = _mm512_set1_epi64(0x...); // S盒仿射1
    const __m512i M2 = _mm512_set1_epi64(0x...); // S盒仿射2
    __m512i tmp = _mm512_gf2p8affine_epi64_epi8(x, M1, 0);
    return _mm512_gf2p8affineinv_epi64_epi8(tmp, M2, 0);
}

// 完整轮函数 (AVX512)
void sm4_round_avx512(__m512i* s0, __m512i* s1, __m512i* s2, __m512i* s3, const uint32_t rk) {
    __m512i x = _mm512_xor_epi32(*s1,
        _mm512_xor_epi32(*s2,
            _mm512_xor_epi32(*s3,
                _mm512_set1_epi32(rk))));
    x = gfni_sbox(x);  // 并行计算16个S盒

    // 并行线性变换
    __m512i L = x;
    L = _mm512_xor_epi32(L, _mm512_rol_epi32(x, 2));
    L = _mm512_xor_epi32(L, _mm512_rol_epi32(x, 10));
    L = _mm512_xor_epi32(L, _mm512_rol_epi32(x, 18));
    L = _mm512_xor_epi32(L, _mm512_rol_epi32(x, 24));

    __m512i new_s = _mm512_xor_epi32(*s0, L);
    *s0 = *s1; *s1 = *s2; *s2 = *s3; *s3 = new_s;
}