// X86 - 64�ܹ��Ż�ʵ��
// 1. ��Ϣ��չ�Ż�
// ʹ��PALIGNR��PSHUFDָ���Ż�
__m128i w16_19 = _mm_shuffle_epi32(
    _mm_xor_si128(
        _mm_xor_si128(w0_3, w4_7),
        _mm_ror_epi32(w8_11, 15)
    ),
    0x1B
);
// 2. ѹ�������Ż�
// 4��չ���궨��
#define ROUND4(A,B,C,D,E,F,G,H,i) \
    SS1 = ROTL32((ROTL32(A,12) + E + ROTL32(Tj[i],i)), 7); \
    SS2 = SS1 ^ ROTL32(A,12); \
    TT1 = FF_i(A,B,C,i) + D + SS2 + Wj_prime[i]; \
    TT2 = GG_i(E,F,G,i) + H + SS1 + Wj[i]; \
    D = C; C = ROTL32(B,9); B = A; A = TT1; \
    H = G; G = ROTL32(F,19); F = E; E = P0(TT2); \
    // �ظ�4��

// ARM64�ܹ��Ż�ʵ��
// 1. ��Ϣ��չ�Ż�
// ʹ��NEONָ���Ż�
uint32x4_t w16_19 = veorq_u32(
    vaddq_u32(w0_3, w4_7),
    vrshlq_u32(w8_11, vdupq_n_s32(-17))
);
// 2. ѹ�������Ż�
// Ͱ����λָ���Ż�
#define FF_i(A,B,C,i) (i < 16 ? \
    (A ^ B ^ C) : \
    ((A & B) | (A & C) | (B & C)) \
)

// ʹ��EXTRָ����ټĴ�������
uint32_t TT1 = __extr(FF_i(A, B, C, i), SS2, 16) + Wj_prime[i];

// Ƕ��ʽʵ���Ż�(Cortex - M)
// ��������Ż�ѭ����λ
__asm volatile(
"ror %0, %1, #7"
    : "=r"(result)
    : "r"(input)
    );

// �Ĵ����������
register uint32_t A asm("r0");
register uint32_t B asm("r1");
register uint32_t C asm("r2");
register uint32_t D asm("r3");

// SIMD����KDF�Ż�
// 1. 8·����ʵ��
void sm3_kdf_avx512(const uint8_t * input, size_t len, uint8_t * output) {
    __m512i state[8];
    // ��ʼ��8������״̬
    for (int i = 0; i < 8; i++) {
        state[i] = _mm512_loadu_epi32(init_state + i * 16);
    }

    // ���д���8�����ݿ�
    for (size_t i = 0; i < len; i += 512) {
        process_8_blocks(state, input + i);
    }

    // ������
    _mm512_storeu_epi32(output, state[0]);
}

