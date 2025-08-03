#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sm3.h>

// �ָ�SM3״̬
void sm3_state_recovery(const unsigned char hash[SM3_DIGEST_LENGTH], SM3_CTX* ctx) {
    // ����������
    memset(ctx, 0, sizeof(SM3_CTX));

    // ����ϣֵ�ֽ�Ϊ8��32λ�֣������
    for (int i = 0; i < 8; i++) {
        ctx->A[i] = ((uint32_t)hash[i * 4] << 24) |
            ((uint32_t)hash[i * 4 + 1] << 16) |
            ((uint32_t)hash[i * 4 + 2] << 8) |
            (uint32_t)hash[i * 4 + 3];
    }

    // ������ȷ����Ϣ���ȼ���
    ctx->Nl = 0;  // ���ڹ�������������
    ctx->Nh = 0;
}

int length_extension_attack() {
    // ԭʼ��Կ����Ϣ
    const char* key = "secret_key";
    const char* message = "original_msg";
    size_t key_len = strlen(key);
    size_t msg_len = strlen(message);

    // ����ԭʼ��ϣ H(key || message)
    SM3_CTX ctx;
    unsigned char original_hash[SM3_DIGEST_LENGTH];
    sm3_init(&ctx);
    sm3_update(&ctx, (const unsigned char*)key, key_len);
    sm3_update(&ctx, (const unsigned char*)message, msg_len);
    sm3_final(original_hash, &ctx);

    // ������⸽��
    const char* evil_append = "&admin=1";
    size_t append_len = strlen(evil_append);

    // ������䳤�� (����SM3������)
    size_t total_len = key_len + msg_len;
    size_t pad_len = 64 - (total_len % 64);
    if (pad_len < 9) pad_len += 64;  // ����9�ֽ����

    // ��������Ϣ: message + padding + evil_append
    unsigned char* new_msg = malloc(msg_len + pad_len + append_len);
    memcpy(new_msg, message, msg_len);

    // ������
    new_msg[msg_len] = 0x80;
    memset(new_msg + msg_len + 1, 0, pad_len - 1);

    // ���ԭʼ��Ϣ���ȣ�λ���ȣ������
    uint64_t bit_len = total_len * 8;
    for (int i = 0; i < 8; i++) {
        new_msg[msg_len + pad_len - 8 + i] = (bit_len >> (56 - i * 8)) & 0xFF;
    }

    // ��Ӷ��⸽��
    memcpy(new_msg + msg_len + pad_len, evil_append, append_len);

    // ������ʵ���¹�ϣ H(key || new_msg)
    unsigned char real_hash[SM3_DIGEST_LENGTH];
    sm3_init(&ctx);
    sm3_update(&ctx, (const unsigned char*)key, key_len);
    sm3_update(&ctx, new_msg, msg_len + pad_len + append_len);
    sm3_final(real_hash, &ctx);

    // ʵʩ������ʹ��ԭʼ��ϣ��Ϊ��ʼ״̬
    SM3_CTX attack_ctx;
    sm3_state_recovery(original_hash, &attack_ctx);

    // ������ȷ����Ϣ���ȣ�������Կ����䣩
    attack_ctx.Nl = (total_len + pad_len) * 8;  // λ����

    // ����������
    sm3_update(&attack_ctx, (const unsigned char*)evil_append, append_len);

    // ���㹥����ϣ
    unsigned char attack_hash[SM3_DIGEST_LENGTH];
    sm3_final(attack_hash, &attack_ctx);

    // ��֤�����Ƿ�ɹ�
    int result = memcmp(real_hash, attack_hash, SM3_DIGEST_LENGTH) == 0;

    free(new_msg);
    return result;
}

int main() {
    if (length_extension_attack()) {
        printf("Length extension attack successful!\n");
    }
    else {
        printf("Attack failed\n");
    }
    return 0;
}