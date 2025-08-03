#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sm3.h>

// 恢复SM3状态
void sm3_state_recovery(const unsigned char hash[SM3_DIGEST_LENGTH], SM3_CTX* ctx) {
    // 重置上下文
    memset(ctx, 0, sizeof(SM3_CTX));

    // 将哈希值分解为8个32位字（大端序）
    for (int i = 0; i < 8; i++) {
        ctx->A[i] = ((uint32_t)hash[i * 4] << 24) |
            ((uint32_t)hash[i * 4 + 1] << 16) |
            ((uint32_t)hash[i * 4 + 2] << 8) |
            (uint32_t)hash[i * 4 + 3];
    }

    // 设置正确的消息长度计数
    ctx->Nl = 0;  // 将在攻击函数中设置
    ctx->Nh = 0;
}

int length_extension_attack() {
    // 原始密钥和消息
    const char* key = "secret_key";
    const char* message = "original_msg";
    size_t key_len = strlen(key);
    size_t msg_len = strlen(message);

    // 计算原始哈希 H(key || message)
    SM3_CTX ctx;
    unsigned char original_hash[SM3_DIGEST_LENGTH];
    sm3_init(&ctx);
    sm3_update(&ctx, (const unsigned char*)key, key_len);
    sm3_update(&ctx, (const unsigned char*)message, msg_len);
    sm3_final(original_hash, &ctx);

    // 构造恶意附加
    const char* evil_append = "&admin=1";
    size_t append_len = strlen(evil_append);

    // 计算填充长度 (根据SM3填充规则)
    size_t total_len = key_len + msg_len;
    size_t pad_len = 64 - (total_len % 64);
    if (pad_len < 9) pad_len += 64;  // 至少9字节填充

    // 构造新消息: message + padding + evil_append
    unsigned char* new_msg = malloc(msg_len + pad_len + append_len);
    memcpy(new_msg, message, msg_len);

    // 添加填充
    new_msg[msg_len] = 0x80;
    memset(new_msg + msg_len + 1, 0, pad_len - 1);

    // 添加原始消息长度（位长度，大端序）
    uint64_t bit_len = total_len * 8;
    for (int i = 0; i < 8; i++) {
        new_msg[msg_len + pad_len - 8 + i] = (bit_len >> (56 - i * 8)) & 0xFF;
    }

    // 添加恶意附加
    memcpy(new_msg + msg_len + pad_len, evil_append, append_len);

    // 计算真实的新哈希 H(key || new_msg)
    unsigned char real_hash[SM3_DIGEST_LENGTH];
    sm3_init(&ctx);
    sm3_update(&ctx, (const unsigned char*)key, key_len);
    sm3_update(&ctx, new_msg, msg_len + pad_len + append_len);
    sm3_final(real_hash, &ctx);

    // 实施攻击：使用原始哈希作为初始状态
    SM3_CTX attack_ctx;
    sm3_state_recovery(original_hash, &attack_ctx);

    // 设置正确的消息长度（包括密钥和填充）
    attack_ctx.Nl = (total_len + pad_len) * 8;  // 位长度

    // 处理附加数据
    sm3_update(&attack_ctx, (const unsigned char*)evil_append, append_len);

    // 计算攻击哈希
    unsigned char attack_hash[SM3_DIGEST_LENGTH];
    sm3_final(attack_hash, &attack_ctx);

    // 验证攻击是否成功
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