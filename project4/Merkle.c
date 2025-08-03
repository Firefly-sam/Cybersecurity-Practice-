#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sm3.h>

#define LEAF_COUNT 100000
#define HASH_SIZE 32

typedef struct {
    uint8_t hash[HASH_SIZE];
} MerkleNode;

typedef struct {
    MerkleNode* nodes;
    int count;
} MerkleLevel;

typedef struct {
    MerkleLevel* levels;
    int height;
    uint8_t root[HASH_SIZE];
} MerkleTree;

typedef struct {
    MerkleNode* nodes;
    int* positions; // 0=左兄弟, 1=右兄弟
    int count;
} MerkleProof;

//2. 树构建实现
// RFC6962叶子节点哈希
void hash_leaf(const uint8_t * data, size_t len, uint8_t out[HASH_SIZE]) {
    SM3_CTX ctx;
    uint8_t prefix = 0x00;
    sm3_init(&ctx);
    sm3_update(&ctx, &prefix, 1);
    sm3_update(&ctx, data, len);
    sm3_final(out, &ctx);
}

// RFC6962内部节点哈希
void hash_internal(const uint8_t* left, const uint8_t* right, uint8_t out[HASH_SIZE]) {
    SM3_CTX ctx;
    uint8_t prefix = 0x01;
    sm3_init(&ctx);
    sm3_update(&ctx, &prefix, 1);
    sm3_update(&ctx, left, HASH_SIZE);
    sm3_update(&ctx, right, HASH_SIZE);
    sm3_final(out, &ctx);
}

// 创建Merkle树
MerkleTree* create_merkle_tree(uint8_t** leaf_data, int leaf_count) {
    // 计算树高度
    int height = 0;
    for (int n = leaf_count; n > 0; n = (n + 1) / 2) {
        height++;
    }

    // 分配树结构
    MerkleTree* tree = malloc(sizeof(MerkleTree));
    tree->height = height;
    tree->levels = malloc(height * sizeof(MerkleLevel));

    // 创建叶子层
    tree->levels[0].count = leaf_count;
    tree->levels[0].nodes = malloc(leaf_count * sizeof(MerkleNode));
    for (int i = 0; i < leaf_count; i++) {
        hash_leaf(leaf_data[i], strlen((char*)leaf_data[i]),
            tree->levels[0].nodes[i].hash);
    }

    // 自底向上构建树
    for (int level = 0; level < height - 1; level++) {
        int current_count = tree->levels[level].count;
        int next_count = (current_count + 1) / 2;

        tree->levels[level + 1].count = next_count;
        tree->levels[level + 1].nodes = malloc(next_count * sizeof(MerkleNode));

        for (int i = 0; i < next_count; i++) {
            int left_idx = 2 * i;
            int right_idx = 2 * i + 1;

            if (right_idx < current_count) {
                hash_internal(tree->levels[level].nodes[left_idx].hash,
                    tree->levels[level].nodes[right_idx].hash,
                    tree->levels[level + 1].nodes[i].hash);
            }
            else {
                // 奇数节点处理：复制左节点
                memcpy(tree->levels[level + 1].nodes[i].hash,
                    tree->levels[level].nodes[left_idx].hash,
                    HASH_SIZE);
            }
        }
    }

    // 保存根哈希
    memcpy(tree->root, tree->levels[height - 1].nodes[0].hash, HASH_SIZE);

    return tree;
}
// 3. 存在性证明
// 生成存在性证明
MerkleProof * generate_proof(MerkleTree * tree, int leaf_index) {
    MerkleProof* proof = malloc(sizeof(MerkleProof));
    proof->count = tree->height - 1;
    proof->nodes = malloc(proof->count * sizeof(MerkleNode));
    proof->positions = malloc(proof->count * sizeof(int));

    int current_index = leaf_index;
    for (int level = 0; level < tree->height - 1; level++) {
        int sibling_index = (current_index % 2) ? current_index - 1 : current_index + 1;

        // 检查兄弟节点是否存在
        if (sibling_index < tree->levels[level].count) {
            memcpy(&proof->nodes[level],
                &tree->levels[level].nodes[sibling_index],
                sizeof(MerkleNode));
            proof->positions[level] = (current_index % 2) ? 0 : 1; // 0=左兄弟, 1=右兄弟
        }
        else {
            // 处理边缘情况
            proof->positions[level] = -1; // 标记无效
        }

        current_index /= 2; // 移动到父节点
    }

    return proof;
}

// 验证存在性证明
int verify_proof(const uint8_t* leaf_hash, const MerkleProof* proof,
    const uint8_t* root_hash) {
    uint8_t current_hash[HASH_SIZE];
    memcpy(current_hash, leaf_hash, HASH_SIZE);

    for (int i = 0; i < proof->count; i++) {
        if (proof->positions[i] == -1) continue; // 跳过无效节点

        uint8_t temp[1 + 2 * HASH_SIZE];
        temp[0] = 0x01; // RFC6962内部节点前缀

        if (proof->positions[i] == 0) {
            // 左兄弟
            memcpy(temp + 1, proof->nodes[i].hash, HASH_SIZE);
            memcpy(temp + 1 + HASH_SIZE, current_hash, HASH_SIZE);
        }
        else {
            // 右兄弟
            memcpy(temp + 1, current_hash, HASH_SIZE);
            memcpy(temp + 1 + HASH_SIZE, proof->nodes[i].hash, HASH_SIZE);
        }

        // 计算父节点哈希
        SM3_CTX ctx;
        sm3_init(&ctx);
        sm3_update(&ctx, temp, 1 + 2 * HASH_SIZE);
        sm3_final(current_hash, &ctx);
    }

    return memcmp(current_hash, root_hash, HASH_SIZE) == 0;
}
// 4. 不存在性证明
typedef struct {
    MerkleProof* prev_proof;
    MerkleProof* next_proof;
    uint8_t prev_leaf[HASH_SIZE];
    uint8_t next_leaf[HASH_SIZE];
} AbsenceProof;

// 生成不存在性证明
AbsenceProof* generate_absence_proof(MerkleTree* tree, int target_index) {
    // 在实际应用中，叶子节点应该是有序的
    int prev_index = target_index - 1;
    int next_index = target_index + 1;

    // 边界检查
    if (prev_index < 0 || next_index >= tree->levels[0].count) {
        return NULL;
    }

    AbsenceProof* proof = malloc(sizeof(AbsenceProof));

    // 保存相邻叶子
    memcpy(proof->prev_leaf, tree->levels[0].nodes[prev_index].hash, HASH_SIZE);
    memcpy(proof->next_leaf, tree->levels[0].nodes[next_index].hash, HASH_SIZE);

    // 生成相邻叶子的存在证明
    proof->prev_proof = generate_proof(tree, prev_index);
    proof->next_proof = generate_proof(tree, next_index);

    return proof;
}

// 验证不存在性证明
int verify_absence(const AbsenceProof* proof, const uint8_t* root_hash) {
    // 验证前驱节点
    if (!verify_proof(proof->prev_leaf, proof->prev_proof, root_hash)) {
        return 0;
    }

    // 验证后继节点
    if (!verify_proof(proof->next_leaf, proof->next_proof, root_hash)) {
        return 0;
    }

    // 在实际应用中，还应验证前驱<目标<后继
    return 1;
}