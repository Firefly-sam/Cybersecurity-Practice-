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
    int* positions; // 0=���ֵ�, 1=���ֵ�
    int count;
} MerkleProof;

//2. ������ʵ��
// RFC6962Ҷ�ӽڵ��ϣ
void hash_leaf(const uint8_t * data, size_t len, uint8_t out[HASH_SIZE]) {
    SM3_CTX ctx;
    uint8_t prefix = 0x00;
    sm3_init(&ctx);
    sm3_update(&ctx, &prefix, 1);
    sm3_update(&ctx, data, len);
    sm3_final(out, &ctx);
}

// RFC6962�ڲ��ڵ��ϣ
void hash_internal(const uint8_t* left, const uint8_t* right, uint8_t out[HASH_SIZE]) {
    SM3_CTX ctx;
    uint8_t prefix = 0x01;
    sm3_init(&ctx);
    sm3_update(&ctx, &prefix, 1);
    sm3_update(&ctx, left, HASH_SIZE);
    sm3_update(&ctx, right, HASH_SIZE);
    sm3_final(out, &ctx);
}

// ����Merkle��
MerkleTree* create_merkle_tree(uint8_t** leaf_data, int leaf_count) {
    // �������߶�
    int height = 0;
    for (int n = leaf_count; n > 0; n = (n + 1) / 2) {
        height++;
    }

    // �������ṹ
    MerkleTree* tree = malloc(sizeof(MerkleTree));
    tree->height = height;
    tree->levels = malloc(height * sizeof(MerkleLevel));

    // ����Ҷ�Ӳ�
    tree->levels[0].count = leaf_count;
    tree->levels[0].nodes = malloc(leaf_count * sizeof(MerkleNode));
    for (int i = 0; i < leaf_count; i++) {
        hash_leaf(leaf_data[i], strlen((char*)leaf_data[i]),
            tree->levels[0].nodes[i].hash);
    }

    // �Ե����Ϲ�����
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
                // �����ڵ㴦��������ڵ�
                memcpy(tree->levels[level + 1].nodes[i].hash,
                    tree->levels[level].nodes[left_idx].hash,
                    HASH_SIZE);
            }
        }
    }

    // �������ϣ
    memcpy(tree->root, tree->levels[height - 1].nodes[0].hash, HASH_SIZE);

    return tree;
}
// 3. ������֤��
// ���ɴ�����֤��
MerkleProof * generate_proof(MerkleTree * tree, int leaf_index) {
    MerkleProof* proof = malloc(sizeof(MerkleProof));
    proof->count = tree->height - 1;
    proof->nodes = malloc(proof->count * sizeof(MerkleNode));
    proof->positions = malloc(proof->count * sizeof(int));

    int current_index = leaf_index;
    for (int level = 0; level < tree->height - 1; level++) {
        int sibling_index = (current_index % 2) ? current_index - 1 : current_index + 1;

        // ����ֵܽڵ��Ƿ����
        if (sibling_index < tree->levels[level].count) {
            memcpy(&proof->nodes[level],
                &tree->levels[level].nodes[sibling_index],
                sizeof(MerkleNode));
            proof->positions[level] = (current_index % 2) ? 0 : 1; // 0=���ֵ�, 1=���ֵ�
        }
        else {
            // �����Ե���
            proof->positions[level] = -1; // �����Ч
        }

        current_index /= 2; // �ƶ������ڵ�
    }

    return proof;
}

// ��֤������֤��
int verify_proof(const uint8_t* leaf_hash, const MerkleProof* proof,
    const uint8_t* root_hash) {
    uint8_t current_hash[HASH_SIZE];
    memcpy(current_hash, leaf_hash, HASH_SIZE);

    for (int i = 0; i < proof->count; i++) {
        if (proof->positions[i] == -1) continue; // ������Ч�ڵ�

        uint8_t temp[1 + 2 * HASH_SIZE];
        temp[0] = 0x01; // RFC6962�ڲ��ڵ�ǰ׺

        if (proof->positions[i] == 0) {
            // ���ֵ�
            memcpy(temp + 1, proof->nodes[i].hash, HASH_SIZE);
            memcpy(temp + 1 + HASH_SIZE, current_hash, HASH_SIZE);
        }
        else {
            // ���ֵ�
            memcpy(temp + 1, current_hash, HASH_SIZE);
            memcpy(temp + 1 + HASH_SIZE, proof->nodes[i].hash, HASH_SIZE);
        }

        // ���㸸�ڵ��ϣ
        SM3_CTX ctx;
        sm3_init(&ctx);
        sm3_update(&ctx, temp, 1 + 2 * HASH_SIZE);
        sm3_final(current_hash, &ctx);
    }

    return memcmp(current_hash, root_hash, HASH_SIZE) == 0;
}
// 4. ��������֤��
typedef struct {
    MerkleProof* prev_proof;
    MerkleProof* next_proof;
    uint8_t prev_leaf[HASH_SIZE];
    uint8_t next_leaf[HASH_SIZE];
} AbsenceProof;

// ���ɲ�������֤��
AbsenceProof* generate_absence_proof(MerkleTree* tree, int target_index) {
    // ��ʵ��Ӧ���У�Ҷ�ӽڵ�Ӧ���������
    int prev_index = target_index - 1;
    int next_index = target_index + 1;

    // �߽���
    if (prev_index < 0 || next_index >= tree->levels[0].count) {
        return NULL;
    }

    AbsenceProof* proof = malloc(sizeof(AbsenceProof));

    // ��������Ҷ��
    memcpy(proof->prev_leaf, tree->levels[0].nodes[prev_index].hash, HASH_SIZE);
    memcpy(proof->next_leaf, tree->levels[0].nodes[next_index].hash, HASH_SIZE);

    // ��������Ҷ�ӵĴ���֤��
    proof->prev_proof = generate_proof(tree, prev_index);
    proof->next_proof = generate_proof(tree, next_index);

    return proof;
}

// ��֤��������֤��
int verify_absence(const AbsenceProof* proof, const uint8_t* root_hash) {
    // ��֤ǰ���ڵ�
    if (!verify_proof(proof->prev_leaf, proof->prev_proof, root_hash)) {
        return 0;
    }

    // ��֤��̽ڵ�
    if (!verify_proof(proof->next_leaf, proof->next_proof, root_hash)) {
        return 0;
    }

    // ��ʵ��Ӧ���У���Ӧ��֤ǰ��<Ŀ��<���
    return 1;
}