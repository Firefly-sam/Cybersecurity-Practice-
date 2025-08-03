pragma circom 2.1.6;

include "../../node_modules/circomlib/circuits/poseidon.circom";

// 完整的 Full Round 操作 (带约束)
template FullRound(round_constants, mds) {
    signal input state_in[2];
    signal output state_out[2];
    
    // AddRoundConstants
    signal after_arc[2];
    after_arc[0] <== state_in[0] + round_constants[0];
    after_arc[1] <== state_in[1] + round_constants[1];
    
    // S-box (x^5)
    signal after_sbox[2];
    after_sbox[0] <== after_arc[0] * after_arc[0];  // x^2
    after_sbox[0] <== after_sbox[0] * after_sbox[0]; // x^4
    after_sbox[0] <== after_sbox[0] * after_arc[0]; // x^5
    
    after_sbox[1] <== after_arc[1] * after_arc[1];
    after_sbox[1] <== after_sbox[1] * after_sbox[1];
    after_sbox[1] <== after_sbox[1] * after_arc[1];
    
    // MixLayer (Matrix Multiplication)
    state_out[0] <== mds[0][0]*after_sbox[0] + mds[0][1]*after_sbox[1];
    state_out[1] <== mds[1][0]*after_sbox[0] + mds[1][1]*after_sbox[1];
}

// 部分 Partial Round 操作 (带约束)
template PartialRound(round_constants, mds) {
    signal input state_in[2];
    signal output state_out[2];
    
    // AddRoundConstants
    signal after_arc[2];
    after_arc[0] <== state_in[0] + round_constants[0];
    after_arc[1] <== state_in[1] + round_constants[1];
    
    // 只对第一个元素应用 S-box
    signal after_sbox[2];
    after_sbox[0] <== after_arc[0] * after_arc[0];  // x^2
    after_sbox[0] <== after_sbox[0] * after_sbox[0]; // x^4
    after_sbox[0] <== after_sbox[0] * after_arc[0];  // x^5
    after_sbox[1] <== after_arc[1];  // 第二个元素不变
    
    // MixLayer
    state_out[0] <== mds[0][0]*after_sbox[0] + mds[0][1]*after_sbox[1];
    state_out[1] <== mds[1][0]*after_sbox[0] + mds[1][1]*after_sbox[1];
}

// 主 Poseidon2 模板
template Poseidon2() {
    // 参数: (n, t, d) = (256, 2, 5)
    // 轮数配置 (R_F = 8, R_P = 56)
    var R_F = 8;        // 完整轮数
    var R_P = 56;       // 部分轮数
    var ROUNDS = R_F + R_P;
    
    // MDS 矩阵 (实际值应来自安全参数)
    var MDS = [
        [2, 1],
        [1, 3]
    ];
    
    // 状态初始化 (使用 CircomLib Poseidon 的常量)
    var round_constants[128];
    
    // 临时: 从 CircomLib 的 Poseidon 获取轮常量 (实际应为不同)
    component poseidon = Poseidon(2, 8, 57);
    for (var i = 0; i < 128; i++) {
        round_constants[i] = poseidon.C[i];
    }
    
    // 输入输出定义
    signal input in;
    signal output out;
    
    // 状态初始化
    signal state[ROUNDS + 1][2];
    
    // 初始状态
    state[0][0] <== in;   // 输入
    state[0][1] <== 0;    // 填充位
    
    // 轮函数处理
    var rc_index = 0;
    
    // 前 R_F/2 个完整轮 (4)
    for (var r = 0; r < R_F/2; r++) {
        component full = FullRound(
            [round_constants[rc_index], round_constants[rc_index + 1]], 
            MDS
        );
        rc_index += 2;
        
        full.state_in[0] <== state[r][0];
        full.state_in[1] <== state[r][1];
        
        state[r + 1][0] <== full.state_out[0];
        state[r + 1][1] <== full.state_out[1];
    }
    
    // R_P 个部分轮 (56)
    for (var r = R_F/2; r < R_F/2 + R_P; r++) {
        component partial = PartialRound(
            [round_constants[rc_index], round_constants[rc_index + 1]], 
            MDS
        );
        rc_index += 2;
        
        partial.state_in[0] <== state[r][0];
        partial.state_in[1] <== state[r][1];
        
        state[r + 1][0] <== partial.state_out[0];
        state[r + 1][1] <== partial.state_out[1];
    }
    
    // 后 R_F/2 个完整轮 (4)
    for (var r = R_F/2 + R_P; r < R_F + R_P; r++) {
        component full = FullRound(
            [round_constants[rc_index], round_constants[rc_index + 1]], 
            MDS
        );
        rc_index += 2;
        
        full.state_in[0] <== state[r][0];
        full.state_in[1] <== state[r][1];
        
        state[r + 1][0] <== full.state_out[0];
        state[r + 1][1] <== full.state_out[1];
    }
    
    // 输出最终状态 (哈希值)
    out <== state[ROUNDS][0];
}

// Groth16 证明系统入口
template Main() {
    signal private input preimage;  // 隐私输入: 哈希原象
    signal public input hash;       // 公开输入: 哈希值
    
    component hasher = Poseidon2();
    hasher.in <== preimage;
    
    // 验证哈希值匹配
    hash === hasher.out;
}