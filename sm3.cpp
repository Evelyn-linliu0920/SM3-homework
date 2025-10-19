#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

// SM3 算法常量定义
#define SM3_BLOCK_SIZE 64       // SM3 分组长度（字节）
#define SM3_HASH_SIZE 32        // SM3 哈希值长度（字节）
#define SM3_IV_NUM 8            // SM3 初始向量数量（8个32位字）
#define SM3_ITER_ROUNDS 64      // SM3 迭代轮数

// SM3 常量 Tj：前16轮使用 0x79CC4519，后48轮使用 0x7A879D8A
static const uint32_t T[SM3_ITER_ROUNDS] = {
    0x79CC4519, 0x79CC4519, 0x79CC4519, 0x79CC4519,
    0x79CC4519, 0x79CC4519, 0x79CC4519, 0x79CC4519,
    0x79CC4519, 0x79CC4519, 0x79CC4519, 0x79CC4519,
    0x79CC4519, 0x79CC4519, 0x79CC4519, 0x79CC4519,
    0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
    0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
    0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
    0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
    0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
    0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
    0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
    0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
    0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
    0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
    0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
    0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A
};

// SM3 初始值 IV（8个32位字）
static const uint32_t IV[SM3_IV_NUM] = {
    0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
    0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E
};
// 循环左移宏：将32位字x循环左移n位
#define ROL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

// 布尔函数 FFj：前16轮使用异或，后48轮使用多数函数
static uint32_t FF(uint32_t X, uint32_t Y, uint32_t Z, int j) {
    return (j < 16) ? (X ^ Y ^ Z) : ((X & Y) | (X & Z) | (Y & Z));
}

// 布尔函数 GGj：前16轮使用异或，后48轮使用选择函数
static uint32_t GG(uint32_t X, uint32_t Y, uint32_t Z, int j) {
    return (j < 16) ? (X ^ Y ^ Z) : ((X & Y) | ((~X) & Z));
}

// 置换函数 P0
static uint32_t P0(uint32_t X) {
    return X ^ ROL(X, 9) ^ ROL(X, 17);
}

// 置换函数 P1
static uint32_t P1(uint32_t X) {
    return X ^ ROL(X, 15) ^ ROL(X, 23);
}

/**
 * @brief SM3 消息填充函数
 * @param input 输入消息指针
 * @param len 输入消息长度（字节）
 * @param output 输出填充后消息指针的指针（需要调用者释放内存）
 * @param out_len 输出填充后消息长度
 * 
 * 填充规则：
 * 1. 在消息末尾添加一个'1'位（0x80）
 * 2. 添加若干个'0'位直到长度满足 (长度 % 512) = 448
 * 3. 最后64位存储原始消息的位长度
 */
static void sm3_padding(const uint8_t* input, size_t len, uint8_t** output, size_t* out_len) {
    if (input == NULL || output == NULL || out_len == NULL) return;

    // 计算原始消息的位长度
    size_t bit_len = len * 8;
    
    // 计算填充后的最小长度：原始长度 + 1字节(0x80) + 8字节(长度字段)
    size_t pad_min_len = len + 1 + 8;
    
    // 计算完整的填充后长度（SM3_BLOCK_SIZE的整数倍）
    *out_len = ((pad_min_len + SM3_BLOCK_SIZE - 1) / SM3_BLOCK_SIZE) * SM3_BLOCK_SIZE;

    // 分配填充后的消息内存
    *output = (uint8_t*)malloc(*out_len);
    if (*output == NULL) {
        fprintf(stderr, "内存分配失败：sm3_padding\n");
        *out_len = 0;
        return;
    }
    
    // 初始化填充后消息为0，并拷贝原始消息
    memset(*output, 0, *out_len);
    memcpy(*output, input, len);

    // 添加填充位：首先添加一个'1'位（0x80）
    (*output)[len] = 0x80;

    // 在最后8字节添加原始消息的位长度（大端序）
    for (int i = 0; i < 8; i++) {
        (*output)[*out_len - 8 + i] = (bit_len >> ((7 - i) * 8)) & 0xFF;
    }
}

/**
 * @brief 消息扩展函数：将512位消息块扩展为132个字（W和W1）
 * @param block 输入消息块（512位，64字节）
 * @param W 扩展后的消息字数组（68个）
 * @param W1 派生消息字数组（64个）
 */
static void message_expansion(const uint8_t* block, uint32_t W[68], uint32_t W1[64]) {
    if (block == NULL || W == NULL || W1 == NULL) return;

    // 步骤1：将512位消息块划分为16个32位字
    for (int i = 0; i < 16; i++) {
        W[i] = ((uint32_t)block[i * 4 + 0] << 24) |
               ((uint32_t)block[i * 4 + 1] << 16) |
               ((uint32_t)block[i * 4 + 2] << 8) |
               ((uint32_t)block[i * 4 + 3] << 0);
    }

    // 步骤2：扩展生成W[16]到W[67]
    for (int i = 16; i < 68; i++) {
        W[i] = P1(W[i - 16] ^ W[i - 9] ^ ROL(W[i - 3], 15)) ^
               ROL(W[i - 13], 7) ^ W[i - 6];
    }

    // 步骤3：生成W1[0]到W1[63]
    for (int i = 0; i < 64; i++) {
        W1[i] = W[i] ^ W[i + 4];
    }
}
