#include "sm3.h"

// SM3初始向量（GM/T 0004-2012标准）
// 这些常量是SM3算法的初始状态值，基于中国国家密码管理局的标准设定
static const uint32_t SM3_IV[8] = {
    0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600,
    0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e
};

// SM3常量T（前16轮T1=0x79cc4519，后48轮T2=0x7a879d8a）
// 这是SM3算法的固定常数数组，前16轮和后48轮使用不同的值
static const uint32_t SM3_T[64] = {
    0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519,
    0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519,
    0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519,
    0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519,
    0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,
    0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,
    0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,
    0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,
    0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,
    0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,
    0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,
    0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,
    0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,
    0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,
    0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,
    0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a
};

// FF布尔函数
// 在SM3算法中，FF函数根据轮次有不同的定义：前16轮为异或运算，后48轮为多数函数
static uint32_t ff(uint32_t x, uint32_t y, uint32_t z, int j) {
    return (j <= 15) ? (x ^ y ^ z) : ((x & y) | (x & z) | (y & z));
}

// GG布尔函数
// 在SM3算法中，GG函数根据轮次有不同的定义：前16轮为异或运算，后48轮为选择函数
static uint32_t gg(uint32_t x, uint32_t y, uint32_t z, int j) {
    return (j <= 15) ? (x ^ y ^ z) : ((x & y) | ((~x) & z));
}

// 置换函数P0
// 用于压缩函数中的线性变换，对输入x进行循环左移和异或操作
static uint32_t p0(uint32_t x) {
    return x ^ ROTLEFT(x, 9) ^ ROTLEFT(x, 17);
}

// 置换函数P1
// 用于消息扩展过程中的线性变换，对输入x进行循环左移和异或操作
static uint32_t p1(uint32_t x) {
    return x ^ ROTLEFT(x, 15) ^ ROTLEFT(x, 23);
}

// 初始化SM3上下文
// 将初始向量复制到状态寄存器，清空缓冲区和比特长度计数器
void sm3_init(SM3_CTX* ctx) {
    memcpy(ctx->state, SM3_IV, sizeof(SM3_IV));
    ctx->bitlen = 0;
    memset(ctx->buffer, 0, SM3_BLOCK_SIZE);
}

// 压缩函数（处理单个512bit分组）
// 这是SM3算法的核心函数，对每个消息分组进行压缩计算，更新哈希状态
static void sm3_compress(SM3_CTX* ctx, const unsigned char block[SM3_BLOCK_SIZE]) {
    uint32_t W[68] = { 0 }, W1[64] = { 0 };
    uint32_t A, B, C, D, E, F, G, H;
    uint32_t SS1, SS2, TT1, TT2;
    int j;

    // 步骤1：生成W[0~67] - 消息扩展过程
    // 将512位的消息分组扩展为132个字（68+64），用于后续的压缩轮运算
    for (j = 0; j < 16; j++) {
        W[j] = (uint32_t)block[j * 4] << 24 |
            (uint32_t)block[j * 4 + 1] << 16 |
            (uint32_t)block[j * 4 + 2] << 8 |
            (uint32_t)block[j * 4 + 3];
    }
    for (j = 16; j < 68; j++) {
        W[j] = p1(W[j - 16] ^ W[j - 9] ^ ROTLEFT(W[j - 3], 15)) ^
            ROTLEFT(W[j - 13], 7) ^ W[j - 6];
    }

    // 步骤2：生成W1[0~63] - 扩展后的消息字进行进一步处理
    for (j = 0; j < 64; j++) {
        W1[j] = W[j] ^ W[j + 4];
    }

    // 步骤3：初始化压缩变量
    // 将当前哈希状态赋值给工作变量，用于本轮压缩计算
    A = ctx->state[0]; B = ctx->state[1]; C = ctx->state[2]; D = ctx->state[3];
    E = ctx->state[4]; F = ctx->state[5]; G = ctx->state[6]; H = ctx->state[7];

    // 步骤4：64轮迭代（严格遵循标准）
    // 每轮使用不同的消息字和常数，通过布尔函数和置换函数更新工作变量
    for (j = 0; j < 64; j++) {
        SS1 = ROTLEFT(ROTLEFT(A, 12) + E + ROTLEFT(SM3_T[j], j), 7);
        SS2 = SS1 ^ ROTLEFT(A, 12);
        TT1 = ff(A, B, C, j) + D + SS2 + W1[j];
        TT2 = gg(E, F, G, j) + H + SS1 + W[j];

        // 更新寄存器（顺序不能错）
        // 按照SM3算法规范更新工作变量的值，实现状态转移
        D = C; C = ROTLEFT(B, 9); B = A; A = TT1;
        H = G; G = ROTLEFT(F, 19); F = E; E = p0(TT2);
    }

    // 步骤5：与初始状态异或
    // 将工作变量的结果与原始哈希状态进行异或，得到新的哈希状态
    ctx->state[0] ^= A; ctx->state[1] ^= B; ctx->state[2] ^= C; ctx->state[3] ^= D;
    ctx->state[4] ^= E; ctx->state[5] ^= F; ctx->state[6] ^= G; ctx->state[7] ^= H;
}

// 更新哈希计算
// 将新的数据块添加到哈希计算中，支持流式处理大容量数据
void sm3_update(SM3_CTX* ctx, const unsigned char* data, size_t len) {
    size_t idx = ctx->bitlen / 8 % SM3_BLOCK_SIZE;
    ctx->bitlen += len * 8;  // 总长度按bit统计

    for (size_t i = 0; i < len; i++) {
        ctx->buffer[idx++] = data[i];
        if (idx == SM3_BLOCK_SIZE) {
            sm3_compress(ctx, ctx->buffer);
            idx = 0;
        }
    }
}

// 完成哈希计算（消息填充）
// 对最后的数据块进行填充，并执行最终的压缩计算，输出256位的哈希值
void sm3_final(SM3_CTX* ctx, unsigned char digest[SM3_DIGEST_SIZE]) {
    size_t idx = ctx->bitlen / 8 % SM3_BLOCK_SIZE;

    // 步骤1：填充0x80 - 这是SM3标准的填充起始标志
    ctx->buffer[idx++] = 0x80;

    // 步骤2：填充0直到剩余8字节
    // 如果当前块空间不足64位长度信息，需要额外处理一个块
    if (idx > 56) {
        while (idx < SM3_BLOCK_SIZE) ctx->buffer[idx++] = 0x00;
        sm3_compress(ctx, ctx->buffer);
        idx = 0;
    }
    while (idx < 56) ctx->buffer[idx++] = 0x00;

    // 步骤3：填充消息长度（64bit，大端序）
    // 将原始消息的比特长度附加在末尾，符合Merkle-Damgård结构的要求
    for (int i = 0; i < 8; i++) {
        ctx->buffer[56 + i] = (ctx->bitlen >> (56 - 8 * i)) & 0xFF;
    }
    sm3_compress(ctx, ctx->buffer);

    // 步骤4：转换为字节数组（大端序）
    // 将32位状态寄存器值转换为8位字节数组，形成最终的256位哈希值
    for (int i = 0; i < 8; i++) {
        digest[i * 4] = (ctx->state[i] >> 24) & 0xFF;
        digest[i * 4 + 1] = (ctx->state[i] >> 16) & 0xFF;
        digest[i * 4 + 2] = (ctx->state[i] >> 8) & 0xFF;
        digest[i * 4 + 3] = ctx->state[i] & 0xFF;
    }
}

// 完整哈希计算（一步完成）
// 该函数提供了简化的接口，适用于一次性计算整个消息的哈希值
void sm3_hash(const unsigned char* input, size_t len, unsigned char output[SM3_DIGEST_SIZE]) {
    SM3_CTX ctx;
    sm3_init(&ctx);
    sm3_update(&ctx, input, len);
    sm3_final(&ctx, output);
}

// 哈希值转十六进制字符串
// 将256位的二进制哈希值转换为64个字符的十六进制字符串表示
char* sm3_hash_to_string(const unsigned char digest[SM3_DIGEST_SIZE]) {
    static char str[SM3_HASH_STR_LEN];
    for (int i = 0; i < SM3_DIGEST_SIZE; i++) {
        snprintf(str + 2 * i, 3, "%02x", digest[i]);
    }
    str[SM3_HASH_STR_LEN - 1] = '\0';
    return str;
}

// 打印哈希值
// 以十六进制形式输出哈希值，方便调试和查看结果
void sm3_print_hash(const unsigned char digest[SM3_DIGEST_SIZE]) {
    for (int i = 0; i < SM3_DIGEST_SIZE; i++) {
        printf("%02x", digest[i]);
    }
    printf("\n");
}

// 计算文件哈希
// 读取文件内容并计算SM3哈希值，适用于大文件的完整性校验
int sm3_file_hash(const char* filename, unsigned char output[SM3_DIGEST_SIZE]) {
    FILE* f = fopen(filename, "rb");
    if (!f) return -1;

    SM3_CTX ctx;
    sm3_init(&ctx);
    unsigned char buf[4096];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0) {
        sm3_update(&ctx, buf, n);
    }
    sm3_final(&ctx, output);
    fclose(f);
    return 0;
}

// 计算字符串哈希
// 专门为C字符串设计的便捷函数，计算字符串的SM3哈希值
int sm3_str_hash(const char* str, unsigned char output[SM3_DIGEST_SIZE]) {
    sm3_hash((const unsigned char*)str, strlen(str), output);
    return 0;
}
// 计算字符串哈希并返回十六进制字符串
// 结合哈希计算和字符串转换，提供更便捷的接口
char* sm3_hash_string(const unsigned char* input, size_t len) {
    unsigned char digest[SM3_DIGEST_SIZE];
    sm3_hash(input, len, digest);
    return sm3_hash_to_string(digest);
}

// 计算字符串哈希（兼容旧版本）
// 保持向后兼容性的函数，内部调用新的实现
int sm3_string_hash(const char* str, unsigned char output[SM3_DIGEST_SIZE]) {
    return sm3_str_hash(str, output);
}

// 打印哈希值（兼容旧版本）
// 提供旧版本函数名的兼容性支持
void print_hash(const unsigned char digest[SM3_DIGEST_SIZE]) {
    sm3_print_hash(digest);
}
