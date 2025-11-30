#include "sm3.h"

/**
 * SM3算法初始向量（IV）
 * 
 * 根据GM/T 0004-2012标准定义，包含8个32位字
 * 这些初始值在算法开始时加载到状态变量中
 */
static const uint32_t SM3_IV[8] = {
    0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600,
    0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e
};

/**
 * SM3常量T
 * 
 * 用于压缩函数中的轮迭代计算
 * - 前16轮使用常量 0x79cc4519
 * - 后48轮使用常量 0x7a879d8a
 */
static const uint32_t SM3_T[64] = {
    0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519,  // 第1-4轮
    0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519,  // 第5-8轮
    0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519,  // 第9-12轮
    0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519,  // 第13-16轮
    0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,  // 第17-20轮
    0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,  // 第21-24轮
    0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,  // 第25-28轮
    0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,  // 第29-32轮
    0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,  // 第33-36轮
    0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,  // 第37-40轮
    0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,  // 第41-44轮
    0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,  // 第45-48轮
    0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,  // 第49-52轮
    0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,  // 第53-56轮
    0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,  // 第57-60轮
    0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a   // 第61-64轮
};

/**
 * @brief FF布尔函数
 * 
 * 根据轮数j的不同使用不同的逻辑：
 * - j=0-15: 使用异或逻辑 FF(X,Y,Z) = X ⊕ Y ⊕ Z
 * - j=16-63: 使用多数逻辑 FF(X,Y,Z) = (X ∧ Y) ∨ (X ∧ Z) ∨ (Y ∧ Z)
 * 
 * @param x,y,z 输入字
 * @param j 轮数（0-63）
 * @return 计算结果
 */
static uint32_t ff(uint32_t x, uint32_t y, uint32_t z, int j) {
    if (j >= 0 && j <= 15)
        return x ^ y ^ z;           // 异或逻辑
    else
        return (x & y) | (x & z) | (y & z);  // 多数逻辑
}

/**
 * @brief GG布尔函数
 * 
 * 根据轮数j的不同使用不同的逻辑：
 * - j=0-15: 使用异或逻辑 GG(X,Y,Z) = X ⊕ Y ⊕ Z
 * - j=16-63: 使用选择逻辑 GG(X,Y,Z) = (X ∧ Y) ∨ (¬X ∧ Z)
 * 
 * @param x,y,z 输入字
 * @param j 轮数（0-63）
 * @return 计算结果
 */
static uint32_t gg(uint32_t x, uint32_t y, uint32_t z, int j) {
    if (j >= 0 && j <= 15)
        return x ^ y ^ z;           // 异或逻辑
    else
        return (x & y) | ((~x) & z);  // 选择逻辑
}

/**
 * @brief 置换函数P0
 * 
 * P0(X) = X ⊕ (X <<< 9) ⊕ (X <<< 17)
 * 用于压缩函数中TT2的处理
 * 
 * @param x 输入字
 * @return 置换后的字
 */
static uint32_t p0(uint32_t x) {
    return x ^ ROTLEFT(x, 9) ^ ROTLEFT(x, 17);
}

/**
 * @brief 置换函数P1
 * 
 * P1(X) = X ⊕ (X <<< 15) ⊕ (X <<< 23)
 * 用于消息扩展过程中
 * 
 * @param x 输入字
 * @return 置换后的字
 */
static uint32_t p1(uint32_t x) {
    return x ^ ROTLEFT(x, 15) ^ ROTLEFT(x, 23);
}

/**
 * @brief 初始化SM3上下文
 * 
 * 将初始向量复制到状态变量，初始化位长度和缓冲区
 * 
 * @param ctx SM3上下文指针
 */
void sm3_init(SM3_CTX* ctx) {
    memcpy(ctx->state, SM3_IV, sizeof(SM3_IV));  // 复制初始向量
    ctx->bitlen = 0;                             // 重置位长度计数器
    memset(ctx->buffer, 0, SM3_BLOCK_SIZE);      // 清空消息缓冲区
}

/**
 * @brief SM3压缩函数（内部函数）
 * 
 * 处理单个512位消息分组，包含：
 * 1. 消息扩展：将16个字扩展为132个字
 * 2. 64轮迭代计算
 * 3. 更新状态变量
 * 
 * @param ctx SM3上下文指针
 * @param block 512位消息分组
 */
static void sm3_compress(SM3_CTX* ctx, const unsigned char block[SM3_BLOCK_SIZE]) {
    uint32_t W[68], W1[64];      // 扩展字数组
    uint32_t A, B, C, D, E, F, G, H;  // 临时状态变量
    uint32_t SS1, SS2, TT1, TT2;      // 中间计算结果
    int j;

    // ==================== 消息扩展阶段 ====================
    
    // 步骤1：将512位分组划分为16个32位字
    for (j = 0; j < 16; j++) {
        // 将4个字节组合为1个32位字（大端序）
        W[j] = (uint32_t)block[j * 4] << 24 |
               (uint32_t)block[j * 4 + 1] << 16 |
               (uint32_t)block[j * 4 + 2] << 8 |
               (uint32_t)block[j * 4 + 3];
    }

    // 步骤2：扩展生成W[16]到W[67]
    for (j = 16; j < 68; j++) {
        W[j] = p1(W[j - 16] ^ W[j - 9] ^ ROTLEFT(W[j - 3], 15)) ^ 
               ROTLEFT(W[j - 13], 7) ^ W[j - 6];
    }

    // 步骤3：生成W1[0]到W1[63]
    for (j = 0; j < 64; j++) {
        W1[j] = W[j] ^ W[j + 4];
    }

    // ==================== 压缩函数阶段 ====================
    
    // 初始化临时状态变量（从上下文复制当前状态）
    A = ctx->state[0];
    B = ctx->state[1];
    C = ctx->state[2];
    D = ctx->state[3];
    E = ctx->state[4];
    F = ctx->state[5];
    G = ctx->state[6];
    H = ctx->state[7];

    // 64轮迭代计算
    for (j = 0; j < 64; j++) {
        // 计算中间值SS1和SS2
        SS1 = ROTLEFT((ROTLEFT(A, 12) + E + ROTLEFT(SM3_T[j], j)), 7);
        SS2 = SS1 ^ ROTLEFT(A, 12);
        
        // 计算TT1和TT2
        TT1 = ff(A, B, C, j) + D + SS2 + W1[j];
        TT2 = gg(E, F, G, j) + H + SS1 + W[j];
        
        // ========== 并行更新状态变量 ==========
        // 注意：这是并行赋值，需要使用临时变量保存旧值
        D = C;                    // D <- C
        C = ROTLEFT(B, 9);        // C <- B <<< 9
        B = A;                    // B <- A
        A = TT1;                  // A <- TT1
        H = G;                    // H <- G
        G = ROTLEFT(F, 19);       // G <- F <<< 19
        F = E;                    // F <- E
        E = p0(TT2);              // E <- P0(TT2)
    }

    // ==================== 更新状态阶段 ====================
    
    // 将临时状态与原始状态进行异或操作
    ctx->state[0] ^= A;
    ctx->state[1] ^= B;
    ctx->state[2] ^= C;
    ctx->state[3] ^= D;
    ctx->state[4] ^= E;
    ctx->state[5] ^= F;
    ctx->state[6] ^= G;
    ctx->state[7] ^= H;
}

/**
 * @brief 更新哈希计算（处理输入数据）
 * 
 * 将输入数据添加到消息缓冲区，当缓冲区满时调用压缩函数
 * 支持处理任意长度的数据（流式处理）
 * 
 * @param ctx SM3上下文指针
 * @param data 输入数据指针
 * @param len 输入数据长度
 */
void sm3_update(SM3_CTX* ctx, const unsigned char* data, size_t len) {
    size_t i;
    size_t idx = ctx->bitlen / 8 % SM3_BLOCK_SIZE;  // 当前缓冲区位置

    // 更新总位数（注意：长度以位为单位）
    ctx->bitlen += len * 8;

    // 逐个字节处理输入数据
    for (i = 0; i < len; i++) {
        ctx->buffer[idx++] = data[i];  // 将数据字节存入缓冲区
        
        // 如果缓冲区已满（512位），调用压缩函数处理
        if (idx == SM3_BLOCK_SIZE) {
            sm3_compress(ctx, ctx->buffer);
            idx = 0;  // 重置缓冲区索引
        }
    }
}

/**
 * @brief 完成哈希计算，输出最终结果
 * 
 * 执行消息填充，处理最后一个分组，输出最终哈希值
 * 填充规则：1个"1"比特 + k个"0"比特 + 64位长度
 * 
 * @param ctx SM3上下文指针
 * @param digest 输出的哈希值数组（32字节）
 */
void sm3_final(SM3_CTX* ctx, unsigned char digest[SM3_DIGEST_SIZE]) {
    size_t idx = ctx->bitlen / 8 % SM3_BLOCK_SIZE;  // 当前缓冲区位置

    // ==================== 消息填充阶段 ====================
    
    // 步骤1：添加填充位"1"（0x80 = 10000000二进制）
    ctx->buffer[idx++] = 0x80;

    // 步骤2：如果剩余空间不足64位（8字节）存放长度信息
    if (idx > 56) {
        // 用0填充剩余缓冲区并处理当前分组
        while (idx < SM3_BLOCK_SIZE)
            ctx->buffer[idx++] = 0x00;
        sm3_compress(ctx, ctx->buffer);
        idx = 0;  // 重置索引，开始新的分组
    }

    // 步骤3：用0填充直到56字节位置（为长度信息预留8字节）
    while (idx < 56)
        ctx->buffer[idx++] = 0x00;

    // 步骤4：添加消息长度（64位，大端序存储）
    // 注意：长度以位为单位，需要转换为字节存储
    for (int i = 0; i < 8; i++) {
        ctx->buffer[56 + i] = (ctx->bitlen >> (56 - 8 * i)) & 0xFF;
    }

    // ==================== 最终处理阶段 ====================
    
    // 处理填充后的最后一个分组
    sm3_compress(ctx, ctx->buffer);

    // ==================== 输出格式化阶段 ====================
    
    // 将8个32位状态变量转换为32字节的哈希值（大端序）
    for (int i = 0; i < 8; i++) {
        digest[i * 4] = (ctx->state[i] >> 24) & 0xFF;      // 最高字节
        digest[i * 4 + 1] = (ctx->state[i] >> 16) & 0xFF;  // 次高字节
        digest[i * 4 + 2] = (ctx->state[i] >> 8) & 0xFF;   // 次低字节
        digest[i * 4 + 3] = ctx->state[i] & 0xFF;          // 最低字节
    }
}

/**
 * @brief 计算数据的SM3哈希值（简化接口）
 * 
 * 一次性计算整个输入数据的哈希值，适用于已知全部数据的情况
 * 
 * @param input 输入数据
 * @param input_len 输入数据长度
 * @param output 输出的哈希值
 */
void sm3_hash(const unsigned char* input, size_t input_len, unsigned char output[SM3_DIGEST_SIZE]) {
    SM3_CTX ctx;
    sm3_init(&ctx);                     // 初始化上下文
    sm3_update(&ctx, input, input_len); // 处理输入数据
    sm3_final(&ctx, output);            // 完成计算并输出
}

/**
 * @brief 计算数据的SM3哈希值并返回十六进制字符串
 * 
 * 将二进制哈希值转换为可读的十六进制字符串形式
 * 
 * @param input 输入数据
 * @param input_len 输入数据长度
 * @return 64字符的十六进制哈希字符串（静态存储，非线程安全）
 */
char* sm3_hash_string(const unsigned char* input, size_t input_len) {
    static char hash_str[SM3_HASH_SIZE];  // 静态存储哈希字符串
    unsigned char digest[SM3_DIGEST_SIZE]; // 临时存储二进制哈希值
    int i;

    // 计算二进制哈希值
    sm3_hash(input, input_len, digest);

    // 将每个字节转换为2个十六进制字符
    for (i = 0; i < SM3_DIGEST_SIZE; i++) {
        snprintf(hash_str + i * 2, 3, "%02x", digest[i]);
    }
    hash_str[SM3_HASH_SIZE - 1] = '\0';  // 添加字符串终止符

    return hash_str;
}

/**
 * @brief 打印哈希值
 * 
 * 以十六进制形式输出哈希值到标准输出
 * 
 * @param hash 哈希值数组
 */
void print_hash(const unsigned char hash[SM3_DIGEST_SIZE]) {
    int i;
    for (i = 0; i < SM3_DIGEST_SIZE; i++) {
        printf("%02x", hash[i]);  // 每个字节输出为2位十六进制
    }
    printf("\n");
}

/**
 * @brief 计算文件的SM3哈希值
 * 
 * 读取文件内容并计算其SM3哈希值，支持大文件处理
 * 
 * @param filename 文件名
 * @param output 输出的哈希值
 * @return 成功返回0，失败返回-1
 */
int sm3_file_hash(const char* filename, unsigned char output[SM3_DIGEST_SIZE]) {
    FILE* file = NULL;
    unsigned char buffer[4096];  // 文件读取缓冲区
    size_t bytes_read;           // 实际读取的字节数
    SM3_CTX ctx;

    // 安全打开文件（跨平台）
#ifdef _WIN32
    if (fopen_s(&file, filename, "rb") != 0) {
        return -1;  // 文件打开失败
    }
#else
    file = fopen(filename, "rb");
    if (file == NULL) {
        return -1;  // 文件打开失败
    }
#endif

    sm3_init(&ctx);  // 初始化SM3上下文

    // 循环读取文件内容并更新哈希计算
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        sm3_update(&ctx, buffer, bytes_read);
    }

    sm3_final(&ctx, output);  // 完成计算
    fclose(file);             // 关闭文件

    return 0;  // 成功返回
}

/**
 * @brief 计算字符串的SM3哈希值
 * 
 * 计算以null结尾的字符串的SM3哈希值
 * 
 * @param input 输入字符串
 * @param output 输出的哈希值
 * @return 成功返回0
 */
int sm3_string_hash(const char* input, unsigned char output[SM3_DIGEST_SIZE]) {
    // 直接调用sm3_hash函数，使用strlen获取字符串长度
    sm3_hash((const unsigned char*)input, strlen(input), output);
    return 0;
}
