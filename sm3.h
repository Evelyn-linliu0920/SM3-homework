// sm3.h
#ifndef SM3_H
#define SM3_H

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#define SM3_BLOCK_SIZE 64    // 512bit分组大小
#define SM3_DIGEST_SIZE 32   // 256bit哈希结果
#define SM3_HASH_STR_LEN 65  // 十六进制字符串长度（64字符+终止符）

// 循环左移宏
#define ROTLEFT(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

// SM3上下文结构体
typedef struct {
    uint32_t state[8];       // 压缩寄存器（A-H）
    uint64_t bitlen;         // 消息总长度（bit）
    unsigned char buffer[SM3_BLOCK_SIZE];  // 分组缓冲区
} SM3_CTX;

// 算法核心接口
void sm3_init(SM3_CTX* ctx);
void sm3_update(SM3_CTX* ctx, const unsigned char* data, size_t len);
void sm3_final(SM3_CTX* ctx, unsigned char digest[SM3_DIGEST_SIZE]);
void sm3_hash(const unsigned char* input, size_t len, unsigned char output[SM3_DIGEST_SIZE]);

// 辅助工具接口
char* sm3_hash_to_string(const unsigned char digest[SM3_DIGEST_SIZE]);
void sm3_print_hash(const unsigned char digest[SM3_DIGEST_SIZE]);
int sm3_file_hash(const char* filename, unsigned char output[SM3_DIGEST_SIZE]);
int sm3_str_hash(const char* str, unsigned char output[SM3_DIGEST_SIZE]);

// 新增函数声明（解决链接错误）
char* sm3_hash_string(const unsigned char* input, size_t len);
int sm3_string_hash(const char* str, unsigned char output[SM3_DIGEST_SIZE]);
void print_hash(const unsigned char digest[SM3_DIGEST_SIZE]);

#endif
