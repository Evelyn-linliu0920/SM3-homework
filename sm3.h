#ifndef SM3_H
#define SM3_H

// 标准库头文件引入
#include <stdio.h>    // 标准输入输出
#include <stdlib.h>   // 标准库函数
#include <string.h>   // 字符串操作
#include <stdint.h>   // 固定宽度整数类型

// Windows平台安全警告禁用
#ifdef _WIN32
#define _CRT_SECURE_NO_WARNINGS
#endif

// SM3算法常量定义
#define SM3_BLOCK_SIZE 64    // SM3分组大小（字节）
#define SM3_DIGEST_SIZE 32   // SM3哈希值大小（字节）
#define SM3_HASH_SIZE 65     // 十六进制哈希字符串大小（64字符 + 终止符）

// 循环左移宏定义
#define ROTLEFT(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

/**
 * @brief SM3算法上下文结构体
 * 
 * 用于维护SM3哈希计算过程中的中间状态
 */
typedef struct {
    uint32_t state[8];           // 8个32位状态变量（A,B,C,D,E,F,G,H）
    uint64_t bitlen;             // 已处理消息的总位数
    unsigned char buffer[SM3_BLOCK_SIZE];  // 消息缓冲区（512位）
} SM3_CTX;

// 函数声明

/**
 * @brief 初始化SM3上下文
 * @param ctx SM3上下文指针
 */
void sm3_init(SM3_CTX* ctx);

/**
 * @brief 更新哈希计算（处理输入数据）
 * @param ctx SM3上下文指针
 * @param data 输入数据指针
 * @param len 输入数据长度
 */
void sm3_update(SM3_CTX* ctx, const unsigned char* data, size_t len);

/**
 * @brief 完成哈希计算，输出最终结果
 * @param ctx SM3上下文指针
 * @param digest 输出的哈希值数组（32字节）
 */
void sm3_final(SM3_CTX* ctx, unsigned char digest[SM3_DIGEST_SIZE]);

/**
 * @brief 计算数据的SM3哈希值（简化接口）
 * @param input 输入数据
 * @param input_len 输入数据长度
 * @param output 输出的哈希值
 */
void sm3_hash(const unsigned char* input, size_t input_len, unsigned char output[SM3_DIGEST_SIZE]);

/**
 * @brief 计算数据的SM3哈希值并返回十六进制字符串
 * @param input 输入数据
 * @param input_len 输入数据长度
 * @return 64字符的十六进制哈希字符串
 */
char* sm3_hash_string(const unsigned char* input, size_t input_len);

/**
 * @brief 打印哈希值
 * @param hash 哈希值数组
 */
void print_hash(const unsigned char hash[SM3_DIGEST_SIZE]);

/**
 * @brief 计算文件的SM3哈希值
 * @param filename 文件名
 * @param output 输出的哈希值
 * @return 成功返回0，失败返回-1
 */
int sm3_file_hash(const char* filename, unsigned char output[SM3_DIGEST_SIZE]);

/**
 * @brief 计算字符串的SM3哈希值
 * @param input 输入字符串
 * @param output 输出的哈希值
 * @return 成功返回0
 */
int sm3_string_hash(const char* input, unsigned char output[SM3_DIGEST_SIZE]);

#endif
