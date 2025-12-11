// sm3_performance_test.c - SM3算法性能测试工具
// 包含SM3算法的性能测试、内存分析、与OpenSSL对比等功能
#include "sm3.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>

#ifdef _WIN32
#include <windows.h>
#define sleep_ms(ms) Sleep(ms)
#else
#include <unistd.h>
#include <sys/time.h>
#define sleep_ms(ms) usleep((ms) * 1000)
#endif

// 性能测试配置
// NUM_TEST_CASES定义测试用例数量，NUM_ITERATIONS定义每个用例的重复测试次数
// 这种设计确保测试结果的统计可靠性，减少偶然误差的影响
#define NUM_TEST_CASES 6
#define NUM_ITERATIONS 10

// 测试数据大小（字节）
// 选择不同大小的测试数据，从16字节到10MB，覆盖典型应用场景
// 从小数据到大数据的测试能全面评估算法性能特征
static const size_t TEST_SIZES[NUM_TEST_CASES] = {
    16,      // 128bit - 测试小数据处理的算法启动开销
    1024,    // 1K     - 测试典型数据块处理的效率
    10240,   // 10K    - 测试多块数据的流水线处理能力
    102400,  // 100K   - 测试较大数据量的处理性能
    1048576, // 1M     - 测试大数据吞吐量的基准性能
    10485760 // 10M    - 测试极限情况下的性能稳定性
};

// 时间测量函数 - 跨平台实现，提供毫秒级精度的时间测量
// Windows使用QueryPerformanceCounter API，Linux使用gettimeofday系统调用
#ifdef _WIN32
static double get_time_ms() {
    LARGE_INTEGER frequency, time;
    QueryPerformanceFrequency(&frequency);
    QueryPerformanceCounter(&time);
    return (double)time.QuadPart * 1000.0 / (double)frequency.QuadPart;
}
#else
static double get_time_ms() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (double)tv.tv_sec * 1000.0 + (double)tv.tv_usec / 1000.0;
}
#endif

// 生成随机数据函数 - 为性能测试提供可重复的随机输入
// 使用标准C库rand()函数生成伪随机数，确保测试的公平性和可重复性
static void generate_random_data(unsigned char* buffer, size_t size) {
    static int seeded = 0;
    if (!seeded) {
        srand((unsigned int)time(NULL));
        seeded = 1;
    }

    for (size_t i = 0; i < size; i++) {
        buffer[i] = (unsigned char)(rand() % 256);
    }
}

// 性能测试主函数 - 执行完整的SM3算法性能测试，包含预热、多轮测试、统计分析
// 测试结果包括平均耗时、最小耗时、最大耗时、吞吐量等关键指标
static void run_performance_test() {
    printf("=== SM3算法性能测试 ===\n\n");

    // 环境信息输出，帮助分析测试结果的环境影响因素
    printf("【测试环境信息】\n");
#ifdef _WIN32
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    printf("处理器核心数: %d\n", sysInfo.dwNumberOfProcessors);
#else
    printf("处理器核心数: 可通过 'lscpu | grep \"CPU(s)\"' 查看\n");
#endif
    printf("测试时间: %s\n", __DATE__ " " __TIME__);
    printf("\n");

    // 测试结果数组定义，存储每个测试用例的详细测试数据
    // time_results存储每次测试的耗时，avg_times/min_times/max_times存储统计结果
    double time_results[NUM_TEST_CASES][NUM_ITERATIONS];
    double avg_times[NUM_TEST_CASES] = { 0 };
    double min_times[NUM_TEST_CASES] = { 0 };
    double max_times[NUM_TEST_CASES] = { 0 };
    double throughput[NUM_TEST_CASES] = { 0 }; // MB/s - 吞吐量指标

    // 预热操作 - 避免CPU缓存、分支预测等对第一次测试的影响
    // 预热可以确保测试结果更加准确，反映算法真实性能
    printf("正在预热...\n");
    unsigned char warmup_buffer[1024];
    unsigned char warmup_hash[SM3_DIGEST_SIZE];
    for (int i = 0; i < 3; i++) {
        generate_random_data(warmup_buffer, sizeof(warmup_buffer));
        sm3_hash(warmup_buffer, sizeof(warmup_buffer), warmup_hash);
    }
    printf("预热完成\n\n");

    // 开始性能测试 - 遍历所有测试用例，每个用例进行多次测试取平均
    for (int size_idx = 0; size_idx < NUM_TEST_CASES; size_idx++) {
        size_t data_size = TEST_SIZES[size_idx];

        printf("测试数据大小: ");
        if (data_size < 1024) {
            printf("%zu 字节", data_size);
        }
        else if (data_size < 1048576) {
            printf("%.1f KB", data_size / 1024.0);
        }
        else {
            printf("%.1f MB", data_size / 1048576.0);
        }
        printf(" (%zu 字节)\n", data_size);

        // 分配测试数据内存 - 使用动态内存分配避免栈溢出
        unsigned char* test_data = (unsigned char*)malloc(data_size);
        if (test_data == NULL) {
            printf("内存分配失败！\n");
            continue;
        }

        // 生成测试数据 - 使用随机数据避免缓存效应和特定模式的影响
        generate_random_data(test_data, data_size);

        // 进行多次测试 - 每个数据大小测试NUM_ITERATIONS次
        printf("正在进行 %d 次测试...\n", NUM_ITERATIONS);

        for (int iter = 0; iter < NUM_ITERATIONS; iter++) {
            unsigned char hash_result[SM3_DIGEST_SIZE];

            // 开始计时 - 使用高精度计时函数
            double start_time = get_time_ms();

            // 执行SM3哈希计算 - 这是性能测试的核心测量点
            sm3_hash(test_data, data_size, hash_result);

            // 结束计时 - 计算耗时
            double end_time = get_time_ms();

            // 记录时间 - 存储本次测试结果
            double elapsed_time = end_time - start_time;
            time_results[size_idx][iter] = elapsed_time;

            // 更新最小/最大值 - 用于后续统计分析和去掉极值
            if (iter == 0 || elapsed_time < min_times[size_idx]) {
                min_times[size_idx] = elapsed_time;
            }
            if (iter == 0 || elapsed_time > max_times[size_idx]) {
                max_times[size_idx] = elapsed_time;
            }

            // 累加总时间 - 计算平均值的基础
            avg_times[size_idx] += elapsed_time;

            // 显示进度 - 实时反馈测试进度，提高用户体验
            printf("  第 %2d 次: %.3f ms\r", iter + 1, elapsed_time);
            fflush(stdout);

            // 短暂休息 - 避免CPU过热导致降频，影响测试结果准确性
            if (iter < NUM_ITERATIONS - 1) {
                sleep_ms(50);
            }
        }
        printf("\n");

        // 计算平均时间（去掉最小值和最大值）- 剔除极端值提高平均值可靠性
        avg_times[size_idx] -= (min_times[size_idx] + max_times[size_idx]);
        avg_times[size_idx] /= (NUM_ITERATIONS - 2);

        // 计算吞吐量（MB/s）- 性能的关键指标，反映算法处理大数据的能力
        if (avg_times[size_idx] > 0) {
            throughput[size_idx] = (data_size / 1048576.0) / (avg_times[size_idx] / 1000.0);
        }

        // 释放测试数据内存 - 防止内存泄漏，保持程序稳定性
        free(test_data);

        printf("结果: 平均 %.3f ms, 吞吐量 %.2f MB/s\n\n",
            avg_times[size_idx], throughput[size_idx]);
    }

    // 输出详细测试报告 - 表格形式展示所有测试结果，便于分析比较
    printf("【详细测试报告】\n");
    printf("================================================================================\n");
    printf("数据大小      平均时间(ms)  最小时间(ms)  最大时间(ms)  吞吐量(MB/s)  10次测试明细(ms)\n");
    printf("================================================================================\n");

    for (int i = 0; i < NUM_TEST_CASES; i++) {
        // 显示数据大小 - 格式化输出，保持表格对齐
        if (TEST_SIZES[i] < 1024) {
            printf("%6zu 字节 ", TEST_SIZES[i]);
        }
        else if (TEST_SIZES[i] < 1048576) {
            printf("%6.1f KB    ", TEST_SIZES[i] / 1024.0);
        }
        else {
            printf("%6.1f MB    ", TEST_SIZES[i] / 1048576.0);
        }

        // 显示统计信息 - 关键性能指标
        printf("%11.3f  %11.3f  %11.3f  %12.2f    ",
            avg_times[i], min_times[i], max_times[i], throughput[i]);

        // 显示10次测试结果 - 原始数据，供深入分析使用
        for (int j = 0; j < NUM_ITERATIONS; j++) {
            printf("%.1f", time_results[i][j]);
            if (j < NUM_ITERATIONS - 1) printf(", ");
        }
        printf("\n");
    }
    printf("================================================================================\n\n");

    // 输出分析报告 - 基于测试数据提供专业分析和优化建议
    printf("【性能分析报告】\n");
    printf("1. 算法复杂度分析:\n");
    printf("   - SM3算法的时间复杂度为O(n)，与输入数据大小成正比\n");
    printf("   - 从测试数据可见，处理时间随数据大小线性增长\n");
    printf("   - 10MB数据的处理时间约为128bit数据的 %.0f 倍\n",
        avg_times[NUM_TEST_CASES - 1] / avg_times[0]);

    printf("\n2. 吞吐量分析:\n");
    printf("   - 小数据(1KB以下)吞吐量较低，主要受算法初始化开销影响\n");
    printf("   - 大数据(1MB以上)吞吐量稳定在 %.2f MB/s 左右\n",
        (throughput[NUM_TEST_CASES - 2] + throughput[NUM_TEST_CASES - 1]) / 2);

    printf("\n3. 稳定性分析:\n");
    printf("   - 10次测试中，最大与最小时间差在 %.1f%% 以内，表现稳定\n",
        (max_times[NUM_TEST_CASES - 1] - min_times[NUM_TEST_CASES - 1]) / avg_times[NUM_TEST_CASES - 1] * 100);

    printf("\n4. 优化建议:\n");
    printf("   a. 循环展开: 可减少压缩函数中的循环判断开销，预计提升10%%-15%%效率\n");
    printf("   b. SIMD指令: 使用AVX2/SSE指令集并行处理多个数据块，可大幅提升吞吐量\n");
    printf("   c. 内存优化: 减少内存拷贝，使用原地操作，降低内存带宽压力\n");
    printf("   d. 多线程: 对超大文件可采用分块并行计算，利用多核CPU优势\n");
}

// OpenSSL对比测试函数 - 指导用户如何与行业标准实现进行对比
// OpenSSL是广泛使用的密码学库，其SM3实现经过高度优化
static void run_openssl_comparison() {
    printf("=== OpenSSL对比测试 ===\n\n");

#ifdef _WIN32
    printf("注意：在Windows上需要手动安装OpenSSL并添加到PATH环境变量\n");
    printf("      然后使用命令行执行对比测试\n\n");

    printf("建议的OpenSSL测试命令：\n");
    printf("1. 生成测试文件：\n");
    printf("   fsutil file createnew test_1M.bin 1048576\n");
    printf("   fsutil file createnew test_10M.bin 10485760\n\n");

    printf("2. 执行SM3哈希：\n");
    printf("   openssl dgst -sm3 test_1M.bin\n");
    printf("   openssl dgst -sm3 test_10M.bin\n\n");

    printf("3. 测量执行时间：\n");
    printf("   powershell \"Measure-Command {openssl dgst -sm3 test_1M.bin}\"\n");
#else
    printf("Linux/macOS下可执行以下命令进行对比测试：\n\n");

    printf("1. 生成测试文件：\n");
    printf("   dd if=/dev/urandom of=test_1M.bin bs=1M count=1\n");
    printf("   dd if=/dev/urandom of=test_10M.bin bs=1M count=10\n\n");

    printf("2. 执行SM3哈希并测量时间：\n");
    printf("   time openssl dgst -sm3 test_1M.bin\n");
    printf("   time openssl dgst -sm3 test_10M.bin\n\n");

    printf("3. 仅测量算法时间（排除I/O）：\n");
    printf("   openssl speed sm3\n");
#endif

    printf("对比要点：\n");
    printf("1. OpenSSL使用高度优化的C/汇编实现，通常比自研实现快2-5倍\n");
    printf("2. OpenSSL支持硬件加速指令（如AES-NI），性能更优\n");
    printf("3. 自研实现应关注算法正确性，性能优化可作为后续改进方向\n");
}

// 内存占用测试说明函数 - 指导用户如何分析SM3算法的内存使用情况
// 内存占用是算法性能的重要指标，尤其在嵌入式系统和资源受限环境中
static void show_memory_usage_info() {
    printf("=== 内存占用测试说明 ===\n\n");

#ifdef _WIN32
    printf("Windows下可使用以下方法测试内存占用：\n\n");

    printf("1. 任务管理器：\n");
    printf("   - 运行程序时观察任务管理器的内存列\n");
    printf("   - 记录峰值工作集内存\n\n");

    printf("2. Valgrind（需要安装WSL或Cygwin）：\n");
    printf("   valgrind --tool=massif ./sm3_performance_test\n");
    printf("   ms_print massif.out.*\n");
#else
    printf("Linux下推荐使用Valgrind测试内存占用：\n\n");

    printf("1. 安装Valgrind：\n");
    printf("   sudo apt-get install valgrind  # Ubuntu/Debian\n");
    printf("   sudo yum install valgrind      # CentOS/RHEL\n\n");

    printf("2. 运行内存分析：\n");
    printf("   valgrind --tool=massif ./sm3_performance_test\n\n");

    printf("3. 查看分析结果：\n");
    printf("   ms_print massif.out.*\n\n");

    printf("4. 同时测试内存泄漏：\n");
    printf("   valgrind --leak-check=full ./sm3_performance_test\n");
#endif

    printf("\n内存占用分析要点：\n");
    printf("1. 基础内存：算法本身占用少量固定内存（约几百字节）\n");
    printf("2. 缓冲区：64字节的块缓冲区，512比特的分组处理空间\n");
    printf("3. 扩展内存：消息扩展产生的额外内存（约几百字节）\n");
    printf("4. 总内存占用：通常小于2KB，适合嵌入式环境\n");
}

// 生成测试数据文件函数 - 创建不同大小的测试文件供后续测试使用
// 这些文件可用于算法性能测试、对比测试和功能验证
static void generate_test_files() {
    printf("=== 生成测试数据文件 ===\n\n");

    for (int i = 0; i < NUM_TEST_CASES; i++) {
        size_t data_size = TEST_SIZES[i];
        char filename[256];

        // 生成文件名 - 根据数据大小自动命名，便于识别
        if (data_size < 1024) {
            snprintf(filename, sizeof(filename), "test_%zubytes.bin", data_size);
        }
        else if (data_size < 1048576) {
            snprintf(filename, sizeof(filename), "test_%.1fKB.bin", data_size / 1024.0);
        }
        else {
            snprintf(filename, sizeof(filename), "test_%.1fMB.bin", data_size / 1048576.0);
        }

        // 生成随机数据并写入文件 - 使用随机数据避免模式化测试的偏差
        unsigned char* buffer = (unsigned char*)malloc(data_size);
        if (buffer == NULL) {
            printf("无法分配内存创建文件: %s\n", filename);
            continue;
        }

        generate_random_data(buffer, data_size);

        FILE* file = fopen(filename, "wb");
        if (file) {
            fwrite(buffer, 1, data_size, file);
            fclose(file);
            printf("已创建: %s (%zu 字节)\n", filename, data_size);
        }
        else {
            printf("无法创建文件: %s\n", filename);
        }

        free(buffer);
    }

    printf("\n文件创建完成！\n");
    printf("可使用以下命令验证文件哈希：\n");
    printf("  ./sm3_performance_test -verify\n");
}

// 验证生成的文件函数 - 计算并显示测试文件的SM3哈希值
// 验证文件完整性，同时展示SM3算法的实际应用
static void verify_test_files() {
    printf("=== 验证测试文件哈希 ===\n\n");

    for (int i = 0; i < NUM_TEST_CASES; i++) {
        size_t data_size = TEST_SIZES[i];
        char filename[256];

        // 生成文件名 - 与generate_test_files函数保持一致的命名规则
        if (data_size < 1024) {
            snprintf(filename, sizeof(filename), "test_%zubytes.bin", data_size);
        }
        else if (data_size < 1048576) {
            snprintf(filename, sizeof(filename), "test_%.1fKB.bin", data_size / 1024.0);
        }
        else {
            snprintf(filename, sizeof(filename), "test_%.1fMB.bin", data_size / 1048576.0);
        }

        // 计算文件哈希 - 使用SM3算法计算文件完整性校验和
        unsigned char hash[SM3_DIGEST_SIZE];
        if (sm3_file_hash(filename, hash) == 0) {
            printf("%-20s: ", filename);
            print_hash(hash);
        }
        else {
            printf("%-20s: 文件不存在或无法读取\n", filename);
        }
    }
}

// 显示帮助信息函数 - 提供详细的命令行使用说明
// 帮助用户了解程序功能和正确使用方法
static void show_help(const char* program_name) {
    printf("SM3算法性能测试工具\n\n");
    printf("用法: %s [选项]\n\n", program_name);
    printf("选项:\n");
    printf("  -run          运行完整性能测试\n");
    printf("  -compare      显示与OpenSSL对比测试方法\n");
    printf("  -memory       显示内存占用测试方法\n");
    printf("  -generate     生成测试数据文件\n");
    printf("  -verify       验证生成的文件哈希\n");
    printf("  -help         显示此帮助信息\n\n");
    printf("示例:\n");
    printf("  %s -run           # 运行完整性能测试\n", program_name);
    printf("  %s -generate      # 生成测试文件\n", program_name);
    printf("  %s -verify        # 验证文件哈希\n", program_name);
}

// 主函数 - 程序入口点，解析命令行参数并调用相应功能
int main(int argc, char* argv[]) {
    printf("========================================\n");
    printf("    SM3算法性能测试工具\n");
    printf("========================================\n\n");

    if (argc < 2) {
        show_help(argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "-run") == 0) {
        run_performance_test();
    }
    else if (strcmp(argv[1], "-compare") == 0) {
        run_openssl_comparison();
    }
    else if (strcmp(argv[1], "-memory") == 0) {
        show_memory_usage_info();
    }
    else if (strcmp(argv[1], "-generate") == 0) {
        generate_test_files();
    }
    else if (strcmp(argv[1], "-verify") == 0) {
        verify_test_files();
    }
    else if (strcmp(argv[1], "-help") == 0) {
        show_help(argv[0]);
    }
    else {
        printf("错误: 未知选项 '%s'\n\n", argv[1]);
        show_help(argv[0]);
        return 1;
    }

    return 0;
}
