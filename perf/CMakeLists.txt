# perf/CMakeLists.txt - 性能优化模块构建配置
cmake_minimum_required(VERSION 3.20)
project(hy2_perf LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 性能优化编译选项
# ================================================
# GCC/Clang 最佳性能参数:
#   -O3                          最高优化级别
#   -march=native                本机 CPU 指令集 (自动启用 AVX2/SSE4.2/NEON)
#   -mavx2                       显式启用 AVX2 (for BLAKE2b SIMD)
#   -flto                        链接时优化 (跨编译单元内联)
#   -funroll-loops               循环展开
#   -fno-exceptions              禁用异常 (减少 unwind 表大小)
#   -fno-rtti                    禁用 RTTI (减少 vtable 开销)
#
# PGO (Profile-Guided Optimization) 流程:
#   1. g++ -O3 -march=native -fprofile-generate ... -o perf_benchInstrumented
#   2. ./perf_benchInstrumented    (运行典型工作负载)
#   3. g++ -O3 -march=native -fprofile-use ... -o perf_benchOptimized
#
# MSVC 最佳参数:
#   /O2 /Ob2 /DNDEBUG /GL /GF /arch:AVX2
#   链接: /LTCG /OPT:REF

if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    add_compile_options(
        -O3
        -march=native
        -mavx2
        -flto
        -funroll-loops
        -finline-functions
        -ffast-math           # 浮点优化 (对整数无影响)
        -DNDEBUG
    )
    add_link_options(-flto)
elseif(MSVC)
    add_compile_options(
        /O2 /Ob2 /DNDEBUG /GL /GF
        /arch:AVX2
    )
    add_link_options(/LTCG /OPT:REF)
endif()

# Perf benchmark 可执行文件
add_executable(perf_bench perf_benchmark.cpp)
target_include_directories(perf_bench PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

# 链接 pthread (Linux)
find_package(Threads REQUIRED)
target_link_libraries(perf_bench PRIVATE Threads::Threads)
