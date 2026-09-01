// coro_task.hpp - C++20 协程 (MSVC 兼容版本)
// 注意: MSVC 对 C++20 协程的支持需要 /await:strict 或较新版本
// 这里提供简化版本，核心性能模块在其他文件中
#pragma once

// 检测协程支持
#if defined(_MSC_VER) && _MSC_VER < 1929
// MSVC 2019 16.10 以下不完整支持 C++20 协程
#define HY2_CORO_SUPPORTED 0
#else
#define HY2_CORO_SUPPORTED 1
#endif

#if HY2_CORO_SUPPORTED
#include <coroutine>
#include <cstdint>
#include <optional>
#include <utility>

namespace hy2::perf {

template <typename T = void>
class Task;

template <>
class Task<void> {
public:
    struct promise_type {
        Task get_return_object() { return Task{}; }
        std::suspend_never initial_suspend() noexcept { return {}; }
        std::suspend_always final_suspend() noexcept { return {}; }
        void return_void() {}
        void unhandled_exception() {}
    };
};

} // namespace hy2::perf
#endif // HY2_CORO_SUPPORTED
