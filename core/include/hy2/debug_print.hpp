// debug_print.hpp - Compile-time-gated debug printing utilities for hy2.
// Only active when _DEBUG is defined; zero overhead in release builds.
#pragma once

#ifdef _DEBUG

#include <chrono>
#include <cstdio>
#include <iostream>
#include <string_view>
#include <sstream>
#include <type_traits>

namespace hy2::debug {

// ---------------------------------------------------------------------------
// Internal: format a single value into a stream.
// ---------------------------------------------------------------------------
inline void FormatOne(std::ostringstream&) {}

template <typename T>
void FormatOne(std::ostringstream& oss, const T& v) {
    if constexpr (std::is_same_v<T, bool>) {
        oss << (v ? "true" : "false");
    } else if constexpr (std::is_integral_v<T> || std::is_floating_point_v<T>) {
        oss << v;
    } else if constexpr (std::is_convertible_v<T, std::string_view>) {
        oss << std::string_view(v);
    } else {
        oss << "[unprintable]";
    }
}

// ---------------------------------------------------------------------------
// Internal: format args as "[a] [b] [c]".
// ---------------------------------------------------------------------------
template <typename... Args>
std::string FormatArgs(const Args&... args) {
    std::ostringstream oss;
    bool first = true;
    ((first ? (first = false, (oss << '['), FormatOne(oss, args), oss << ']')
            : (oss << " [", FormatOne(oss, args), oss << ']')),
     ...);
    return oss.str();
}

// ---------------------------------------------------------------------------
// Print: variadic template, prints each argument in brackets.
//   hy2::debug::Print("hello", 42, 3.14);
//   -> [hello] [42] [3.14]
// ---------------------------------------------------------------------------
template <typename... Args>
void Print(const Args&... args) {
    std::cerr << FormatArgs(args...) << '\n';
}

// ---------------------------------------------------------------------------
// Log: same as Print, but prepends [file:line] and a timestamp.
//   hy2::debug::Log(__FILE__, __LINE__, "msg", 99);
//   -> [2026-08-30 12:34:56.789] [main.cpp:42] [msg] [99]
// ---------------------------------------------------------------------------
template <typename... Args>
void Log(std::string_view file, int line, const Args&... args) {
    using namespace std::chrono;
    auto now = system_clock::now();
    auto ms  = duration_cast<milliseconds>(now.time_since_epoch()) % 1000;
    auto tt  = system_clock::to_time_t(now);

    char timeBuf[32];
    std::strftime(timeBuf, sizeof(timeBuf), "%Y-%m-%d %H:%M:%S", std::localtime(&tt));

    std::cerr << '[' << timeBuf << '.' << ms.count() << ']'
              << " [" << file << ':' << line << ']'
              << ' ' << FormatArgs(args...) << '\n';
}

} // namespace hy2::debug

// Convenience macros — expand to nothing when _DEBUG is not defined.
#define DBG(...)     ::hy2::debug::Print(__VA_ARGS__)
#define DBG_LOG(...) ::hy2::debug::Log(__FILE__, __LINE__, __VA_ARGS__)

#else // _DEBUG not defined — zero overhead

#define DBG(...)
#define DBG_LOG(...)

#endif // _DEBUG
