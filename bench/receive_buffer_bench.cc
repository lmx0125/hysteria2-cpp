// Standalone A/B of the old stream buffer and the production receive FIFO.
// Usage: hy2_receive_buffer_bench [MiB transferred, default 256]
#include "hy2/detail/receive_buffer.hpp"
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <vector>

struct OldBuffer {
    std::vector<uint8_t> data;
    size_t pos = 0;
    void Append(const uint8_t* p, size_t n) { data.insert(data.end(), p, p + n); }
    size_t Read(uint8_t* p, size_t n) {
        const size_t take = std::min(n, data.size() - pos);
        std::memcpy(p, data.data() + pos, take);
        pos += take;
        if (pos == data.size()) { data.clear(); pos = 0; }
        return take;
    }
    size_t capacity() const { return data.capacity(); }
};

template<class Buffer>
void Run(const char* label, size_t total, size_t backlog) {
    Buffer buffer;
    constexpr size_t chunk = 32768;
    std::vector<uint8_t> src(std::max(chunk, backlog), 0x5a), out(chunk);
    if (backlog) buffer.Append(src.data(), backlog);
    uint64_t checksum = 0;
    const auto start = std::chrono::steady_clock::now();
    for (size_t done = 0; done < total; done += chunk) {
        if (!backlog) buffer.Append(src.data(), chunk);
        const size_t n = buffer.Read(out.data(), chunk);
        for (size_t i = 0; i < n; ++i) checksum += out[i];
        if (backlog) buffer.Append(src.data(), chunk);
    }
    const double ms = std::chrono::duration<double, std::milli>(
        std::chrono::steady_clock::now() - start).count();
    std::printf("%s backlog=%zu KiB total=%zu MiB ms=%.3f capacity=%.3f MiB checksum=%llu\n",
        label, backlog / 1024, total / (1024 * 1024), ms,
        buffer.capacity() / (1024.0 * 1024.0), (unsigned long long)checksum);
    if (checksum != uint64_t(total) * 0x5a) std::abort();
}

int main(int argc, char** argv) {
    const int mib = argc > 1 ? std::atoi(argv[1]) : 256;
    if (mib < 1 || mib > 1024) return 2;
    const size_t total = size_t(mib) * 1024 * 1024;
    for (size_t backlog : {size_t{0}, size_t{4 * 1024 * 1024}}) {
        for (int repeat = 0; repeat < 5; ++repeat) {
            // Alternate order to reduce warmup/order bias.
            if (repeat & 1) {
                Run<hy2::detail::ReceiveBuffer>("ring", total, backlog);
                Run<OldBuffer>("old ", total, backlog);
            } else {
                Run<OldBuffer>("old ", total, backlog);
                Run<hy2::detail::ReceiveBuffer>("ring", total, backlog);
            }
        }
    }
}
