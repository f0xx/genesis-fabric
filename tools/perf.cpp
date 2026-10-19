/* In-process transfer used by CI. Prints a stable summary and exits non-zero
 * if throughput or RSS is outside the budget. No sockets and no peers. */
#include "engine.hpp"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>

#include <sys/resource.h>

namespace {

struct Buf {
    std::vector<uint8_t> data;
    size_t off = 0;
};

int rd(void* u, uint8_t* d, int n) {
    auto* b = static_cast<Buf*>(u);
    if (b->off >= b->data.size()) return 0;
    size_t left = b->data.size() - b->off;
    if (static_cast<size_t>(n) < left) left = static_cast<size_t>(n);
    std::memcpy(d, b->data.data() + b->off, left);
    b->off += left;
    return static_cast<int>(left);
}

int wr(void* u, const uint8_t* d, int n) {
    auto* b = static_cast<Buf*>(u);
    b->data.insert(b->data.end(), d, d + n);
    return n;
}

}  // namespace

int main() {
    constexpr int N = 4 * 1024 * 1024;
    Buf src, dst;
    src.data.resize(static_cast<size_t>(N));
    for (int i = 0; i < N; ++i) src.data[static_cast<size_t>(i)] = static_cast<uint8_t>(i * 13 + 7);

    genesis::EngineOpts o;
    o.enable_fec = 0;
    o.enable_nack = 0;
    o.link_hint = 1;
    o.plain_mss = 1200;
    o.window = 256;
    o.file_size = static_cast<uint64_t>(N);
    std::snprintf(o.file_name, sizeof(o.file_name), "perf.bin");

    rusage before{};
    getrusage(RUSAGE_SELF, &before);
    genesis::Engine tx(o, true);
    genesis::Engine rx(o, false);
    tx.add_candidate({0x7f000001u, 1});
    tx.set_io(rd, nullptr, &src);
    rx.set_io(nullptr, wr, &dst);
    uint64_t now = 1000;
    tx.start(now);
    rx.start(now);
    int steps = 0;
    for (; steps < 200000 && !(tx.success() && rx.success()); ++steps) {
        tx.tick(now);
        rx.tick(now);
        genesis::DatagramOut d;
        while (tx.pop(d)) rx.on_datagram(d.data, d.len, {0x7f000001u, 2}, now);
        while (rx.pop(d)) tx.on_datagram(d.data, d.len, {0x7f000001u, 1}, now);
        now += 50;
    }
    rusage after{};
    getrusage(RUSAGE_SELF, &after);
    long rss = after.ru_maxrss;
    uint64_t user_us = static_cast<uint64_t>(after.ru_utime.tv_sec - before.ru_utime.tv_sec) * 1000000ull +
                       static_cast<uint64_t>(after.ru_utime.tv_usec - before.ru_utime.tv_usec);
    uint64_t sys_us = static_cast<uint64_t>(after.ru_stime.tv_sec - before.ru_stime.tv_sec) * 1000000ull +
                      static_cast<uint64_t>(after.ru_stime.tv_usec - before.ru_stime.tv_usec);
    uint64_t cpu_us = user_us + sys_us;
    if (cpu_us == 0) cpu_us = 1;
    bool ok = tx.success() && rx.success() && dst.data == src.data;
    uint64_t bps = ok ? (static_cast<uint64_t>(N) * 1000000ull) / cpu_us : 0;
    std::printf("perf_ok=%d\n", ok ? 1 : 0);
    std::printf("perf_bytes=%d\n", N);
    std::printf("perf_steps=%d\n", steps);
    std::printf("perf_cpu_us=%llu\n", static_cast<unsigned long long>(cpu_us));
    std::printf("perf_bps=%llu\n", static_cast<unsigned long long>(bps));
    std::printf("perf_rss_kb=%ld\n", rss);
    std::printf("perf_user_us=%llu\n", static_cast<unsigned long long>(user_us));
    std::printf("perf_sys_us=%llu\n", static_cast<unsigned long long>(sys_us));
    std::printf("perf_retx=%llu\n", static_cast<unsigned long long>(tx.retx()));
    /* In-process CPU throughput, not socket throughput. 8 MB/s and 64 MB RSS
     * leave headroom on a laptop and still catch a quadratic blow-up. */
    if (!ok || bps < 8ull * 1000ull * 1000ull || rss > 64l * 1024l) return 1;
    return 0;
}
