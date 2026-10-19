#pragma once

#include <atomic>
#include <cstddef>
#include <type_traits>

namespace genesis {

/* Single-producer single-consumer ring. One thread may push, another may pop.
 * Capacity is a power of two. Indices are published with release/acquire so a
 * slot is not read before the write, and not overwritten before the read.
 * This is the streaming handoff between an application thread and the poller;
 * it is intentionally not a general MPMC queue. */
template <typename T, size_t N>
class SpscRing {
    static_assert(N >= 2 && (N & (N - 1)) == 0, "capacity must be a power of two");
    static_assert(std::is_trivially_copyable<T>::value, "SpscRing requires trivial items");

public:
    bool push(const T& item) {
        const size_t t = tail_.load(std::memory_order_relaxed);
        const size_t h = head_.load(std::memory_order_acquire);
        if (t - h >= N) return false;
        slots_[t & (N - 1)] = item;
        tail_.store(t + 1, std::memory_order_release);
        return true;
    }

    bool pop(T& item) {
        const size_t h = head_.load(std::memory_order_relaxed);
        const size_t t = tail_.load(std::memory_order_acquire);
        if (h == t) return false;
        item = slots_[h & (N - 1)];
        head_.store(h + 1, std::memory_order_release);
        return true;
    }

    size_t size() const {
        return tail_.load(std::memory_order_acquire) - head_.load(std::memory_order_acquire);
    }

private:
    T slots_[N]{};
    alignas(64) std::atomic<size_t> head_{0};
    alignas(64) std::atomic<size_t> tail_{0};
};

}  // namespace genesis
