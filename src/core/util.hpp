#pragma once

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>

namespace genesis {

inline bool ct_equal(const uint8_t* a, const uint8_t* b, size_t n) {
    uint8_t d = 0;
    for (size_t i = 0; i < n; ++i) d = static_cast<uint8_t>(d | (a[i] ^ b[i]));
    return d == 0;
}

inline void secure_zero(void* p, size_t n) {
#if defined(__GNUC__) || defined(__clang__)
    volatile uint8_t* v = static_cast<volatile uint8_t*>(p);
    for (size_t i = 0; i < n; ++i) v[i] = 0;
#else
    std::memset(p, 0, n);
#endif
}

inline int hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

inline bool from_hex(const char* s, uint8_t* out, size_t n) {
    if (!s) return false;
    for (size_t i = 0; i < n; ++i) {
        int hi = hex_nibble(s[i * 2]);
        int lo = hex_nibble(s[i * 2 + 1]);
        if (hi < 0 || lo < 0) return false;
        out[i] = static_cast<uint8_t>((hi << 4) | lo);
    }
    return s[n * 2] == '\0' || s[n * 2] == '\n' || s[n * 2] == '\r';
}

inline void to_hex(const uint8_t* in, size_t n, char* out) {
    static const char* kHex = "0123456789abcdef";
    for (size_t i = 0; i < n; ++i) {
        out[i * 2] = kHex[in[i] >> 4];
        out[i * 2 + 1] = kHex[in[i] & 0x0f];
    }
    out[n * 2] = '\0';
}

inline void copy_cstr(char* dst, size_t cap, const char* src) {
    if (cap == 0) return;
    if (!src) {
        dst[0] = '\0';
        return;
    }
    size_t i = 0;
    while (i + 1 < cap && src[i]) {
        dst[i] = src[i];
        ++i;
    }
    dst[i] = '\0';
}

inline bool bytes_zero(const uint8_t* p, size_t n) {
    uint8_t a = 0;
    for (size_t i = 0; i < n; ++i) a = static_cast<uint8_t>(a | p[i]);
    return a == 0;
}

}  // namespace genesis
