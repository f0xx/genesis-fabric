#pragma once

#include <cstdint>
#include <cstring>

namespace genesis {

inline uint16_t load_be16(const uint8_t* p) {
    return static_cast<uint16_t>((static_cast<uint16_t>(p[0]) << 8) | p[1]);
}

inline uint32_t load_be32(const uint8_t* p) {
    return (static_cast<uint32_t>(p[0]) << 24) | (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) << 8) | static_cast<uint32_t>(p[3]);
}

inline uint64_t load_be64(const uint8_t* p) {
    return (static_cast<uint64_t>(load_be32(p)) << 32) | load_be32(p + 4);
}

inline void store_be16(uint8_t* p, uint16_t v) {
    p[0] = static_cast<uint8_t>(v >> 8);
    p[1] = static_cast<uint8_t>(v);
}

inline void store_be32(uint8_t* p, uint32_t v) {
    p[0] = static_cast<uint8_t>(v >> 24);
    p[1] = static_cast<uint8_t>(v >> 16);
    p[2] = static_cast<uint8_t>(v >> 8);
    p[3] = static_cast<uint8_t>(v);
}

inline void store_be64(uint8_t* p, uint64_t v) {
    store_be32(p, static_cast<uint32_t>(v >> 32));
    store_be32(p + 4, static_cast<uint32_t>(v));
}

inline uint16_t load_le16(const uint8_t* p) {
    return static_cast<uint16_t>(p[0] | (static_cast<uint16_t>(p[1]) << 8));
}

inline uint32_t load_le32(const uint8_t* p) {
    return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) | (static_cast<uint32_t>(p[3]) << 24);
}

inline uint64_t load_le64(const uint8_t* p) {
    return static_cast<uint64_t>(load_le32(p)) | (static_cast<uint64_t>(load_le32(p + 4)) << 32);
}

inline void store_le16(uint8_t* p, uint16_t v) {
    p[0] = static_cast<uint8_t>(v);
    p[1] = static_cast<uint8_t>(v >> 8);
}

inline void store_le32(uint8_t* p, uint32_t v) {
    p[0] = static_cast<uint8_t>(v);
    p[1] = static_cast<uint8_t>(v >> 8);
    p[2] = static_cast<uint8_t>(v >> 16);
    p[3] = static_cast<uint8_t>(v >> 24);
}

inline void store_le64(uint8_t* p, uint64_t v) {
    store_le32(p, static_cast<uint32_t>(v));
    store_le32(p + 4, static_cast<uint32_t>(v >> 32));
}

/* Compiler bswap is a single BSWAP/REV. Wire code does not use htonl so the
 * same translation unit builds for little-endian SoCs and big-endian targets. */
inline uint32_t bswap32(uint32_t x) {
#if defined(__GNUC__) || defined(__clang__)
    return __builtin_bswap32(x);
#else
    return (x >> 24) | ((x >> 8) & 0xff00u) | ((x << 8) & 0xff0000u) | (x << 24);
#endif
}

inline uint64_t bswap64(uint64_t x) {
#if defined(__GNUC__) || defined(__clang__)
    return __builtin_bswap64(x);
#else
    return (static_cast<uint64_t>(bswap32(static_cast<uint32_t>(x))) << 32) |
           bswap32(static_cast<uint32_t>(x >> 32));
#endif
}

inline bool host_is_little_endian() {
    const uint16_t n = 1;
    return *reinterpret_cast<const uint8_t*>(&n) == 1;
}

}  // namespace genesis
