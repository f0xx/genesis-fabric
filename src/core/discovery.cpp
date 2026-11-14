#include "discovery.hpp"
#include "endian.hpp"

#include <cstring>

namespace genesis {

size_t beacon_encode(uint8_t* dst, size_t cap, const Beacon& b) {
    size_t name = 0;
    while (b.name[name] && name < 31) ++name;
    size_t need = 4 + 1 + 2 + 4 + 16 + 1 + name;
    if (need > cap) return 0;
    store_be32(dst, kDiscoveryMagic);
    dst[4] = b.version;
    store_be16(dst + 5, b.port);
    store_be32(dst + 7, b.features);
    std::memcpy(dst + 11, b.node_id, 16);
    dst[27] = static_cast<uint8_t>(name);
    std::memcpy(dst + 28, b.name, name);
    return 28 + name;
}

bool beacon_decode(const uint8_t* src, size_t len, Beacon& b) {
    if (len < 28) return false;
    if (load_be32(src) != kDiscoveryMagic) return false;
    b.version = src[4];
    if (b.version == 0 || b.version > 1) return false;
    b.port = load_be16(src + 5);
    b.features = load_be32(src + 7);
    std::memcpy(b.node_id, src + 11, 16);
    uint8_t name = src[27];
    if (28u + name > len || name > 31) return false;
    std::memset(b.name, 0, sizeof(b.name));
    std::memcpy(b.name, src + 28, name);
    return true;
}

size_t beacon_append_exports(uint8_t* dst, size_t cap, size_t len, const char names[][32], const uint8_t* rw,
                             int count) {
    if (!dst || len > cap || count <= 0 || !names || !rw) return len;
    if (count > 8) count = 8;
    size_t need = len + 2;
    for (int i = 0; i < count; ++i) {
        size_t n = 0;
        while (names[i][n] && n < 31) ++n;
        need += 2 + n;
    }
    if (need > cap) return len;
    dst[len] = 0xE1;
    dst[len + 1] = static_cast<uint8_t>(count);
    size_t o = len + 2;
    for (int i = 0; i < count; ++i) {
        size_t n = 0;
        while (names[i][n] && n < 31) ++n;
        dst[o++] = static_cast<uint8_t>(n);
        std::memcpy(dst + o, names[i], n);
        o += n;
        dst[o++] = rw[i] ? 1 : 0;
    }
    return o;
}

int beacon_read_exports(const uint8_t* src, size_t len, char names[][32], uint8_t* rw, int cap) {
    if (!src || len < 28 || !names || cap <= 0) return 0;
    uint8_t name = src[27];
    size_t o = 28u + name;
    if (o >= len || src[o] != 0xE1) return 0;
    ++o;
    if (o >= len) return 0;
    int count = src[o++];
    if (count < 0 || count > 8) return 0;
    int got = 0;
    for (int i = 0; i < count; ++i) {
        if (o >= len) return 0;
        uint8_t n = src[o++];
        if (n > 31 || o + n + 1 > len) return 0;
        if (got < cap) {
            std::memset(names[got], 0, 32);
            std::memcpy(names[got], src + o, n);
            rw[got] = src[o + n] ? 1 : 0;
            ++got;
        }
        o += static_cast<size_t>(n) + 1;
    }
    return got;
}

}  // namespace genesis
