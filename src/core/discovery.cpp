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

}  // namespace genesis
