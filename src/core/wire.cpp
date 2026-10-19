#include "wire.hpp"
#include "endian.hpp"

#include <cstring>

namespace genesis {

bool encode_header(uint8_t* dst, size_t cap, const Header& h) {
    if (cap < kHeaderBytes) return false;
    store_be32(dst + 0, kMagic);
    dst[4] = h.version;
    dst[5] = h.type;
    store_be16(dst + 6, h.flags);
    store_be32(dst + 8, h.conn_id);
    store_be64(dst + 12, h.seq);
    store_be64(dst + 20, h.ack);
    store_be64(dst + 28, h.sack);
    store_be64(dst + 36, h.timestamp_us);
    store_be16(dst + 44, h.payload_len);
    store_be16(dst + 46, h.ext_len);
    return true;
}

bool decode_header(const uint8_t* src, size_t len, Header& h) {
    if (len < kHeaderBytes) return false;
    if (load_be32(src) != kMagic) return false;
    h.version = src[4];
    h.type = src[5];
    h.flags = load_be16(src + 6);
    h.conn_id = load_be32(src + 8);
    h.seq = load_be64(src + 12);
    h.ack = load_be64(src + 20);
    h.sack = load_be64(src + 28);
    h.timestamp_us = load_be64(src + 36);
    h.payload_len = load_be16(src + 44);
    h.ext_len = load_be16(src + 46);
    if (kHeaderBytes + static_cast<size_t>(h.ext_len) + h.payload_len > len) return false;
    if (h.version == 0 || h.version > kProtoVersion) return false;
    return true;
}

}  // namespace genesis
