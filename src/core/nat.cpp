#include "nat.hpp"

#include "endian.hpp"

#include <cstring>

namespace genesis {
namespace {

bool put_str(uint8_t* dst, size_t cap, size_t* n, const char* s) {
    size_t L = s ? std::strlen(s) : 0;
    if (L > kNatName || *n + 1 + L > cap) return false;
    dst[(*n)++] = static_cast<uint8_t>(L);
    if (L) std::memcpy(dst + *n, s, L);
    *n += L;
    return true;
}

bool take_str(const uint8_t* src, size_t len, size_t* n, char* out, size_t cap) {
    if (*n >= len) return false;
    size_t L = src[(*n)++];
    if (L >= cap || *n + L > len) return false;
    std::memcpy(out, src + *n, L);
    out[L] = '\0';
    *n += L;
    return true;
}

bool put_data(uint8_t* dst, size_t cap, size_t* n, const std::vector<uint8_t>& data) {
    if (data.size() > kNatInnerMax || *n + 2 + data.size() > cap) return false;
    store_be16(dst + *n, static_cast<uint16_t>(data.size()));
    *n += 2;
    if (!data.empty()) std::memcpy(dst + *n, data.data(), data.size());
    *n += data.size();
    return true;
}

bool take_data(const uint8_t* src, size_t len, size_t* n, std::vector<uint8_t>& data) {
    if (*n + 2 > len) return false;
    uint16_t L = load_be16(src + *n);
    *n += 2;
    if (L > kNatInnerMax || *n + L > len) return false;
    data.assign(src + *n, src + *n + L);
    *n += L;
    return true;
}

}  // namespace

bool nat_name_ok(const char* s) {
    if (!s || !s[0] || std::strlen(s) > kNatName) return false;
    for (const char* p = s; *p; ++p) {
        char c = *p;
        bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '_' ||
                  c == '-' || c == '+';
        if (!ok) return false;
    }
    return true;
}

bool nat_is(const uint8_t* p, size_t n) {
    return p && n >= 8 && load_be32(p) == kNatMagic && p[4] == kNatVersion;
}

size_t nat_encode(uint8_t* dst, size_t cap, const NatMsg& m) {
    if (!dst || cap < 8) return 0;
    store_be32(dst, kNatMagic);
    dst[4] = kNatVersion;
    dst[5] = m.type;
    size_t n = 6;
    if (!put_str(dst, cap, &n, m.room) || !put_str(dst, cap, &n, m.name)) return 0;
    auto need = [&](size_t k) { return n + k <= cap; };
    switch (m.type) {
    case kNatRegister:
        break;
    case kNatRegistered:
    case kNatPunch:
    case kNatPunchAck:
        if (!need(4 + 2 + 8)) return 0;
        store_be32(dst + n, m.addr);
        n += 4;
        store_be16(dst + n, m.port);
        n += 2;
        store_be64(dst + n, m.cookie);
        n += 8;
        break;
    case kNatLookup:
        if (!put_str(dst, cap, &n, m.peer)) return 0;
        break;
    case kNatPeer:
        if (!need(1 + 4 + 2 + 8)) return 0;
        dst[n++] = m.ok;
        store_be32(dst + n, m.addr);
        n += 4;
        store_be16(dst + n, m.port);
        n += 2;
        store_be64(dst + n, m.cookie);
        n += 8;
        if (!put_str(dst, cap, &n, m.peer)) return 0;
        break;
    case kNatRelay:
        if (!need(8)) return 0;
        store_be64(dst + n, m.cookie);
        n += 8;
        if (!put_data(dst, cap, &n, m.data)) return 0;
        break;
    case kNatProbe:
        if (!need(4)) return 0;
        store_be32(dst + n, m.id);
        n += 4;
        if (!put_data(dst, cap, &n, m.data)) return 0;
        break;
    case kNatProbeAck:
        if (!need(4 + 2)) return 0;
        store_be32(dst + n, m.id);
        n += 4;
        store_be16(dst + n, static_cast<uint16_t>(m.data.size()));
        n += 2;
        break;
    case kNatBench:
        if (!need(4 + 4)) return 0;
        store_be32(dst + n, m.id);
        n += 4;
        store_be32(dst + n, m.total);
        n += 4;
        if (!put_data(dst, cap, &n, m.data)) return 0;
        break;
    case kNatBenchAck:
        if (!need(4)) return 0;
        store_be32(dst + n, m.id);
        n += 4;
        break;
    case kNatTun:
        if (!need(4)) return 0;
        store_be32(dst + n, m.id);
        n += 4;
        if (!put_data(dst, cap, &n, m.data)) return 0;
        break;
    case kNatTunAck:
        if (!need(4 + 8)) return 0;
        store_be32(dst + n, m.ack);
        n += 4;
        store_be64(dst + n, m.bitmap);
        n += 8;
        break;
    default:
        return 0;
    }
    return n;
}

bool nat_decode(const uint8_t* src, size_t len, NatMsg& m) {
    m = NatMsg{};
    if (!nat_is(src, len)) return false;
    m.type = src[5];
    size_t n = 6;
    if (!take_str(src, len, &n, m.room, sizeof(m.room)) || !take_str(src, len, &n, m.name, sizeof(m.name))) return false;
    switch (m.type) {
    case kNatRegister:
        return n == len;
    case kNatRegistered:
    case kNatPunch:
    case kNatPunchAck:
        if (n + 14 > len) return false;
        m.addr = load_be32(src + n);
        m.port = load_be16(src + n + 4);
        m.cookie = load_be64(src + n + 6);
        return true;
    case kNatLookup:
        return take_str(src, len, &n, m.peer, sizeof(m.peer));
    case kNatPeer:
        if (n + 15 > len) return false;
        m.ok = src[n++];
        m.addr = load_be32(src + n);
        n += 4;
        m.port = load_be16(src + n);
        n += 2;
        m.cookie = load_be64(src + n);
        n += 8;
        return take_str(src, len, &n, m.peer, sizeof(m.peer));
    case kNatRelay:
        if (n + 8 > len) return false;
        m.cookie = load_be64(src + n);
        n += 8;
        return take_data(src, len, &n, m.data);
    case kNatProbe:
        if (n + 4 > len) return false;
        m.id = load_be32(src + n);
        n += 4;
        return take_data(src, len, &n, m.data);
    case kNatProbeAck:
        if (n + 6 > len) return false;
        m.id = load_be32(src + n);
        m.total = load_be16(src + n + 4);
        return true;
    case kNatBench:
        if (n + 8 > len) return false;
        m.id = load_be32(src + n);
        m.total = load_be32(src + n + 4);
        n += 8;
        return take_data(src, len, &n, m.data);
    case kNatBenchAck:
        if (n + 4 > len) return false;
        m.id = load_be32(src + n);
        return true;
    case kNatTun:
        if (n + 4 > len) return false;
        m.id = load_be32(src + n);
        n += 4;
        return take_data(src, len, &n, m.data);
    case kNatTunAck:
        if (n + 12 > len) return false;
        m.ack = load_be32(src + n);
        m.bitmap = load_be64(src + n + 4);
        return true;
    default:
        return false;
    }
}

}  // namespace genesis
