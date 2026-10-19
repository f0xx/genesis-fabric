#include "stun.hpp"
#include "crypto.hpp"
#include "endian.hpp"
#include "util.hpp"

#include <cstring>

namespace genesis {
namespace {
constexpr uint32_t kCookie = 0x2112A442u;
constexpr uint16_t kBindingRequest = 0x0001;
constexpr uint16_t kBindingSuccess = 0x0101;
constexpr uint16_t kAllocate = 0x0003;
constexpr uint16_t kAttrXorMapped = 0x0020;
constexpr uint16_t kAttrXorRelayed = 0x0016;
constexpr uint16_t kAttrMapped = 0x0001;
constexpr uint16_t kAttrIntegrity = 0x0008;
constexpr uint16_t kAttrFingerprint = 0x8028;
constexpr uint16_t kAttrRequestedTransport = 0x0019;
}  // namespace

size_t stun_binding_request(uint8_t* dst, size_t cap, const uint8_t tid[12]) {
    if (cap < 20) return 0;
    store_be16(dst + 0, kBindingRequest);
    store_be16(dst + 2, 0);
    store_be32(dst + 4, kCookie);
    std::memcpy(dst + 8, tid, 12);
    return 20;
}

bool stun_parse_xor_addr(const uint8_t* attr, size_t len, uint16_t* port, uint8_t* addr, int* addr_len) {
    if (len < 8) return false;
    uint8_t family = attr[1];
    uint16_t xport = load_be16(attr + 2);
    *port = static_cast<uint16_t>(xport ^ (kCookie >> 16));
    if (family == 0x01) {
        if (len < 8) return false;
        uint32_t xip = load_be32(attr + 4);
        uint32_t ip = xip ^ kCookie;
        store_be32(addr, ip);
        *addr_len = 4;
        return true;
    }
    if (family == 0x02 && len >= 20) {
        /* IPv6 is XORed with cookie || transaction, but callers that only have the
         * attribute body cannot finish that without the tid. We support the IPv4
         * path used on this network and reject truncated v6. */
        *addr_len = 16;
        return false;
    }
    return false;
}

bool stun_parse_binding_response(const uint8_t* msg, size_t len, const uint8_t tid[12], StunResult& out) {
    out = StunResult();
    if (len < 20) return false;
    uint16_t type = load_be16(msg);
    uint16_t mlen = load_be16(msg + 2);
    if (type != kBindingSuccess && type != kBindingRequest) return false;
    if (load_be32(msg + 4) != kCookie) return false;
    if (!ct_equal(msg + 8, tid, 12)) return false;
    if (20u + mlen > len) return false;
    size_t n = 20;
    size_t end = 20u + mlen;
    while (n + 4 <= end) {
        uint16_t at = load_be16(msg + n);
        uint16_t al = load_be16(msg + n + 2);
        n += 4;
        if (n + al > end) return false;
        if (at == kAttrXorMapped || at == kAttrXorRelayed) {
            uint16_t port = 0;
            uint8_t addr[16] = {};
            int alen = 0;
            if (stun_parse_xor_addr(msg + n, al, &port, addr, &alen)) {
                out.ok = true;
                out.port = port;
                out.addr_len = alen;
                std::memcpy(out.addr, addr, static_cast<size_t>(alen));
                out.family = 1;
                return true;
            }
        } else if (at == kAttrMapped && al >= 8 && msg[n + 1] == 0x01) {
            out.ok = true;
            out.port = load_be16(msg + n + 2);
            out.addr_len = 4;
            std::memcpy(out.addr, msg + n + 4, 4);
            return true;
        }
        n += (al + 3u) & ~3u;
    }
    return false;
}

uint32_t stun_fingerprint(const uint8_t* msg, size_t len_before_attr) {
    return crc32_ieee(msg, len_before_attr) ^ 0x5354554eu;
}

bool stun_add_integrity_and_fingerprint(uint8_t* msg, size_t* len, size_t cap, const uint8_t* key,
                                       size_t key_len) {
    /* MESSAGE-INTEGRITY is 20 bytes. The header length, while hashing, includes the
     * attribute header+value (24) but not the fingerprint that follows. */
    if (*len < 20 || *len + 24 + 8 > cap) return false;
    uint16_t length_with_mi = static_cast<uint16_t>((*len - 20) + 24);
    store_be16(msg + 2, length_with_mi);
    uint8_t mac[20];
    hmac_sha1(key, key_len, msg, *len, mac);
    store_be16(msg + *len, kAttrIntegrity);
    store_be16(msg + *len + 2, 20);
    std::memcpy(msg + *len + 4, mac, 20);
    *len += 24;
    uint16_t length_with_fp = static_cast<uint16_t>(length_with_mi + 8);
    store_be16(msg + 2, length_with_fp);
    uint32_t fp = stun_fingerprint(msg, *len);
    store_be16(msg + *len, kAttrFingerprint);
    store_be16(msg + *len + 2, 4);
    store_be32(msg + *len + 4, fp);
    *len += 8;
    return true;
}

bool stun_check_integrity(const uint8_t* msg, size_t len, const uint8_t* key, size_t key_len) {
    if (len < 20) return false;
    size_t n = 20;
    uint16_t mlen = load_be16(msg + 2);
    size_t end = 20u + mlen;
    if (end > len) return false;
    while (n + 4 <= end) {
        uint16_t at = load_be16(msg + n);
        uint16_t al = load_be16(msg + n + 2);
        if (at == kAttrIntegrity && al == 20) {
            uint8_t tmp[1500];
            if (n > sizeof(tmp)) return false;
            std::memcpy(tmp, msg, n);
            store_be16(tmp + 2, static_cast<uint16_t>(n - 20 + 24));
            uint8_t mac[20];
            hmac_sha1(key, key_len, tmp, n, mac);
            return ct_equal(mac, msg + n + 4, 20);
        }
        n += 4 + ((al + 3u) & ~3u);
    }
    return false;
}

size_t turn_allocate_request(uint8_t* dst, size_t cap, const uint8_t tid[12]) {
    /* Header + REQUESTED-TRANSPORT (UDP = 17) padded to 4. */
    if (cap < 20 + 8) return 0;
    store_be16(dst + 0, kAllocate);
    store_be16(dst + 2, 8);
    store_be32(dst + 4, kCookie);
    std::memcpy(dst + 8, tid, 12);
    store_be16(dst + 20, kAttrRequestedTransport);
    store_be16(dst + 22, 4);
    dst[24] = 17;
    dst[25] = dst[26] = dst[27] = 0;
    return 28;
}

}  // namespace genesis
