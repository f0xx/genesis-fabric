#include "handshake.hpp"
#include "crypto.hpp"
#include "endian.hpp"
#include "util.hpp"

#include <cstring>

namespace genesis {

bool encode_hello(uint8_t* dst, size_t cap, size_t* out_len, const PeerView& peer) {
    size_t name_len = 0;
    while (peer.name[name_len] && name_len < 32) ++name_len;
    size_t file_len = 0;
    while (peer.file_name[file_len] && file_len < 200) ++file_len;
    int nc = peer.cand_count;
    if (nc < 0) nc = 0;
    if (nc > kMaxCandidates) nc = kMaxCandidates;
    size_t need = 1 + 1 + 2 + 4 + 32 + 16 + 16 + 2 + 1 + name_len + 2 + file_len + 8 + 1 +
                  static_cast<size_t>(nc) * 8;
    if (need > cap) return false;
    size_t n = 0;
    dst[n++] = peer.hs_version;
    dst[n++] = peer.profile;
    store_be16(dst + n, 0);
    n += 2;
    store_be32(dst + n, peer.features);
    n += 4;
    std::memcpy(dst + n, peer.pubkey, 32);
    n += 32;
    std::memcpy(dst + n, peer.nonce, 16);
    n += 16;
    std::memcpy(dst + n, peer.node_id, 16);
    n += 16;
    store_be16(dst + n, peer.udp_port);
    n += 2;
    dst[n++] = static_cast<uint8_t>(name_len);
    std::memcpy(dst + n, peer.name, name_len);
    n += name_len;
    store_be16(dst + n, static_cast<uint16_t>(file_len));
    n += 2;
    std::memcpy(dst + n, peer.file_name, file_len);
    n += file_len;
    store_be64(dst + n, peer.file_size);
    n += 8;
    dst[n++] = static_cast<uint8_t>(nc);
    for (int i = 0; i < nc; ++i) {
        dst[n++] = peer.cand_kind[i];
        dst[n++] = 4;
        std::memcpy(dst + n, peer.cand_addr[i], 4);
        n += 4;
        store_be16(dst + n, peer.cand_port[i]);
        n += 2;
    }
    *out_len = n;
    return true;
}

bool decode_hello(const uint8_t* src, size_t len, PeerView& peer) {
    if (len < 1 + 1 + 2 + 4 + 32 + 16 + 16 + 2 + 1) return false;
    size_t n = 0;
    peer.hs_version = src[n++];
    if (peer.hs_version == 0 || peer.hs_version > kHsVersion) return false;
    peer.profile = src[n++];
    n += 2;
    peer.features = load_be32(src + n);
    n += 4;
    std::memcpy(peer.pubkey, src + n, 32);
    n += 32;
    std::memcpy(peer.nonce, src + n, 16);
    n += 16;
    std::memcpy(peer.node_id, src + n, 16);
    n += 16;
    peer.udp_port = load_be16(src + n);
    n += 2;
    uint8_t name_len = src[n++];
    if (name_len > 32 || n + name_len + 2 > len) return false;
    std::memset(peer.name, 0, sizeof(peer.name));
    std::memcpy(peer.name, src + n, name_len);
    n += name_len;
    if (n + 2 > len) return false;
    uint16_t file_len = load_be16(src + n);
    n += 2;
    if (file_len > 200 || n + file_len + 8 + 1 > len) return false;
    std::memset(peer.file_name, 0, sizeof(peer.file_name));
    std::memcpy(peer.file_name, src + n, file_len);
    n += file_len;
    peer.file_size = load_be64(src + n);
    n += 8;
    uint8_t nc = src[n++];
    if (nc > kMaxCandidates) return false;
    peer.cand_count = nc;
    for (int i = 0; i < nc; ++i) {
        if (n + 8 > len) return false;
        peer.cand_kind[i] = src[n++];
        uint8_t alen = src[n++];
        if (alen != 4) return false;
        std::memcpy(peer.cand_addr[i], src + n, 4);
        n += 4;
        peer.cand_port[i] = load_be16(src + n);
        n += 2;
    }
    return true;
}

size_t hello_body_end(const uint8_t* src, size_t len) {
    if (len < 1 + 1 + 2 + 4 + 32 + 16 + 16 + 2 + 1) return 0;
    size_t n = 1 + 1 + 2 + 4 + 32 + 16 + 16 + 2;
    uint8_t name_len = src[n++];
    if (name_len > 32 || n + name_len + 2 > len) return 0;
    n += name_len;
    uint16_t file_len = load_be16(src + n);
    n += 2;
    if (file_len > 200 || n + file_len + 8 + 1 > len) return 0;
    n += file_len + 8;
    uint8_t nc = src[n++];
    if (nc > kMaxCandidates || n + static_cast<size_t>(nc) * 8 > len) return 0;
    return n + static_cast<size_t>(nc) * 8;
}

size_t hello_append_tail(uint8_t* dst, size_t cap, size_t len, uint16_t chunk, uint64_t resume_off) {
    if (len + 3 + 9 > cap) return len;
    dst[len++] = 1;
    store_be16(dst + len, chunk);
    len += 2;
    dst[len++] = 2;
    store_be64(dst + len, resume_off);
    len += 8;
    return len;
}

void hello_read_tail(const uint8_t* src, size_t len, uint16_t* chunk, uint64_t* resume_off) {
    if (chunk) *chunk = 0;
    if (resume_off) *resume_off = 0;
    size_t n = hello_body_end(src, len);
    if (!n) return;
    while (n < len) {
        uint8_t type = src[n++];
        if (type == 1 && n + 2 <= len) {
            if (chunk) *chunk = load_be16(src + n);
            n += 2;
        } else if (type == 2 && n + 8 <= len) {
            if (resume_off) *resume_off = load_be64(src + n);
            n += 8;
        } else {
            break;
        }
    }
}

void derive_transport_keys(const uint8_t shared[32], const uint8_t* psk, bool have_psk,
                           const uint8_t nonce_init[16], const uint8_t nonce_resp[16],
                           uint8_t key_i2r[32], uint8_t key_r2i[32]) {
    uint8_t ikm[64];
    std::memcpy(ikm, shared, 32);
    size_t ikm_len = 32;
    if (have_psk && psk) {
        std::memcpy(ikm + 32, psk, 32);
        ikm_len = 64;
    }
    uint8_t salt[32];
    std::memcpy(salt, nonce_init, 16);
    std::memcpy(salt + 16, nonce_resp, 16);
    static const uint8_t info[] = "genesis-hs-v1";
    uint8_t okm[64];
    hkdf_sha256(ikm, ikm_len, salt, 32, info, sizeof(info) - 1, okm, 64);
    std::memcpy(key_i2r, okm, 32);
    std::memcpy(key_r2i, okm + 32, 32);
    secure_zero(ikm, sizeof(ikm));
    secure_zero(okm, sizeof(okm));
}

size_t encode_peer_update(uint8_t* dst, size_t cap, uint64_t seq, const PeerView& peer) {
    /* body: u64 seq, u8 count, TLVs for features, profile, and each candidate. */
    int nc = peer.cand_count;
    if (nc < 0) nc = 0;
    if (nc > kMaxCandidates) nc = kMaxCandidates;
    size_t need = 8 + 1 + (2 + 4) + (2 + 1) + static_cast<size_t>(nc) * (2 + 7);
    if (need > cap) return 0;
    size_t n = 0;
    store_be64(dst + n, seq);
    n += 8;
    dst[n++] = static_cast<uint8_t>(2 + nc);
    dst[n++] = 2;
    dst[n++] = 4;
    store_be32(dst + n, peer.features);
    n += 4;
    dst[n++] = 3;
    dst[n++] = 1;
    dst[n++] = peer.profile;
    for (int i = 0; i < nc; ++i) {
        dst[n++] = 1;
        dst[n++] = 7;
        dst[n++] = peer.cand_kind[i];
        std::memcpy(dst + n, peer.cand_addr[i], 4);
        n += 4;
        store_be16(dst + n, peer.cand_port[i]);
        n += 2;
    }
    return n;
}

bool apply_peer_update(PeerView& peer, const uint8_t* src, size_t len) {
    if (len < 9) return false;
    uint64_t seq = load_be64(src);
    if (seq <= peer.update_seq) return false;
    size_t n = 8;
    uint8_t count = src[n++];
    PeerView next = peer;
    next.cand_count = 0;
    bool saw_cand = false;
    for (uint8_t i = 0; i < count; ++i) {
        if (n + 2 > len) return false;
        uint8_t type = src[n++];
        uint8_t l = src[n++];
        if (n + l > len) return false;
        if (type == 2 && l == 4) {
            next.features = load_be32(src + n);
        } else if (type == 3 && l == 1) {
            next.profile = src[n];
        } else if (type == 1 && l == 7 && next.cand_count < kMaxCandidates) {
            int c = next.cand_count++;
            next.cand_kind[c] = src[n];
            std::memcpy(next.cand_addr[c], src + n + 1, 4);
            next.cand_port[c] = load_be16(src + n + 5);
            saw_cand = true;
        }
        /* Unknown types are skipped. That is the versioning rule for TLV updates. */
        n += l;
    }
    if (!saw_cand) next.cand_count = peer.cand_count;
    next.update_seq = seq;
    peer = next;
    return true;
}

}  // namespace genesis
