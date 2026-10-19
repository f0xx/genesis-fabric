#include "crypto.hpp"

#include <cstring>

namespace genesis {

void hmac_sha256(const uint8_t* key, size_t key_len, const uint8_t* msg, size_t msg_len, uint8_t out[32]) {
    uint8_t k[64];
    std::memset(k, 0, sizeof(k));
    if (key_len > 64) Sha256::hash(key, key_len, k);
    else std::memcpy(k, key, key_len);
    uint8_t ipad[64], opad[64];
    for (int i = 0; i < 64; ++i) {
        ipad[i] = static_cast<uint8_t>(k[i] ^ 0x36);
        opad[i] = static_cast<uint8_t>(k[i] ^ 0x5c);
    }
    Sha256 inner;
    inner.update(ipad, 64);
    inner.update(msg, msg_len);
    uint8_t ih[32];
    inner.final(ih);
    Sha256 outer;
    outer.update(opad, 64);
    outer.update(ih, 32);
    outer.final(out);
}

void hmac_sha1(const uint8_t* key, size_t key_len, const uint8_t* msg, size_t msg_len, uint8_t out[20]) {
    uint8_t k[64];
    std::memset(k, 0, sizeof(k));
    if (key_len > 64) Sha1::hash(key, key_len, k);
    else std::memcpy(k, key, key_len);
    uint8_t ipad[64], opad[64];
    for (int i = 0; i < 64; ++i) {
        ipad[i] = static_cast<uint8_t>(k[i] ^ 0x36);
        opad[i] = static_cast<uint8_t>(k[i] ^ 0x5c);
    }
    Sha1 inner;
    inner.update(ipad, 64);
    inner.update(msg, msg_len);
    uint8_t ih[20];
    inner.final(ih);
    Sha1 outer;
    outer.update(opad, 64);
    outer.update(ih, 20);
    outer.final(out);
}

bool hkdf_sha256(const uint8_t* ikm, size_t ikm_len, const uint8_t* salt, size_t salt_len,
                 const uint8_t* info, size_t info_len, uint8_t* okm, size_t okm_len) {
    if (okm_len > 255 * 32) return false;
    uint8_t zeros[32];
    std::memset(zeros, 0, sizeof(zeros));
    const uint8_t* s = salt;
    size_t sl = salt_len;
    if (!s || sl == 0) {
        s = zeros;
        sl = 32;
    }
    uint8_t prk[32];
    hmac_sha256(s, sl, ikm, ikm_len, prk);
    uint8_t prev[32];
    size_t prev_len = 0;
    size_t done = 0;
    uint8_t counter = 1;
    while (done < okm_len) {
        /* T(i) = HMAC(PRK, T(i-1) | info | counter) */
        uint8_t block[32 + 1024 + 1];
        if (info_len > 1024) return false;
        size_t n = 0;
        for (size_t i = 0; i < prev_len; ++i) block[n++] = prev[i];
        for (size_t i = 0; i < info_len; ++i) block[n++] = info[i];
        block[n++] = counter++;
        uint8_t t[32];
        hmac_sha256(prk, 32, block, n, t);
        size_t take = okm_len - done;
        if (take > 32) take = 32;
        for (size_t i = 0; i < take; ++i) okm[done + i] = t[i];
        done += take;
        std::memcpy(prev, t, 32);
        prev_len = 32;
    }
    return true;
}

}  // namespace genesis
