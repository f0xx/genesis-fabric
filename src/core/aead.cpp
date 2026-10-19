#include "crypto.hpp"
#include "endian.hpp"
#include "util.hpp"

#include <cstring>

namespace genesis {
namespace {

uint32_t rotl(uint32_t x, int n) { return (x << n) | (x >> (32 - n)); }

void quarter(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d) {
    a += b;
    d ^= a;
    d = rotl(d, 16);
    c += d;
    b ^= c;
    b = rotl(b, 12);
    a += b;
    d ^= a;
    d = rotl(d, 8);
    c += d;
    b ^= c;
    b = rotl(b, 7);
}

void chacha_block(uint8_t out[64], const uint32_t in[16]) {
    uint32_t x[16];
    for (int i = 0; i < 16; ++i) x[i] = in[i];
    for (int i = 0; i < 10; ++i) {
        quarter(x[0], x[4], x[8], x[12]);
        quarter(x[1], x[5], x[9], x[13]);
        quarter(x[2], x[6], x[10], x[14]);
        quarter(x[3], x[7], x[11], x[15]);
        quarter(x[0], x[5], x[10], x[15]);
        quarter(x[1], x[6], x[11], x[12]);
        quarter(x[2], x[7], x[8], x[13]);
        quarter(x[3], x[4], x[9], x[14]);
    }
    for (int i = 0; i < 16; ++i) store_le32(out + i * 4, x[i] + in[i]);
}

void poly_clamp(uint8_t r[16]) {
    r[3] &= 15;
    r[7] &= 15;
    r[11] &= 15;
    r[15] &= 15;
    r[4] &= 252;
    r[8] &= 252;
    r[12] &= 252;
}

/* 130-bit accumulator in radix 2^26. Five limbs, each < 2^26 after reduction. */
struct Limb {
    uint32_t v[5];
};

Limb limb_from_block(const uint8_t* p, size_t n, bool hibit) {
    uint8_t tmp[17];
    std::memset(tmp, 0, sizeof(tmp));
    for (size_t i = 0; i < n; ++i) tmp[i] = p[i];
    if (hibit) tmp[n] = 1;
    Limb a{};
    uint64_t acc = 0;
    int bits = 0;
    int li = 0;
    for (size_t i = 0; i < (hibit ? n + 1 : n); ++i) {
        acc |= static_cast<uint64_t>(tmp[i]) << bits;
        bits += 8;
        if (bits >= 26 && li < 5) {
            a.v[li++] = static_cast<uint32_t>(acc & 0x3ffffffu);
            acc >>= 26;
            bits -= 26;
        }
    }
    if (bits && li < 5) a.v[li] = static_cast<uint32_t>(acc & 0x3ffffffu);
    return a;
}

void limb_add(Limb& h, const Limb& n) {
    uint32_t c = 0;
    for (int i = 0; i < 5; ++i) {
        uint32_t s = h.v[i] + n.v[i] + c;
        h.v[i] = s & 0x3ffffffu;
        c = s >> 26;
    }
    /* Carry out of the 130th bit: 5*26=130. c is the overflow, fold *5. */
    h.v[0] += c * 5;
    c = h.v[0] >> 26;
    h.v[0] &= 0x3ffffffu;
    h.v[1] += c;
}

void limb_mul(Limb& h, const Limb& r) {
    uint64_t t[5] = {};
    for (int i = 0; i < 5; ++i) {
        for (int j = 0; j < 5; ++j) {
            uint64_t m = static_cast<uint64_t>(h.v[i]) * r.v[j];
            int k = i + j;
            if (k < 5) {
                t[k] += m;
            } else {
                /* 2^130 ≡ 5 (mod 2^130-5), and the extra 26-bit place is another *5 per limb. */
                t[k - 5] += m * 5;
            }
        }
    }
    uint64_t c = 0;
    for (int i = 0; i < 5; ++i) {
        c += t[i];
        h.v[i] = static_cast<uint32_t>(c & 0x3ffffffu);
        c >>= 26;
    }
    h.v[0] += static_cast<uint32_t>(c) * 5;
    c = h.v[0] >> 26;
    h.v[0] &= 0x3ffffffu;
    h.v[1] += static_cast<uint32_t>(c);
    c = h.v[1] >> 26;
    h.v[1] &= 0x3ffffffu;
    h.v[2] += static_cast<uint32_t>(c);
}

void limb_freeze(Limb& h) {
    /* Fully propagate carries, then subtract p if h >= p. p = 2^130-5. */
    uint32_t c = 0;
    for (int i = 0; i < 5; ++i) {
        uint32_t s = h.v[i] + c;
        h.v[i] = s & 0x3ffffffu;
        c = s >> 26;
    }
    h.v[0] += c * 5;
    c = 0;
    for (int i = 0; i < 5; ++i) {
        uint32_t s = h.v[i] + c;
        h.v[i] = s & 0x3ffffffu;
        c = s >> 26;
    }
    /* Compare with p = 2^130-5, whose 2^26 limbs are: 2^130-5 = (5 limbs of 2^26) - 5
       so p_limbs = [2^26-5, 2^26-1, 2^26-1, 2^26-1, 2^26-1] masked to 26 bits... 
       2^130 is exactly one past the 5-limb space, so any fully reduced 5-limb value is < 2^130.
       p = 2^130 - 5, values >= p are those >= 2^130-5, i.e. the top of the range.
       A 5*26 value is always < 2^130, so h >= p iff h + 5 >= 2^130 iff adding 5 overflows.
    */
    Limb t = h;
    uint32_t add = 5;
    for (int i = 0; i < 5; ++i) {
        uint32_t s = t.v[i] + add;
        t.v[i] = s & 0x3ffffffu;
        add = s >> 26;
    }
    if (add) {
        /* overflowed => h >= p => h -= p => h = (h+5) - 2^130 = t */
        h = t;
    }
}

void poly_tag(uint8_t tag[16], const uint8_t key[32], const uint8_t* msg, size_t len) {
    uint8_t rbytes[16];
    std::memcpy(rbytes, key, 16);
    poly_clamp(rbytes);
    Limb r = limb_from_block(rbytes, 16, false);
    Limb h{};
    size_t off = 0;
    while (off < len) {
        size_t n = len - off;
        if (n > 16) n = 16;
        Limb block = limb_from_block(msg + off, n, true);
        limb_add(h, block);
        limb_mul(h, r);
        off += n;
    }
    limb_freeze(h);
    /* Serialize 128 bits (drop the hibit place) and add s. */
    uint8_t hbytes[16];
    std::memset(hbytes, 0, 16);
    /* Pack 26-bit limbs back to bytes, low 128 bits. 5*26 = 130, we need 128. */
    uint64_t acc = 0;
    int bits = 0;
    int outi = 0;
    uint32_t limbs[5] = {h.v[0], h.v[1], h.v[2], h.v[3], h.v[4]};
    for (int i = 0; i < 5 && outi < 16; ++i) {
        acc |= static_cast<uint64_t>(limbs[i]) << bits;
        bits += 26;
        while (bits >= 8 && outi < 16) {
            hbytes[outi++] = static_cast<uint8_t>(acc & 0xff);
            acc >>= 8;
            bits -= 8;
        }
    }
    uint32_t s0 = load_le32(key + 16);
    uint32_t s1 = load_le32(key + 20);
    uint32_t s2 = load_le32(key + 24);
    uint32_t s3 = load_le32(key + 28);
    uint32_t h0 = load_le32(hbytes);
    uint32_t h1 = load_le32(hbytes + 4);
    uint32_t h2 = load_le32(hbytes + 8);
    uint32_t h3 = load_le32(hbytes + 12);
    uint64_t c = static_cast<uint64_t>(h0) + s0;
    store_le32(tag, static_cast<uint32_t>(c));
    c = (c >> 32) + h1 + s1;
    store_le32(tag + 4, static_cast<uint32_t>(c));
    c = (c >> 32) + h2 + s2;
    store_le32(tag + 8, static_cast<uint32_t>(c));
    c = (c >> 32) + h3 + s3;
    store_le32(tag + 12, static_cast<uint32_t>(c));
}

void pad16(uint8_t* dst, size_t* n, const uint8_t* src, size_t len) {
    for (size_t i = 0; i < len; ++i) dst[(*n)++] = src[i];
    while ((*n) & 15) dst[(*n)++] = 0;
}

}  // namespace

void chacha20_xor(uint8_t* dst, const uint8_t* src, size_t len, const uint8_t key[32],
                  const uint8_t nonce[12], uint32_t counter) {
    uint32_t st[16];
    st[0] = 0x61707865;
    st[1] = 0x3320646e;
    st[2] = 0x79622d32;
    st[3] = 0x6b206574;
    for (int i = 0; i < 8; ++i) st[4 + i] = load_le32(key + i * 4);
    st[12] = counter;
    st[13] = load_le32(nonce);
    st[14] = load_le32(nonce + 4);
    st[15] = load_le32(nonce + 8);
    uint8_t block[64];
    size_t off = 0;
    while (off < len) {
        chacha_block(block, st);
        st[12]++;
        size_t n = len - off;
        if (n > 64) n = 64;
        for (size_t i = 0; i < n; ++i) dst[off + i] = src[off + i] ^ block[i];
        off += n;
    }
    secure_zero(block, sizeof(block));
}

bool aead_encrypt(uint8_t* cipher, size_t cipher_cap, size_t* cipher_len, const uint8_t* plain,
                  size_t plain_len, const uint8_t* aad, size_t aad_len, const uint8_t key[32],
                  const uint8_t nonce[12]) {
    if (cipher_cap < plain_len + 16) return false;
    uint8_t polykey_block[64];
    std::memset(polykey_block, 0, sizeof(polykey_block));
    chacha20_xor(polykey_block, polykey_block, 64, key, nonce, 0);
    chacha20_xor(cipher, plain, plain_len, key, nonce, 1);
    /* MAC input: aad || pad || cipher || pad || le64(aad_len) || le64(cipher_len) */
    size_t mac_len = ((aad_len + 15) & ~size_t{15}) + ((plain_len + 15) & ~size_t{15}) + 16;
    /* Stack buffer is fine for our MSS. Cap AAD+cipher to 8 KiB. */
    if (aad_len > 2048 || plain_len > 4096) return false;
    uint8_t mac[2048 + 4096 + 64];
    size_t n = 0;
    if (aad && aad_len) pad16(mac, &n, aad, aad_len);
    else if (aad_len == 0) {
        /* no bytes, no pad */
    }
    pad16(mac, &n, cipher, plain_len);
    store_le64(mac + n, aad_len);
    n += 8;
    store_le64(mac + n, plain_len);
    n += 8;
    (void)mac_len;
    poly_tag(cipher + plain_len, polykey_block, mac, n);
    *cipher_len = plain_len + 16;
    secure_zero(polykey_block, sizeof(polykey_block));
    return true;
}

bool aead_decrypt(uint8_t* plain, size_t plain_cap, size_t* plain_len, const uint8_t* cipher,
                  size_t cipher_len, const uint8_t* aad, size_t aad_len, const uint8_t key[32],
                  const uint8_t nonce[12]) {
    if (cipher_len < 16) return false;
    size_t clen = cipher_len - 16;
    if (plain_cap < clen) return false;
    if (aad_len > 2048 || clen > 4096) return false;
    uint8_t polykey_block[64];
    std::memset(polykey_block, 0, sizeof(polykey_block));
    chacha20_xor(polykey_block, polykey_block, 64, key, nonce, 0);
    uint8_t mac[2048 + 4096 + 64];
    size_t n = 0;
    if (aad && aad_len) pad16(mac, &n, aad, aad_len);
    pad16(mac, &n, cipher, clen);
    store_le64(mac + n, aad_len);
    n += 8;
    store_le64(mac + n, clen);
    n += 8;
    uint8_t tag[16];
    poly_tag(tag, polykey_block, mac, n);
    if (!ct_equal(tag, cipher + clen, 16)) {
        secure_zero(polykey_block, sizeof(polykey_block));
        return false;
    }
    chacha20_xor(plain, cipher, clen, key, nonce, 1);
    *plain_len = clen;
    secure_zero(polykey_block, sizeof(polykey_block));
    return true;
}

uint32_t crc32_ieee(const uint8_t* data, size_t len) {
    uint32_t c = 0xffffffffu;
    for (size_t i = 0; i < len; ++i) {
        c ^= data[i];
        for (int b = 0; b < 8; ++b) {
            uint32_t mask = -(c & 1u);
            c = (c >> 1) ^ (0xedb88320u & mask);
        }
    }
    return ~c;
}

}  // namespace genesis
