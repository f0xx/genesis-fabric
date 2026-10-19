#include "crypto.hpp"
#include "endian.hpp"

namespace genesis {
namespace {

uint32_t rotl(uint32_t x, uint32_t n) { return (x << n) | (x >> (32 - n)); }

void compress(uint32_t s[5], const uint8_t block[64]) {
    uint32_t w[80];
    for (int i = 0; i < 16; ++i) w[i] = load_be32(block + i * 4);
    for (int i = 16; i < 80; ++i) w[i] = rotl(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
    uint32_t a = s[0], b = s[1], c = s[2], d = s[3], e = s[4];
    for (int i = 0; i < 80; ++i) {
        uint32_t f, k;
        if (i < 20) {
            f = (b & c) | ((~b) & d);
            k = 0x5a827999;
        } else if (i < 40) {
            f = b ^ c ^ d;
            k = 0x6ed9eba1;
        } else if (i < 60) {
            f = (b & c) | (b & d) | (c & d);
            k = 0x8f1bbcdc;
        } else {
            f = b ^ c ^ d;
            k = 0xca62c1d6;
        }
        uint32_t t = rotl(a, 5) + f + e + k + w[i];
        e = d;
        d = c;
        c = rotl(b, 30);
        b = a;
        a = t;
    }
    s[0] += a;
    s[1] += b;
    s[2] += c;
    s[3] += d;
    s[4] += e;
}

}  // namespace

Sha1::Sha1() {
    state[0] = 0x67452301;
    state[1] = 0xefcdab89;
    state[2] = 0x98badcfe;
    state[3] = 0x10325476;
    state[4] = 0xc3d2e1f0;
}

void Sha1::update(const uint8_t* data, size_t len) {
    bits += static_cast<uint64_t>(len) * 8;
    while (len) {
        size_t take = 64 - n;
        if (take > len) take = len;
        for (size_t i = 0; i < take; ++i) block[n + i] = data[i];
        n += take;
        data += take;
        len -= take;
        if (n == 64) {
            compress(state, block);
            n = 0;
        }
    }
}

void Sha1::final(uint8_t out[20]) {
    uint64_t saved = bits;
    uint8_t pad = 0x80;
    update(&pad, 1);
    pad = 0;
    while (n != 56) update(&pad, 1);
    bits = saved;
    uint8_t lenb[8];
    store_be64(lenb, saved);
    for (int i = 0; i < 8; ++i) block[n++] = lenb[i];
    compress(state, block);
    for (int i = 0; i < 5; ++i) store_be32(out + i * 4, state[i]);
}

void Sha1::hash(const uint8_t* data, size_t len, uint8_t out[20]) {
    Sha1 s;
    s.update(data, len);
    s.final(out);
}

}  // namespace genesis
