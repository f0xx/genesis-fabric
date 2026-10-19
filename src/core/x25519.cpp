#include "crypto.hpp"
#include "util.hpp"

#include <cstdio>
#include <cstring>

namespace genesis {
namespace {

/* 256-bit little-endian field element, kept reduced modulo 2^255-19. */
struct Fe {
    uint32_t l[8];
};

const uint32_t kP[8] = {0xffffffed, 0xffffffff, 0xffffffff, 0xffffffff,
                        0xffffffff, 0xffffffff, 0xffffffff, 0x7fffffff};

void fe_zero(Fe& a) { std::memset(a.l, 0, sizeof(a.l)); }

void fe_copy(Fe& d, const Fe& s) { std::memcpy(d.l, s.l, sizeof(d.l)); }

void fe_add_raw(uint32_t r[9], const uint32_t a[8], const uint32_t b[8]) {
    uint64_t c = 0;
    for (int i = 0; i < 8; ++i) {
        c += static_cast<uint64_t>(a[i]) + b[i];
        r[i] = static_cast<uint32_t>(c);
        c >>= 32;
    }
    r[8] = static_cast<uint32_t>(c);
}

void fe_sub_p_if_ge(Fe& r) {
    uint32_t tmp[8];
    int64_t br = 0;
    for (int i = 0; i < 8; ++i) {
        int64_t d = static_cast<int64_t>(r.l[i]) - static_cast<int64_t>(kP[i]) + br;
        if (d < 0) {
            d += (static_cast<int64_t>(1) << 32);
            br = -1;
        } else {
            br = 0;
        }
        tmp[i] = static_cast<uint32_t>(d);
    }
    /* br == 0 means r >= p (no borrow). Select tmp, else keep r. Constant-time select. */
    uint32_t mask = static_cast<uint32_t>(-(br == 0));
    for (int i = 0; i < 8; ++i) r.l[i] = (tmp[i] & mask) | (r.l[i] & ~mask);
}

void fe_reduce9(Fe& r, const uint32_t w[9]) {
    /* w < 2^256 + a bit. Fold bit 255 and above: lo + 19*hi. */
    uint32_t lo[8];
    for (int i = 0; i < 8; ++i) lo[i] = w[i];
    uint32_t top = (lo[7] >> 31) | (w[8] << 1);
    lo[7] &= 0x7fffffffu;
    /* hi is a small integer (w[8] is 0 or 1 for sums, larger for products — this helper is for add). */
    uint64_t c = static_cast<uint64_t>(top) * 19u;
    for (int i = 0; i < 8; ++i) {
        c += lo[i];
        r.l[i] = static_cast<uint32_t>(c);
        c >>= 32;
    }
    /* c should now be 0 or a single carry that itself needs folding. */
    if (c) {
        uint64_t c2 = c * 19u;
        for (int i = 0; i < 8; ++i) {
            c2 += r.l[i];
            r.l[i] = static_cast<uint32_t>(c2);
            c2 >>= 32;
        }
    }
    fe_sub_p_if_ge(r);
    fe_sub_p_if_ge(r);
}

void fe_add(Fe& r, const Fe& a, const Fe& b) {
    uint32_t w[9];
    fe_add_raw(w, a.l, b.l);
    fe_reduce9(r, w);
}

void fe_sub(Fe& r, const Fe& a, const Fe& b) {
    int64_t br = 0;
    uint32_t d[8];
    for (int i = 0; i < 8; ++i) {
        int64_t diff = static_cast<int64_t>(a.l[i]) - static_cast<int64_t>(b.l[i]) + br;
        if (diff < 0) {
            diff += (static_cast<int64_t>(1) << 32);
            br = -1;
        } else {
            br = 0;
        }
        d[i] = static_cast<uint32_t>(diff);
    }
    if (br) {
        uint64_t c = 0;
        for (int i = 0; i < 8; ++i) {
            c += static_cast<uint64_t>(d[i]) + kP[i];
            d[i] = static_cast<uint32_t>(c);
            c >>= 32;
        }
    }
    for (int i = 0; i < 8; ++i) r.l[i] = d[i];
    fe_sub_p_if_ge(r);
}

void fe_mul(Fe& r, const Fe& a, const Fe& b) {
    /* Each column sums at most 8 products of 32-bit limbs (~2^67). uint64 overflows. */
    unsigned __int128 t[16] = {};
    for (int i = 0; i < 8; ++i) {
        for (int j = 0; j < 8; ++j)
            t[i + j] += static_cast<unsigned __int128>(a.l[i]) * b.l[j];
    }
    uint32_t w[16];
    unsigned __int128 c = 0;
    for (int i = 0; i < 16; ++i) {
        c += t[i];
        w[i] = static_cast<uint32_t>(c);
        c >>= 32;
    }
    /* Reduce a 512-bit value modulo 2^255-19 three times: lo + 19*hi. */
    for (int round = 0; round < 3; ++round) {
        uint32_t hi[16];
        /* hi = w >> 255. Bit 255 is the top bit of limb 7. */
        uint32_t shifted[16];
        for (int i = 0; i < 16; ++i) shifted[i] = (i + 7 < 16) ? w[i + 7] : 0;
        for (int i = 0; i < 15; ++i) hi[i] = (shifted[i] >> 31) | (shifted[i + 1] << 1);
        hi[15] = shifted[15] >> 31;
        uint32_t lo[8];
        for (int i = 0; i < 7; ++i) lo[i] = w[i];
        lo[7] = w[7] & 0x7fffffffu;
        uint64_t prod[16];
        for (int i = 0; i < 16; ++i) prod[i] = 0;
        for (int i = 0; i < 16; ++i) {
            uint64_t m = static_cast<uint64_t>(hi[i]) * 19u;
            prod[i] += m;
        }
        uint64_t carry = 0;
        uint32_t sum[17];
        for (int i = 0; i < 8; ++i) {
            carry += prod[i] + lo[i];
            sum[i] = static_cast<uint32_t>(carry);
            carry >>= 32;
        }
        for (int i = 8; i < 16; ++i) {
            carry += prod[i];
            sum[i] = static_cast<uint32_t>(carry);
            carry >>= 32;
        }
        sum[16] = static_cast<uint32_t>(carry);
        for (int i = 0; i < 16; ++i) w[i] = sum[i];
        /* Fold the 17th limb (very small) into a 16-limb buffer by * 2^(512) mod p.
           2^512 = 2^(2*255 + 2) = (2^255)^2 * 4 ≡ 19^2 * 4 = 1444. We only have sum[16]
           which is the coefficient of 2^512. */
        if (sum[16]) {
            uint64_t extra = static_cast<uint64_t>(sum[16]) * 1444u;
            carry = extra;
            for (int i = 0; i < 16; ++i) {
                carry += w[i];
                w[i] = static_cast<uint32_t>(carry);
                carry >>= 32;
            }
        }
    }
    for (int i = 0; i < 8; ++i) r.l[i] = w[i];
    /* High limbs must be zero after three reductions; fold once more if not. */
    uint32_t rest = 0;
    for (int i = 8; i < 16; ++i) rest |= w[i];
    if (rest || (r.l[7] >> 31)) {
        uint32_t wide[9];
        for (int i = 0; i < 8; ++i) wide[i] = r.l[i];
        wide[8] = 0;
        fe_reduce9(r, wide);
    }
    fe_sub_p_if_ge(r);
    fe_sub_p_if_ge(r);
}

void fe_sq(Fe& r, const Fe& a) { fe_mul(r, a, a); }

void fe_from_bytes(Fe& r, const uint8_t in[32]) {
    uint32_t w[9];
    for (int i = 0; i < 8; ++i) {
        w[i] = static_cast<uint32_t>(in[i * 4]) | (static_cast<uint32_t>(in[i * 4 + 1]) << 8) |
               (static_cast<uint32_t>(in[i * 4 + 2]) << 16) | (static_cast<uint32_t>(in[i * 4 + 3]) << 24);
    }
    w[7] &= 0x7fffffffu;
    w[8] = 0;
    fe_reduce9(r, w);
}

void fe_to_bytes(uint8_t out[32], const Fe& a) {
    Fe t;
    fe_copy(t, a);
    fe_sub_p_if_ge(t);
    for (int i = 0; i < 8; ++i) {
        out[i * 4] = static_cast<uint8_t>(t.l[i]);
        out[i * 4 + 1] = static_cast<uint8_t>(t.l[i] >> 8);
        out[i * 4 + 2] = static_cast<uint8_t>(t.l[i] >> 16);
        out[i * 4 + 3] = static_cast<uint8_t>(t.l[i] >> 24);
    }
}

void fe_cswap(Fe& a, Fe& b, uint32_t swap) {
    uint32_t mask = 0u - swap;
    for (int i = 0; i < 8; ++i) {
        uint32_t x = mask & (a.l[i] ^ b.l[i]);
        a.l[i] ^= x;
        b.l[i] ^= x;
    }
}

void fe_mul_small(Fe& r, const Fe& a, uint32_t k) {
    uint64_t c = 0;
    uint32_t w[9];
    for (int i = 0; i < 8; ++i) {
        c += static_cast<uint64_t>(a.l[i]) * k;
        w[i] = static_cast<uint32_t>(c);
        c >>= 32;
    }
    w[8] = static_cast<uint32_t>(c);
    fe_reduce9(r, w);
}

void fe_inv(Fe& r, const Fe& a) {
    /* a^(p-2) = a^(2^255 - 21). Exponent bits: 8..254 are 1, low byte is 0xEB. */
    Fe base;
    fe_copy(base, a);
    Fe result;
    fe_zero(result);
    result.l[0] = 1;
    for (int bit = 254; bit >= 0; --bit) {
        fe_sq(result, result);
        int on = (bit >= 8) ? 1 : ((0xEB >> bit) & 1);
        if (on) fe_mul(result, result, base);
    }
    fe_copy(r, result);
}

}  // namespace

int field_selftest() {
    auto check = [](const char* name, const Fe& got, uint32_t expect0) {
        if (got.l[0] != expect0) {
            std::fprintf(stderr, "field %s got %u\n", name, got.l[0]);
            return 1;
        }
        for (int i = 1; i < 8; ++i) {
            if (got.l[i] != 0) {
                std::fprintf(stderr, "field %s high limb %d = %u\n", name, i, got.l[i]);
                return 1;
            }
        }
        return 0;
    };
    int bad = 0;
    Fe a{}, b{}, r{};
    a.l[0] = 2;
    b.l[0] = 3;
    fe_mul(r, a, b);
    bad += check("2*3", r, 6);
    fe_add(r, a, b);
    bad += check("2+3", r, 5);
    fe_sub(r, b, a);
    bad += check("3-2", r, 1);
    Fe one{};
    one.l[0] = 1;
    fe_sub(r, one, b); /* 1-3 = p-2 */
    if (r.l[0] != kP[0] - 2) {
        std::fprintf(stderr, "field 1-3 low %u\n", r.l[0]);
        bad++;
    }
    a.l[0] = 0xffffffffu;
    b.l[0] = 0xffffffffu;
    fe_mul(r, a, b);
    if (r.l[0] != 1u || r.l[1] != 0xfffffffeu) {
        std::fprintf(stderr, "field ff*ff %08x %08x\n", r.l[0], r.l[1]);
        bad++;
    }
    fe_zero(a);
    a.l[7] = 1u << 30; /* 2^254 */
    fe_mul_small(r, a, 4);
    bad += check("2^256", r, 38);
    fe_zero(a);
    a.l[6] = 1u << 8; /* 2^200 */
    fe_sq(b, a);      /* 2^400 ≡ 19 * 2^145 */
    fe_zero(r);
    r.l[4] = 19u << 17;
    if (std::memcmp(b.l, r.l, sizeof(r.l)) != 0) {
        std::fprintf(stderr, "field 2^400");
        for (int i = 0; i < 8; ++i) std::fprintf(stderr, " %08x", b.l[i]);
        std::fprintf(stderr, "\n");
        bad++;
    }
    fe_zero(a);
    a.l[0] = 5;
    Fe inv{};
    fe_inv(inv, a);
    fe_mul(r, a, inv);
    bad += check("5*inv", r, 1);
    /* 9 * 121665 */
    a.l[0] = 9;
    fe_mul_small(r, a, 121665);
    if (r.l[0] != 9u * 121665u) {
        std::fprintf(stderr, "field 9*121665 %u\n", r.l[0]);
        bad++;
    }
    fe_zero(a);
    a.l[0] = 5;
    for (int i = 0; i < 10; ++i) fe_sq(a, a);
    const uint32_t want1024[8] = {0x4b50c75d, 0x8734b649, 0x699d3c71, 0x64f9cba3,
                                  0xbba92f6a, 0xb087936f, 0x554756f4, 0x1f6247ab};
    if (std::memcmp(a.l, want1024, sizeof(want1024)) != 0) {
        std::fprintf(stderr, "field 5^1024 mismatch\n");
        bad++;
    }
    return bad;
}

void x25519(uint8_t out[32], const uint8_t scalar_in[32], const uint8_t point[32]) {
    uint8_t scalar[32];
    std::memcpy(scalar, scalar_in, 32);
    scalar[0] &= 248;
    scalar[31] &= 127;
    scalar[31] |= 64;

    Fe x1;
    fe_from_bytes(x1, point);
    Fe x2, z2, x3, z3;
    fe_zero(x2);
    x2.l[0] = 1;
    fe_zero(z2);
    fe_copy(x3, x1);
    fe_zero(z3);
    z3.l[0] = 1;
    uint32_t swap = 0;

    for (int t = 254; t >= 0; --t) {
        uint32_t kt = (scalar[t / 8] >> (t % 8)) & 1u;
        swap ^= kt;
        fe_cswap(x2, x3, swap);
        fe_cswap(z2, z3, swap);
        swap = kt;

        Fe A, AA, B, BB, E, C, D, DA, CB, sum, diff;
        fe_add(A, x2, z2);
        fe_sq(AA, A);
        fe_sub(B, x2, z2);
        fe_sq(BB, B);
        fe_sub(E, AA, BB);
        fe_add(C, x3, z3);
        fe_sub(D, x3, z3);
        fe_mul(DA, D, A);
        fe_mul(CB, C, B);
        fe_add(sum, DA, CB);
        fe_sq(x3, sum);
        fe_sub(diff, DA, CB);
        fe_sq(diff, diff);
        fe_mul(z3, x1, diff);
        fe_mul(x2, AA, BB);
        Fe e121;
        fe_mul_small(e121, E, 121665);
        fe_add(e121, AA, e121);
        fe_mul(z2, E, e121);
    }
    fe_cswap(x2, x3, swap);
    fe_cswap(z2, z3, swap);
    Fe zinv;
    fe_inv(zinv, z2);
    Fe res;
    fe_mul(res, x2, zinv);
    fe_to_bytes(out, res);
    secure_zero(scalar, sizeof(scalar));
}

void x25519_base(uint8_t pubkey[32], const uint8_t scalar[32]) {
    uint8_t base[32] = {9};
    x25519(pubkey, scalar, base);
}

void x25519_keypair(uint8_t pubkey[32], uint8_t secret[32]) {
    if (!random_bytes(secret, 32)) std::memset(secret, 0, 32);
    x25519_base(pubkey, secret);
}

}  // namespace genesis
