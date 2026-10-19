#include "fec.hpp"

#include <cstring>

namespace genesis {
namespace {

uint8_t gf_exp[512];
uint8_t gf_log[256];
bool gf_ready = false;

void gf_init() {
    if (gf_ready) return;
    unsigned x = 1;
    for (int i = 0; i < 255; ++i) {
        gf_exp[i] = static_cast<uint8_t>(x);
        gf_log[x] = static_cast<uint8_t>(i);
        x <<= 1;
        if (x & 0x100) x ^= 0x11d;
    }
    for (int i = 255; i < 512; ++i) gf_exp[i] = gf_exp[i - 255];
    gf_log[0] = 0;
    gf_ready = true;
}

uint8_t gf_mul(uint8_t a, uint8_t b) {
    if (!a || !b) return 0;
    return gf_exp[static_cast<unsigned>(gf_log[a]) + gf_log[b]];
}

uint8_t gf_inv(uint8_t a) { return gf_exp[255 - gf_log[a]]; }

uint8_t gf_pow(uint8_t a, int n) {
    if (n == 0) return 1;
    if (!a) return 0;
    return gf_exp[(static_cast<unsigned>(gf_log[a]) * static_cast<unsigned>(n)) % 255];
}

uint8_t coeff(int parity_row, int data_col) {
    return gf_pow(static_cast<uint8_t>(parity_row + 1), data_col);
}

bool invert(uint8_t m[kFecMaxData][kFecMaxData], int n) {
    uint8_t invm[kFecMaxData][kFecMaxData] = {};
    for (int i = 0; i < n; ++i) invm[i][i] = 1;
    for (int col = 0; col < n; ++col) {
        int pivot = -1;
        for (int row = col; row < n; ++row) {
            if (m[row][col]) {
                pivot = row;
                break;
            }
        }
        if (pivot < 0) return false;
        if (pivot != col) {
            for (int j = 0; j < n; ++j) {
                uint8_t tmp = m[col][j];
                m[col][j] = m[pivot][j];
                m[pivot][j] = tmp;
                tmp = invm[col][j];
                invm[col][j] = invm[pivot][j];
                invm[pivot][j] = tmp;
            }
        }
        uint8_t inv_p = gf_inv(m[col][col]);
        for (int j = 0; j < n; ++j) {
            m[col][j] = gf_mul(m[col][j], inv_p);
            invm[col][j] = gf_mul(invm[col][j], inv_p);
        }
        for (int row = 0; row < n; ++row) {
            if (row == col || m[row][col] == 0) continue;
            uint8_t f = m[row][col];
            for (int j = 0; j < n; ++j) {
                m[row][j] ^= gf_mul(f, m[col][j]);
                invm[row][j] ^= gf_mul(f, invm[col][j]);
            }
        }
    }
    for (int i = 0; i < n; ++i)
        for (int j = 0; j < n; ++j) m[i][j] = invm[i][j];
    return true;
}

}  // namespace

bool fec_encode(const uint8_t* const* data, int k, int parity, int block, uint8_t* const* out_parity) {
    if (k < 1 || k > kFecMaxData || parity < 1 || parity > kFecMaxParity || block < 1 ||
        block > kFecMaxBlock)
        return false;
    gf_init();
    for (int i = 0; i < parity; ++i) {
        std::memset(out_parity[i], 0, static_cast<size_t>(block));
        for (int j = 0; j < k; ++j) {
            uint8_t m = coeff(i, j);
            const uint8_t* src = data[j];
            uint8_t* dst = out_parity[i];
            for (int b = 0; b < block; ++b) dst[b] ^= gf_mul(src[b], m);
        }
    }
    return true;
}

bool fec_recover(uint8_t** data, const uint8_t* const* parity, const uint8_t* have_data,
                 const uint8_t* have_parity, int k, int parity_n, int block) {
    if (k < 1 || k > kFecMaxData || parity_n < 0 || parity_n > kFecMaxParity || block < 1 ||
        block > kFecMaxBlock)
        return false;
    gf_init();
    int missing = 0;
    for (int j = 0; j < k; ++j)
        if (!have_data[j]) ++missing;
    if (missing == 0) return true;
    int got_parity = 0;
    for (int i = 0; i < parity_n; ++i)
        if (have_parity[i]) ++got_parity;
    if (missing > got_parity) return false;

    /* Build k equations. Present data shard j contributes the identity row.
     * The first `missing` available parity shards contribute Vandermonde rows. */
    int eq_src[kFecMaxData];
    int eq_is_parity[kFecMaxData];
    int ne = 0;
    for (int j = 0; j < k; ++j) {
        if (!have_data[j]) continue;
        eq_src[ne] = j;
        eq_is_parity[ne] = 0;
        ++ne;
    }
    for (int i = 0; i < parity_n && ne < k; ++i) {
        if (!have_parity[i]) continue;
        eq_src[ne] = i;
        eq_is_parity[ne] = 1;
        ++ne;
    }
    if (ne != k) return false;

    uint8_t mat[kFecMaxData][kFecMaxData] = {};
    for (int e = 0; e < k; ++e) {
        if (!eq_is_parity[e]) {
            mat[e][eq_src[e]] = 1;
        } else {
            for (int j = 0; j < k; ++j) mat[e][j] = coeff(eq_src[e], j);
        }
    }
    if (!invert(mat, k)) return false;

    /* Snapshot received shards. Identity rows must not alias the output we overwrite. */
    uint8_t snapshot[kFecMaxData][kFecMaxBlock];
    for (int e = 0; e < k; ++e) {
        const uint8_t* src = eq_is_parity[e] ? parity[eq_src[e]] : data[eq_src[e]];
        std::memcpy(snapshot[e], src, static_cast<size_t>(block));
    }
    for (int j = 0; j < k; ++j) {
        if (have_data[j]) continue;
        std::memset(data[j], 0, static_cast<size_t>(block));
        for (int e = 0; e < k; ++e) {
            uint8_t m = mat[j][e];
            if (!m) continue;
            for (int b = 0; b < block; ++b) data[j][b] ^= gf_mul(snapshot[e][b], m);
        }
    }
    /* Present shards are left untouched. Rows of the inverse that correspond to
     * known data are not applied, which is correct because we only fill holes. */
    return true;
}

}  // namespace genesis
