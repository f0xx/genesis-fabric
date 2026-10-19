#pragma once

#include <cstddef>
#include <cstdint>

namespace genesis {

constexpr int kFecMaxData = 32;
constexpr int kFecMaxParity = 8;
constexpr int kFecMaxBlock = 1400;

/* Systematic Reed-Solomon over GF(2^8). Parity row 0 is the XOR of the data
 * shards (evaluation point 1), so one parity symbol is a plain XOR. */
bool fec_encode(const uint8_t* const* data, int k, int parity, int block, uint8_t* const* out_parity);

/* `have_data[j]` / `have_parity[i]` are 0 or 1. Missing data buffers must still
 * be writable. On success every data shard is filled in. */
bool fec_recover(uint8_t** data, const uint8_t* const* parity, const uint8_t* have_data,
                 const uint8_t* have_parity, int k, int parity_n, int block);

}  // namespace genesis
