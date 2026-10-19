#pragma once

#include "wire.hpp"

#include <cstddef>
#include <cstdint>

namespace genesis {

constexpr int kMaxCandidates = 8;
constexpr uint8_t kHsVersion = 1;

struct PeerView {
    uint8_t hs_version = kHsVersion;
    uint8_t profile = 0;
    uint32_t features = 0;
    uint8_t pubkey[32]{};
    uint8_t nonce[16]{};
    uint8_t node_id[16]{};
    uint16_t udp_port = 0;
    char name[33]{};
    char file_name[201]{};
    uint64_t file_size = 0;
    uint8_t cand_kind[kMaxCandidates]{};
    uint8_t cand_addr[kMaxCandidates][4]{};
    uint16_t cand_port[kMaxCandidates]{};
    int cand_count = 0;
    uint64_t update_seq = 0;
};

bool encode_hello(uint8_t* dst, size_t cap, size_t* out_len, const PeerView& peer);
bool decode_hello(const uint8_t* src, size_t len, PeerView& peer);
/* Trailing TLVs after the v1 hello body. Older peers stop before them.
 * Type 1 is the sender chunk size. Type 2 is the receiver's resume offset. */
size_t hello_append_tail(uint8_t* dst, size_t cap, size_t len, uint16_t chunk, uint64_t resume_off);
void hello_read_tail(const uint8_t* src, size_t len, uint16_t* chunk, uint64_t* resume_off);

void derive_transport_keys(const uint8_t shared[32], const uint8_t* psk, bool have_psk,
                           const uint8_t nonce_init[16], const uint8_t nonce_resp[16],
                           uint8_t key_i2r[32], uint8_t key_r2i[32]);

/* Returns bytes written, or 0 on overflow. seq is the monotonic update counter. */
size_t encode_peer_update(uint8_t* dst, size_t cap, uint64_t seq, const PeerView& peer);
/* Rejects replay (seq <= peer.update_seq) and unknown TLV versions by skipping them. */
bool apply_peer_update(PeerView& peer, const uint8_t* src, size_t len);

}  // namespace genesis
