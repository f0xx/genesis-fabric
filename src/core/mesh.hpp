#pragma once

#include "crypto.hpp"
#include "util.hpp"

#include <cstdint>
#include <cstring>

namespace genesis {

struct MeshNode {
    uint8_t id[16]{};
    char name[32]{};
    uint32_t metric = 0xffffffffu;
    uint32_t rtt_us = 0;
    uint32_t bw_kbps = 0;
    uint8_t next_hop[16]{};
    uint64_t updated_us = 0;
    bool used = false;
};

constexpr int kMeshCap = 32;

struct MeshTable {
    MeshNode nodes[kMeshCap]{};
    uint64_t gossip_seq = 0;
    uint64_t last_rx_seq = 0;
};

inline uint32_t mesh_metric(uint32_t rtt_us, uint32_t bw_kbps) {
    /* Lower is better. Same shape as the design note (rtt / bandwidth) but in integers
     * so the value is stable across endianness and does not ride in a double. */
    uint32_t bw = bw_kbps ? bw_kbps : 1;
    uint64_t m = (static_cast<uint64_t>(rtt_us) * 1000ull) / bw;
    if (m > 0xffffffffull) m = 0xffffffffull;
    if (m == 0) m = 1;
    return static_cast<uint32_t>(m);
}

inline int mesh_find(MeshTable& t, const uint8_t id[16]) {
    for (int i = 0; i < kMeshCap; ++i)
        if (t.nodes[i].used && ct_equal(t.nodes[i].id, id, 16)) return i;
    return -1;
}

inline int mesh_upsert(MeshTable& t, const uint8_t id[16]) {
    int i = mesh_find(t, id);
    if (i >= 0) return i;
    for (int n = 0; n < kMeshCap; ++n) {
        if (!t.nodes[n].used) {
            t.nodes[n] = MeshNode{};
            std::memcpy(t.nodes[n].id, id, 16);
            std::memcpy(t.nodes[n].next_hop, id, 16);
            t.nodes[n].used = true;
            return n;
        }
    }
    return -1;
}

inline void mesh_observe(MeshTable& t, const uint8_t id[16], uint32_t rtt_us, uint32_t bw_kbps, uint64_t now) {
    int i = mesh_upsert(t, id);
    if (i < 0) return;
    t.nodes[i].rtt_us = rtt_us;
    t.nodes[i].bw_kbps = bw_kbps;
    t.nodes[i].metric = mesh_metric(rtt_us, bw_kbps);
    std::memcpy(t.nodes[i].next_hop, id, 16);
    t.nodes[i].updated_us = now;
}

inline bool mesh_best_hop(const MeshTable& t, const uint8_t dest[16], uint8_t hop[16], uint32_t* metric) {
    int best = -1;
    for (int i = 0; i < kMeshCap; ++i) {
        if (!t.nodes[i].used) continue;
        if (!ct_equal(t.nodes[i].id, dest, 16)) continue;
        best = i;
        break;
    }
    if (best < 0) return false;
    std::memcpy(hop, t.nodes[best].next_hop, 16);
    if (metric) *metric = t.nodes[best].metric;
    return true;
}

/* Gossip body is AEAD'd with the session key. Plaintext carries a monotonic seq
 * so a replay of an old map is rejected. There is no plaintext "network token". */
size_t mesh_encode_gossip(MeshTable& t, uint8_t* plain, size_t cap, uint64_t now);
bool mesh_apply_gossip(MeshTable& t, uint8_t* plain, size_t len, const uint8_t self_id[16]);

}  // namespace genesis
