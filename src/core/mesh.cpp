#include "mesh.hpp"
#include "endian.hpp"
#include "util.hpp"

namespace genesis {

size_t mesh_encode_gossip(MeshTable& t, uint8_t* plain, size_t cap, uint64_t now) {
    int n = 0;
    for (int i = 0; i < kMeshCap; ++i)
        if (t.nodes[i].used) ++n;
    size_t need = 8 + 8 + 2 + static_cast<size_t>(n) * (16 + 16 + 4 + 4 + 4);
    if (need > cap) return 0;
    ++t.gossip_seq;
    size_t o = 0;
    store_be64(plain + o, t.gossip_seq);
    o += 8;
    store_be64(plain + o, now);
    o += 8;
    store_be16(plain + o, static_cast<uint16_t>(n));
    o += 2;
    for (int i = 0; i < kMeshCap; ++i) {
        if (!t.nodes[i].used) continue;
        std::memcpy(plain + o, t.nodes[i].id, 16);
        o += 16;
        std::memcpy(plain + o, t.nodes[i].next_hop, 16);
        o += 16;
        store_be32(plain + o, t.nodes[i].metric);
        o += 4;
        store_be32(plain + o, t.nodes[i].rtt_us);
        o += 4;
        store_be32(plain + o, t.nodes[i].bw_kbps);
        o += 4;
    }
    return o;
}

bool mesh_apply_gossip(MeshTable& t, uint8_t* plain, size_t len, const uint8_t self_id[16]) {
    if (len < 18) return false;
    uint64_t seq = load_be64(plain);
    if (seq <= t.last_rx_seq) return false;
    uint64_t now = load_be64(plain + 8);
    uint16_t count = load_be16(plain + 16);
    size_t o = 18;
    if (o + static_cast<size_t>(count) * 44 > len) return false;
    for (uint16_t i = 0; i < count; ++i) {
        uint8_t id[16], hop[16];
        std::memcpy(id, plain + o, 16);
        o += 16;
        std::memcpy(hop, plain + o, 16);
        o += 16;
        uint32_t metric = load_be32(plain + o);
        o += 4;
        uint32_t rtt = load_be32(plain + o);
        o += 4;
        uint32_t bw = load_be32(plain + o);
        o += 4;
        if (ct_equal(id, self_id, 16)) continue;
        int slot = mesh_find(t, id);
        if (slot >= 0 && t.nodes[slot].updated_us && now + 1000 < t.nodes[slot].updated_us) continue;
        /* A direct observation (next hop is the node itself and we measured it) wins
         * over a gossip advertisement that is not strictly better. */
        bool direct = slot >= 0 && ct_equal(t.nodes[slot].next_hop, id, 16) && t.nodes[slot].updated_us;
        if (direct && t.nodes[slot].metric <= metric) continue;
        int dst = mesh_upsert(t, id);
        if (dst < 0) continue;
        std::memcpy(t.nodes[dst].next_hop, hop, 16);
        t.nodes[dst].metric = metric ? metric : mesh_metric(rtt, bw);
        t.nodes[dst].rtt_us = rtt;
        t.nodes[dst].bw_kbps = bw;
        t.nodes[dst].updated_us = now;
    }
    t.last_rx_seq = seq;
    return true;
}

}  // namespace genesis
