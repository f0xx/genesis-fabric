#include "dht.hpp"

#include "endian.hpp"

#include <cstring>

namespace genesis {

int dht_bucket(const uint8_t self[16], const uint8_t id[16]) {
    for (int i = 0; i < 16; ++i) {
        uint8_t x = static_cast<uint8_t>(self[i] ^ id[i]);
        if (!x) continue;
        int bit = 0;
        while ((x & 0x80u) == 0) {
            x = static_cast<uint8_t>(x << 1);
            ++bit;
        }
        int pos = i * 8 + bit;
        int bucket = pos / 8;
        if (bucket > 15) bucket = 15;
        return bucket;
    }
    return 15;
}

int dht_proximity(const uint8_t self[16], const DhtNode& node) {
    if (node.rtt_us > 0 && node.rtt_us < 30000) return 1;
    return dht_bucket(self, node.id) >= 10 ? 1 : 0;
}

void DhtTable::set_self(const uint8_t id[16]) { std::memcpy(self, id, 16); }

bool DhtTable::insert(const DhtNode& node) {
    if (!node.port) return false;
    bool self_id = true;
    for (int i = 0; i < 16; ++i)
        if (node.id[i] != self[i]) self_id = false;
    if (self_id) return false;
    int b = dht_bucket(self, node.id);
    for (int i = 0; i < kDhtK; ++i) {
        if (buckets[b][i].used && std::memcmp(buckets[b][i].id, node.id, 16) == 0) {
            buckets[b][i].addr = node.addr;
            buckets[b][i].port = node.port;
            if (node.rtt_us) buckets[b][i].rtt_us = node.rtt_us;
            return true;
        }
    }
    for (int i = 0; i < kDhtK; ++i) {
        if (!buckets[b][i].used) {
            buckets[b][i] = node;
            buckets[b][i].used = true;
            return true;
        }
    }
    /* Bucket full: replace the farthest RTT so a nearer observation can enter. */
    int worst = 0;
    for (int i = 1; i < kDhtK; ++i)
        if (buckets[b][i].rtt_us > buckets[b][worst].rtt_us) worst = i;
    if (node.rtt_us && (buckets[b][worst].rtt_us == 0 || node.rtt_us < buckets[b][worst].rtt_us)) {
        buckets[b][worst] = node;
        buckets[b][worst].used = true;
        return true;
    }
    return false;
}

int DhtTable::closest(const uint8_t target[16], DhtNode* out, int cap) const {
    if (!out || cap < 1) return 0;
    DhtNode best[kDhtK]{};
    int n = 0;
    for (int b = 0; b < kDhtBuckets; ++b) {
        for (int i = 0; i < kDhtK; ++i) {
            if (!buckets[b][i].used) continue;
            int place = n;
            if (n < kDhtK && n < cap) {
                best[n++] = buckets[b][i];
                place = n - 1;
            } else {
                place = -1;
                int far = 0;
                for (int k = 1; k < n; ++k)
                    if (dht_bucket(target, best[k].id) < dht_bucket(target, best[far].id)) far = k;
                if (dht_bucket(target, buckets[b][i].id) > dht_bucket(target, best[far].id)) {
                    best[far] = buckets[b][i];
                    place = far;
                }
            }
            (void)place;
        }
    }
    for (int i = 1; i < n; ++i) {
        DhtNode key = best[i];
        int j = i;
        while (j > 0 && dht_bucket(target, best[j - 1].id) < dht_bucket(target, key.id)) {
            best[j] = best[j - 1];
            --j;
        }
        best[j] = key;
    }
    for (int i = 0; i < n; ++i) out[i] = best[i];
    return n;
}

int DhtTable::count() const {
    int n = 0;
    for (int b = 0; b < kDhtBuckets; ++b)
        for (int i = 0; i < kDhtK; ++i)
            if (buckets[b][i].used) ++n;
    return n;
}

size_t dht_encode(uint8_t* dst, size_t cap, const DhtMessage& msg) {
    size_t need = 40 + static_cast<size_t>(msg.count) * 26;
    if (!dst || cap < need || msg.count > kDhtK) return 0;
    store_be32(dst, kDhtMagic);
    dst[4] = 1;
    dst[5] = msg.type;
    dst[6] = msg.count;
    dst[7] = 0;
    std::memcpy(dst + 8, msg.sender, 16);
    std::memcpy(dst + 24, msg.target, 16);
    size_t o = 40;
    for (int i = 0; i < msg.count; ++i) {
        std::memcpy(dst + o, msg.nodes[i].id, 16);
        store_be32(dst + o + 16, msg.nodes[i].addr);
        store_be16(dst + o + 20, msg.nodes[i].port);
        store_be32(dst + o + 22, msg.nodes[i].rtt_us);
        o += 26;
    }
    return o;
}

bool dht_decode(const uint8_t* src, size_t len, DhtMessage& msg) {
    if (!src || len < 40 || load_be32(src) != kDhtMagic || src[4] != 1) return false;
    msg = DhtMessage{};
    msg.type = src[5];
    msg.count = src[6];
    if (msg.count > kDhtK) return false;
    if (len < 40 + static_cast<size_t>(msg.count) * 26) return false;
    if (msg.type != kDhtPing && msg.type != kDhtFind && msg.type != kDhtNodes) return false;
    std::memcpy(msg.sender, src + 8, 16);
    std::memcpy(msg.target, src + 24, 16);
    size_t o = 40;
    for (int i = 0; i < msg.count; ++i) {
        std::memcpy(msg.nodes[i].id, src + o, 16);
        msg.nodes[i].addr = load_be32(src + o + 16);
        msg.nodes[i].port = load_be16(src + o + 20);
        msg.nodes[i].rtt_us = load_be32(src + o + 22);
        msg.nodes[i].used = msg.nodes[i].port != 0;
        o += 26;
    }
    return true;
}

}  // namespace genesis
