#pragma once

#include <cstddef>
#include <cstdint>

namespace genesis {

constexpr uint32_t kDhtMagic = 0x47444854u; /* 'GDHT' */
constexpr int kDhtBuckets = 16;
constexpr int kDhtK = 8;

enum DhtType : uint8_t { kDhtPing = 1, kDhtFind = 2, kDhtNodes = 3 };

struct DhtNode {
    uint8_t id[16]{};
    uint32_t addr = 0;
    uint16_t port = 0;
    uint32_t rtt_us = 0;
    bool used = false;
};

struct DhtMessage {
    uint8_t type = 0;
    uint8_t count = 0;
    uint8_t sender[16]{};
    uint8_t target[16]{};
    DhtNode nodes[kDhtK]{};
};

/* Bit position of the highest XOR bit. 15 is the closest bucket. */
int dht_bucket(const uint8_t self[16], const uint8_t id[16]);
/* 1 near, 0 far. Near means a close id prefix or a sub-30 ms RTT. */
int dht_proximity(const uint8_t self[16], const DhtNode& node);

struct DhtTable {
    uint8_t self[16]{};
    DhtNode buckets[kDhtBuckets][kDhtK]{};

    void set_self(const uint8_t id[16]);
    bool insert(const DhtNode& node);
    int closest(const uint8_t target[16], DhtNode* out, int cap) const;
    int count() const;
};

size_t dht_encode(uint8_t* dst, size_t cap, const DhtMessage& msg);
bool dht_decode(const uint8_t* src, size_t len, DhtMessage& msg);

}  // namespace genesis
