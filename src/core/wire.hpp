#pragma once

#include <cstddef>
#include <cstdint>

namespace genesis {

constexpr uint32_t kMagic = 0x47435831u; /* 'GCX1' */
constexpr uint8_t kProtoVersion = 1;
constexpr size_t kHeaderBytes = 48;
constexpr size_t kMaxDatagram = 1500;

enum FrameType : uint8_t {
    kHello = 1,
    kHelloAck = 2,
    kKeyConfirm = 3,
    kData = 4,
    kFec = 5,
    kAck = 6,
    kNack = 7,
    kFin = 8,
    kFinAck = 9,
    kGossip = 10,
    kPing = 11,
    kPong = 12,
    kPeerUpdate = 13
};

enum HeaderFlag : uint16_t { kFlagEncrypted = 1u << 0 };

enum FeatureBit : uint32_t {
    kFeatFec = 1u << 0,
    kFeatBbr = 1u << 1,
    kFeatMesh = 1u << 2,
    kFeatStream = 1u << 3,
    kFeatFile = 1u << 4,
    kFeatCellular = 1u << 5,
    kFeatGbe = 1u << 6,
    kFeatRelay = 1u << 7,
    kFeatDiscovery = 1u << 8,
    kFeatNack = 1u << 9,
    kFeatWifi = 1u << 10,
    kFeatDht = 1u << 11,
    kFeatJitter = 1u << 12,
    kFeatResume = 1u << 13
};

struct Header {
    uint8_t version = kProtoVersion;
    uint8_t type = 0;
    uint16_t flags = 0;
    uint32_t conn_id = 0;
    uint64_t seq = 0;
    uint64_t ack = 0;
    uint64_t sack = 0;
    uint64_t timestamp_us = 0;
    uint16_t payload_len = 0;
    uint16_t ext_len = 0;
};

bool encode_header(uint8_t* dst, size_t cap, const Header& h);
bool decode_header(const uint8_t* src, size_t len, Header& h);

}  // namespace genesis
