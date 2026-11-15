#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

namespace genesis {

constexpr uint32_t kNatMagic = 0x474E4154u; /* 'GNAT' */
constexpr uint8_t kNatVersion = 1;
constexpr size_t kNatName = 31;
constexpr size_t kNatInnerMax = 1400;

enum NatType : uint8_t {
    kNatRegister = 1,
    kNatRegistered = 2,
    kNatLookup = 3,
    kNatPeer = 4,
    kNatPunch = 5,
    kNatPunchAck = 6,
    kNatRelay = 7,
    kNatProbe = 8,
    kNatProbeAck = 9,
    kNatBench = 10,
    kNatBenchAck = 11,
    kNatTun = 12,
    kNatTunAck = 13
};

struct NatMsg {
    uint8_t type = 0;
    char room[kNatName + 1]{};
    char name[kNatName + 1]{};
    char peer[kNatName + 1]{};
    uint8_t ok = 0;
    uint32_t addr = 0;
    uint16_t port = 0;
    uint64_t cookie = 0;
    uint32_t id = 0;
    uint32_t total = 0;
    uint32_t ack = 0;
    uint64_t bitmap = 0;
    std::vector<uint8_t> data;
};

bool nat_is(const uint8_t* p, size_t n);
bool nat_name_ok(const char* s);
size_t nat_encode(uint8_t* dst, size_t cap, const NatMsg& m);
bool nat_decode(const uint8_t* src, size_t n, NatMsg& m);

}  // namespace genesis
