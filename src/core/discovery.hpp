#pragma once

#include <cstddef>
#include <cstdint>

namespace genesis {

constexpr uint32_t kDiscoveryMagic = 0x47444953u; /* 'GDIS' */
constexpr uint16_t kDiscoveryPort = 37421;
/* Link-local multicast. Not SSDP/1900: we do not rewrite router mappings. */
constexpr uint32_t kDiscoveryGroup = 0xefff2a13u; /* 239.255.42.19 */

struct Beacon {
    uint8_t version = 1;
    uint16_t port = 0;
    uint32_t features = 0;
    uint8_t node_id[16]{};
    char name[32]{};
};

size_t beacon_encode(uint8_t* dst, size_t cap, const Beacon& b);
bool beacon_decode(const uint8_t* src, size_t len, Beacon& b);

}  // namespace genesis
