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

/* Trailer after the v1 name. Older decoders stop at the name and ignore it.
 * names[][32] is the export name, rw is 1 for read-write. count 0 leaves len unchanged. */
size_t beacon_append_exports(uint8_t* dst, size_t cap, size_t len, const char names[][32], const uint8_t* rw,
                             int count);
/* 0 when there is no trailer or it is truncated. Does not fail beacon_decode. */
int beacon_read_exports(const uint8_t* src, size_t len, char names[][32], uint8_t* rw, int cap);

}  // namespace genesis
