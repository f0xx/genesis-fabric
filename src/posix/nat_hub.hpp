#pragma once

#include "udp.hpp"

#include <cstddef>
#include <cstdint>

namespace genesis {

struct NatHub;

NatHub* nat_hub_create();
void nat_hub_destroy(NatHub* hub);
void nat_hub_packet(NatHub* hub, UdpSocket& sock, const uint8_t* data, size_t n, uint32_t addr, uint16_t port);

}  // namespace genesis
