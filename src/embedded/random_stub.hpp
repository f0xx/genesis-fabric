#pragma once

#include <cstddef>
#include <cstdint>

/* Embedded ports replace src/posix/random.cpp with this hook.
 * The protocol core does not open sockets. A Zephyr, ESP-IDF, or bare-metal
 * port supplies entropy here and drives Engine::on_datagram / tick / pop
 * from its own UDP driver. */

namespace genesis {
void embedded_set_random(int (*hook)(uint8_t*, size_t));
}
