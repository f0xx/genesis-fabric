#pragma once

#include <cstring>

namespace genesis {

/* 1 ethernet (primary), 2 wifi (secondary), 3 cellular (third). 0 unknown. */
inline int classify_iface(const char* name) {
    if (!name || !name[0]) return 0;
    if (std::strncmp(name, "wwan", 4) == 0 || std::strncmp(name, "rmnet", 5) == 0 ||
        std::strncmp(name, "ppp", 3) == 0 || std::strncmp(name, "usb", 3) == 0)
        return 3;
    if (std::strncmp(name, "wlan", 4) == 0 || std::strncmp(name, "wl", 2) == 0 ||
        std::strncmp(name, "wifi", 4) == 0 || std::strncmp(name, "wlp", 3) == 0)
        return 2;
    if (std::strncmp(name, "eth", 3) == 0 || std::strncmp(name, "en", 2) == 0 ||
        std::strncmp(name, "lan", 3) == 0)
        return 1;
    return 0;
}

/* RTT/jitter guess used when the interface name is unknown.
 * Ethernet is preferred when both a name and a sample exist: a fast RTT does
 * not reclassify a wwan interface, and a slow RTT does not reclassify eth. */
inline int classify_rtt(uint64_t rtt_us, uint64_t jitter_us) {
    if (rtt_us == 0) return 0;
    if (rtt_us < 2000 && jitter_us < 1500) return 1;
    if (rtt_us < 40000 && jitter_us < 20000) return 2;
    return 3;
}

inline int choose_link(int iface, int rtt_class) {
    if (iface == 1 || iface == 2 || iface == 3) return iface;
    return rtt_class;
}

}  // namespace genesis
