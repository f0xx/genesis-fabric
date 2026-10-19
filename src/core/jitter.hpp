#pragma once

#include <cstdint>

namespace genesis {

/* RFC 3550 interarrival jitter. Clock offset cancels because the sample is
 * (arrival delta) - (sender timestamp delta), not a raw one-way delay. */
struct JitterMeter {
    uint64_t jitter_us = 0;
    uint64_t prev_arrival = 0;
    uint64_t prev_sent = 0;
    bool have = false;

    void observe(uint64_t sent_ts, uint64_t arrival) {
        if (sent_ts == 0 || arrival == 0) return;
        if (!have) {
            prev_arrival = arrival;
            prev_sent = sent_ts;
            have = true;
            return;
        }
        uint64_t ad = arrival > prev_arrival ? arrival - prev_arrival : prev_arrival - arrival;
        uint64_t sd = sent_ts > prev_sent ? sent_ts - prev_sent : prev_sent - sent_ts;
        uint64_t d = ad > sd ? ad - sd : sd - ad;
        if (d >= jitter_us) jitter_us += (d - jitter_us) / 16;
        else jitter_us -= (jitter_us - d) / 16;
        prev_arrival = arrival;
        prev_sent = sent_ts;
    }
};

/* Hold time before a gap is treated as loss. Cellular keeps a wide window
 * because the path jitters without dropping. Ethernet stays tight. */
inline uint64_t jitter_hold_us(uint64_t jitter_us, int link_kind, int jitter_ms) {
    if (jitter_ms > 0) return static_cast<uint64_t>(jitter_ms) * 1000ull;
    uint64_t h = jitter_us * 2;
    uint64_t floor = 2000;
    uint64_t cap = 20000;
    if (link_kind == 3) {
        floor = 40000;
        cap = 200000;
    } else if (link_kind == 2) {
        floor = 8000;
        cap = 60000;
    }
    if (h < floor) h = floor;
    if (h > cap) h = cap;
    return h;
}

}  // namespace genesis
