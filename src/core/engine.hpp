#pragma once

#include <cstddef>
#include <cstdint>

namespace genesis {

struct Endpoint {
    uint32_t addr_be = 0;
    uint16_t port = 0;
};

struct EngineOpts {
    int profile = 0;
    int fec_k = 8;
    int fec_r = 1;
    int plain_mss = 1200;
    int window = 256;
    int enable_fec = 1;   /* -1 auto, 0 off, 1 on */
    int enable_nack = 0;  /* -1 auto, 0 off, 1 on. Tests default off. */
    int enable_dht = 1;
    int link_hint = 0; /* 0 unknown, 1 ethernet, 2 wifi, 3 cellular */
    int jitter_ms = 0; /* 0 = from the link class */
    bool enable_mesh = true;
    bool have_psk = false;
    uint8_t psk[32]{};
    bool have_cookie = false;
    uint8_t cookie[16]{};
    bool have_expect_pub = false;
    uint8_t expect_pub[32]{};
    char node_name[32] = "node";
    char file_name[200] = {};
    uint64_t file_size = 0;
    int punch_ms = 1500;
    uint16_t local_port = 0;
};

struct DatagramOut {
    uint8_t data[1500]{};
    uint16_t len = 0;
    uint32_t addr_be = 0;
    uint16_t port = 0;
};

using IoRead = int (*)(void*, uint8_t*, int);
using IoWrite = int (*)(void*, const uint8_t*, int);
/* absorb receives the durable prefix so the final SHA-256 still covers the whole file.
 * Return a multiple of align, or 0 to start over. */
using ResumeAbsorb = void (*)(void* state, const uint8_t* data, int n);
using ResumeFn = uint64_t (*)(void* user, const char* file_name, uint64_t file_size, int align, ResumeAbsorb absorb,
                              void* absorb_state);

class Engine {
public:
    Engine(const EngineOpts& opt, bool sender);
    ~Engine();
    Engine(const Engine&) = delete;
    Engine& operator=(const Engine&) = delete;

    void add_candidate(Endpoint ep);
    void add_route(Endpoint ep);
    void set_io(IoRead read, IoWrite write, void* user);
    void set_resume(ResumeFn fn, void* user);
    uint64_t resume_offset() const;
    void start(uint64_t now_us);
    void on_datagram(const uint8_t* data, size_t len, Endpoint from, uint64_t now_us);
    void tick(uint64_t now_us);
    bool pop(DatagramOut& out);
    bool done() const;
    bool success() const;
    const char* error() const;
    uint64_t payload_done() const;
    uint64_t file_size() const;
    uint64_t pacing_bps() const;
    uint64_t rate_bps(uint64_t now_us) const;
    uint64_t min_rtt_us() const;
    uint64_t next_wakeup_us() const;
    int profile() const;
    int phase() const;
    uint32_t peer_features() const;
    int peer_handshake_version() const;
    const char* peer_name() const;
    const char* peer_file_name() const;
    uint64_t retx() const;
    uint64_t fec_recovered() const;
    uint64_t wire_tx() const;
    uint64_t wire_rx() const;
    uint64_t jitter_us() const;
    uint64_t nacks_sent() const;
    uint64_t packets_tx() const;
    uint64_t packets_rx() const;
    uint64_t fec_tx_packets() const;
    uint64_t fec_rx_packets() const;
    uint64_t nack_tx_packets() const;
    uint64_t nack_rx_packets() const;
    uint64_t fec_tx_bytes() const;
    uint64_t nack_tx_bytes() const;
    uint64_t started_us() const;
    int link_kind() const;
    int fec_on() const;
    int nack_on() const;
    int routes_alive() const;
    int dht_peers() const;
    void sha256_hex(char out[65]) const;

private:
    struct Impl;
    Impl* impl_;
};

}  // namespace genesis
