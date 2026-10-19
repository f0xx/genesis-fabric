#pragma once

#include <cstddef>
#include <cstdint>

namespace genesis {

class UdpSocket {
public:
    UdpSocket() = default;
    ~UdpSocket();
    UdpSocket(const UdpSocket&) = delete;
    UdpSocket& operator=(const UdpSocket&) = delete;

    bool open(const char* host, uint16_t port, int buffer_bytes, bool io_uring);
    void close();
    int fd() const { return fd_; }
    uint16_t local_port() const;
    uint32_t local_addr_host() const;
    bool join_multicast(uint32_t group_host);
    bool io_uring() const { return uring_; }

    bool send_to(const uint8_t* data, size_t len, uint32_t addr_host, uint16_t port);
    /* Sends up to n datagrams. Returns how many were accepted by the kernel. */
    int send_batch(const uint8_t* const* data, const size_t* lens, const uint32_t* addrs, const uint16_t* ports, int n);
    /* timeout_ms < 0 blocks, 0 polls, >0 waits. Returns bytes, 0 on timeout, <0 on error. */
    int recv_from(uint8_t* data, size_t cap, uint32_t* addr_host, uint16_t* port, int timeout_ms);

private:
    int fd_ = -1;
    bool uring_ = false;
    void* ring_ = nullptr;
};

bool ipv4_resolve(const char* host, uint32_t* addr_host);
bool ipv4_format(uint32_t addr_host, char* dst, size_t cap);
int primary_link(char* ifname, size_t cap);
uint64_t monotonic_us();
bool pin_thread(int core);

/* STUN binding from an already-bound UDP socket. addr_host/port are host order. */
bool stun_query(UdpSocket& sock, const char* host, uint16_t port, uint32_t* mapped_host, uint16_t* mapped_port);

}  // namespace genesis
