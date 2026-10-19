#include "udp.hpp"

#include "crypto.hpp"
#include "link.hpp"
#include "stun.hpp"

#include <arpa/inet.h>
#include <cerrno>
#include <poll.h>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#if defined(__linux__)
#include <pthread.h>
#include <sys/socket.h>
#endif

#if defined(GENESIS_HAS_IO_URING) && GENESIS_HAS_IO_URING
#include <liburing.h>
#endif

namespace genesis {

UdpSocket::~UdpSocket() { close(); }

void UdpSocket::close() {
#if defined(GENESIS_HAS_IO_URING) && GENESIS_HAS_IO_URING
    if (ring_) {
        auto* ring = static_cast<struct ::io_uring*>(ring_);
        io_uring_queue_exit(ring);
        delete ring;
        ring_ = nullptr;
    }
#endif
    if (fd_ >= 0) {
        ::close(fd_);
        fd_ = -1;
    }
    uring_ = false;
}

bool UdpSocket::open(const char* host, uint16_t port, int buffer_bytes, bool want_uring) {
    close();
    fd_ = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (fd_ < 0) return false;
    int one = 1;
    setsockopt(fd_, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    if (buffer_bytes > 0) {
        setsockopt(fd_, SOL_SOCKET, SO_RCVBUF, &buffer_bytes, sizeof(buffer_bytes));
        setsockopt(fd_, SOL_SOCKET, SO_SNDBUF, &buffer_bytes, sizeof(buffer_bytes));
    }
#if defined(IP_MTU_DISCOVER) && defined(IP_PMTUDISC_DO)
    int df = IP_PMTUDISC_DO;
    setsockopt(fd_, IPPROTO_IP, IP_MTU_DISCOVER, &df, sizeof(df));
#endif
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    if (host && host[0] && std::strcmp(host, "0.0.0.0") != 0) {
        uint32_t hip = 0;
        if (!ipv4_resolve(host, &hip)) {
            close();
            return false;
        }
        addr.sin_addr.s_addr = htonl(hip);
    }
    if (bind(fd_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        close();
        return false;
    }
    int flags = fcntl(fd_, F_GETFL, 0);
    fcntl(fd_, F_SETFL, flags | O_NONBLOCK);
#if defined(GENESIS_HAS_IO_URING) && GENESIS_HAS_IO_URING
    if (want_uring) {
        auto* ring = new struct ::io_uring();
        if (io_uring_queue_init(64, ring, 0) == 0) {
            ring_ = ring;
            uring_ = true;
        } else {
            delete ring;
            uring_ = false;
        }
    }
#else
    (void)want_uring;
#endif
    return true;
}

uint16_t UdpSocket::local_port() const {
    sockaddr_in addr{};
    socklen_t len = sizeof(addr);
    if (getsockname(fd_, reinterpret_cast<sockaddr*>(&addr), &len) != 0) return 0;
    return ntohs(addr.sin_port);
}

uint32_t UdpSocket::local_addr_host() const {
    sockaddr_in addr{};
    socklen_t len = sizeof(addr);
    if (getsockname(fd_, reinterpret_cast<sockaddr*>(&addr), &len) != 0) return 0;
    return ntohl(addr.sin_addr.s_addr);
}

bool UdpSocket::join_multicast(uint32_t group_host) {
    ip_mreq mreq{};
    mreq.imr_multiaddr.s_addr = htonl(group_host);
    mreq.imr_interface.s_addr = htonl(INADDR_ANY);
    return setsockopt(fd_, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) == 0;
}

bool UdpSocket::send_to(const uint8_t* data, size_t len, uint32_t addr_host, uint16_t port) {
    sockaddr_in to{};
    to.sin_family = AF_INET;
    to.sin_port = htons(port);
    to.sin_addr.s_addr = htonl(addr_host);
    for (int attempt = 0; attempt < 3; ++attempt) {
        ssize_t n = ::sendto(fd_, data, len, 0, reinterpret_cast<sockaddr*>(&to), sizeof(to));
        if (n == static_cast<ssize_t>(len)) return true;
        if (n < 0 && errno == EINTR) {
            --attempt;
            continue;
        }
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == ENOBUFS)) {
            pollfd pfd{};
            pfd.fd = fd_;
            pfd.events = POLLOUT;
            if (::poll(&pfd, 1, 2) < 0 && errno == EINTR) --attempt;
            continue;
        }
        return false;
    }
    return false;
}

int UdpSocket::send_batch(const uint8_t* const* data, const size_t* lens, const uint32_t* addrs, const uint16_t* ports,
                          int n) {
    if (n <= 0) return 0;
#if defined(__linux__)
    sockaddr_in to[32];
    iovec iov[32];
    mmsghdr msgs[32];
    if (n > 32) n = 32;
    std::memset(msgs, 0, sizeof(mmsghdr) * static_cast<size_t>(n));
    for (int i = 0; i < n; ++i) {
        to[i] = sockaddr_in{};
        to[i].sin_family = AF_INET;
        to[i].sin_port = htons(ports[i]);
        to[i].sin_addr.s_addr = htonl(addrs[i]);
        iov[i].iov_base = const_cast<uint8_t*>(data[i]);
        iov[i].iov_len = lens[i];
        msgs[i].msg_hdr.msg_name = &to[i];
        msgs[i].msg_hdr.msg_namelen = sizeof(to[i]);
        msgs[i].msg_hdr.msg_iov = &iov[i];
        msgs[i].msg_hdr.msg_iovlen = 1;
    }
    int sent = 0;
    while (sent < n) {
        int rc = ::sendmmsg(fd_, msgs + sent, static_cast<unsigned>(n - sent), 0);
        if (rc < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) break;
            return sent > 0 ? sent : -1;
        }
        sent += rc;
        if (rc == 0) break;
    }
    return sent;
#else
    int sent = 0;
    for (int i = 0; i < n; ++i) {
        sockaddr_in to{};
        to.sin_family = AF_INET;
        to.sin_port = htons(ports[i]);
        to.sin_addr.s_addr = htonl(addrs[i]);
        ssize_t rc = ::sendto(fd_, data[i], lens[i], 0, reinterpret_cast<sockaddr*>(&to), sizeof(to));
        if (rc != static_cast<ssize_t>(lens[i])) break;
        ++sent;
    }
    return sent;
#endif
}

int UdpSocket::recv_from(uint8_t* data, size_t cap, uint32_t* addr_host, uint16_t* port, int timeout_ms) {
    pollfd pfd {};
    pfd.fd = fd_;
    pfd.events = POLLIN;
    int pr = ::poll(&pfd, 1, timeout_ms);
    if (pr == 0) return 0;
    if (pr < 0) return (errno == EINTR) ? 0 : -1;
    sockaddr_in from{};
    socklen_t fl = sizeof(from);
    ssize_t n = ::recvfrom(fd_, data, cap, 0, reinterpret_cast<sockaddr*>(&from), &fl);
    if (n < 0) return (errno == EAGAIN || errno == EWOULDBLOCK) ? 0 : -1;
    if (addr_host) *addr_host = ntohl(from.sin_addr.s_addr);
    if (port) *port = ntohs(from.sin_port);
    return static_cast<int>(n);
}

bool ipv4_resolve(const char* host, uint32_t* addr_host) {
    if (!host || !addr_host) return false;
    in_addr ia{};
    if (inet_pton(AF_INET, host, &ia) == 1) {
        *addr_host = ntohl(ia.s_addr);
        return true;
    }
    addrinfo hints{};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    addrinfo* res = nullptr;
    if (getaddrinfo(host, nullptr, &hints, &res) != 0 || !res) return false;
    auto* in = reinterpret_cast<sockaddr_in*>(res->ai_addr);
    *addr_host = ntohl(in->sin_addr.s_addr);
    freeaddrinfo(res);
    return true;
}

bool ipv4_format(uint32_t addr_host, char* dst, size_t cap) {
    in_addr ia{};
    ia.s_addr = htonl(addr_host);
    return inet_ntop(AF_INET, &ia, dst, static_cast<socklen_t>(cap)) != nullptr;
}

uint64_t monotonic_us() {
    timespec ts{};
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return static_cast<uint64_t>(ts.tv_sec) * 1000000ull + static_cast<uint64_t>(ts.tv_nsec) / 1000ull;
}

bool pin_thread(int core) {
    if (core < 0) return false;
#if defined(__linux__)
    cpu_set_t set;
    CPU_ZERO(&set);
    if (core >= CPU_SETSIZE) return false;
    CPU_SET(core, &set);
    return pthread_setaffinity_np(pthread_self(), sizeof(set), &set) == 0;
#else
    (void)core;
    return false;
#endif
}

bool stun_query(UdpSocket& sock, const char* host, uint16_t port, uint32_t* mapped_host, uint16_t* mapped_port) {
    if (!host || !host[0] || !port) return false;
    uint32_t stun_ip = 0;
    if (!ipv4_resolve(host, &stun_ip)) return false;
    uint8_t tid[12];
    if (!random_bytes(tid, 12)) return false;
    uint8_t req[20];
    if (!stun_binding_request(req, sizeof(req), tid)) return false;
    if (!sock.send_to(req, 20, stun_ip, port)) return false;
    uint64_t deadline = monotonic_us() + 1000000ull;
    uint8_t buf[512];
    while (monotonic_us() < deadline) {
        uint32_t from = 0;
        uint16_t fp = 0;
        int n = sock.recv_from(buf, sizeof(buf), &from, &fp, 200);
        if (n <= 0) continue;
        StunResult parsed;
        if (stun_parse_binding_response(buf, static_cast<size_t>(n), tid, parsed) && parsed.ok && parsed.addr_len == 4) {
            *mapped_host = (static_cast<uint32_t>(parsed.addr[0]) << 24) | (static_cast<uint32_t>(parsed.addr[1]) << 16) |
                           (static_cast<uint32_t>(parsed.addr[2]) << 8) | parsed.addr[3];
            *mapped_port = parsed.port;
            return true;
        }
    }
    return false;
}

int primary_link(char* ifname, size_t cap) {
    if (ifname && cap) ifname[0] = '\0';
    FILE* f = std::fopen("/proc/net/route", "r");
    if (!f) return 0;
    char line[256];
    if (!std::fgets(line, sizeof(line), f)) {
        std::fclose(f);
        return 0;
    }
    char best[32]{};
    int best_metric = 100000000;
    while (std::fgets(line, sizeof(line), f)) {
        char name[32];
        unsigned dest = 0, gw = 0, flags = 0, ref = 0, use = 0, metric = 0, mask = 0;
        if (std::sscanf(line, "%31s %x %x %x %u %u %u %x", name, &dest, &gw, &flags, &ref, &use, &metric, &mask) < 7)
            continue;
        if (dest != 0) continue;
        if (static_cast<int>(metric) < best_metric) {
            best_metric = static_cast<int>(metric);
            std::snprintf(best, sizeof(best), "%s", name);
        }
    }
    std::fclose(f);
    if (!best[0]) return 0;
    if (ifname && cap) std::snprintf(ifname, cap, "%s", best);
    return classify_iface(best);
}

}  // namespace genesis
