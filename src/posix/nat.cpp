#include "genesis/api.h"
#include "nat_hub.hpp"

#include "crypto.hpp"
#include "endian.hpp"
#include "nat.hpp"
#include "wire.hpp"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <deque>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include <arpa/inet.h>
#include <fcntl.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

namespace genesis {
namespace {

constexpr uint64_t kSlotUs = 45000000ull;

struct Slot {
    bool used = false;
    char room[kNatName + 1]{};
    char name[kNatName + 1]{};
    uint32_t addr = 0;
    uint16_t port = 0;
    uint64_t cookie = 0;
    uint64_t last_us = 0;
};

bool fresh(const Slot& s, uint64_t now) { return s.used && now - s.last_us < kSlotUs; }

bool same_room(const Slot& a, const char* room) { return std::strcmp(a.room, room) == 0; }

bool gcx1(const uint8_t* p, size_t n) { return p && n >= 4 && load_be32(p) == kMagic; }

bool send_msg(UdpSocket& sock, const NatMsg& msg, uint32_t addr, uint16_t port) {
    uint8_t buf[1600];
    size_t n = nat_encode(buf, sizeof(buf), msg);
    if (!n) return false;
    return sock.send_to(buf, n, addr, port);
}

}  // namespace

struct NatHub {
    Slot slots[32];
};

NatHub* nat_hub_create() { return new NatHub(); }
void nat_hub_destroy(NatHub* hub) { delete hub; }

void nat_hub_packet(NatHub* hub, UdpSocket& sock, const uint8_t* data, size_t n, uint32_t addr, uint16_t port) {
    if (!hub) return;
    NatMsg msg;
    if (!nat_decode(data, n, msg)) return;
    uint64_t now = monotonic_us();
    if (msg.type == kNatRegister) {
        if (!nat_name_ok(msg.room) || !nat_name_ok(msg.name)) return;
        Slot* slot = nullptr;
        for (auto& s : hub->slots) {
            if (s.used && same_room(s, msg.room) && std::strcmp(s.name, msg.name) == 0) slot = &s;
        }
        if (!slot) {
            for (auto& s : hub->slots)
                if (!s.used || !fresh(s, now)) {
                    slot = &s;
                    break;
                }
        }
        if (!slot) return;
        *slot = Slot{};
        slot->used = true;
        std::memcpy(slot->room, msg.room, sizeof(slot->room));
        std::memcpy(slot->name, msg.name, sizeof(slot->name));
        slot->addr = addr;
        slot->port = port;
        random_bytes(reinterpret_cast<uint8_t*>(&slot->cookie), sizeof(slot->cookie));
        if (slot->cookie == 0) slot->cookie = 1;
        slot->last_us = now;
        NatMsg reply;
        reply.type = kNatRegistered;
        std::memcpy(reply.room, slot->room, sizeof(reply.room));
        std::memcpy(reply.name, slot->name, sizeof(reply.name));
        reply.addr = addr;
        reply.port = port;
        reply.cookie = slot->cookie;
        send_msg(sock, reply, addr, port);
        return;
    }
    Slot* sender = nullptr;
    for (auto& s : hub->slots)
        if (fresh(s, now) && s.addr == addr && s.port == port) sender = &s;
    if (msg.type == kNatLookup) {
        if (!sender || !nat_name_ok(msg.peer)) return;
        sender->last_us = now;
        NatMsg reply;
        reply.type = kNatPeer;
        std::memcpy(reply.room, sender->room, sizeof(reply.room));
        std::memcpy(reply.name, sender->name, sizeof(reply.name));
        std::memcpy(reply.peer, msg.peer, sizeof(reply.peer));
        for (auto& s : hub->slots) {
            if (fresh(s, now) && same_room(s, sender->room) && std::strcmp(s.name, msg.peer) == 0) {
                reply.ok = 1;
                reply.addr = s.addr;
                reply.port = s.port;
                reply.cookie = s.cookie;
                break;
            }
        }
        send_msg(sock, reply, addr, port);
        return;
    }
    if (msg.type == kNatRelay) {
        if (!sender || msg.data.empty() || msg.data.size() > kNatInnerMax) return;
        if (!nat_is(msg.data.data(), msg.data.size()) && !gcx1(msg.data.data(), msg.data.size())) return;
        sender->last_us = now;
        Slot* dest = nullptr;
        for (auto& s : hub->slots)
            if (fresh(s, now) && s.cookie == msg.cookie && same_room(s, sender->room)) dest = &s;
        if (!dest || dest == sender) return;
        NatMsg fwd;
        fwd.type = kNatRelay;
        std::memcpy(fwd.room, sender->room, sizeof(fwd.room));
        std::memcpy(fwd.name, sender->name, sizeof(fwd.name));
        fwd.cookie = sender->cookie;
        fwd.data = msg.data;
        send_msg(sock, fwd, dest->addr, dest->port);
    }
}

}  // namespace genesis

struct GenesisTunSlot {
    bool live = false;
    uint32_t seq = 0;
    uint64_t sent = 0;
    std::vector<uint8_t> data;
};

struct genesis_path {
    genesis::UdpSocket sock;
    genesis::UdpSocket local;
    std::thread rx;
    std::thread proxy;
    std::atomic<int> stop{0};
    std::mutex mu;
    std::condition_variable cv;
    bool got_reg = false;
    bool got_peer = false;
    bool got_punch = false;
    uint32_t probe_got = 0;
    std::deque<std::vector<uint8_t>> appq;
    std::vector<uint32_t> bench_acks;
    int tun_fd = -1;
    char tun_name[IFNAMSIZ]{};
    GenesisTunSlot tunq[16];
    uint32_t tun_next = 1;
    uint32_t tun_hi = 0;
    uint64_t tun_seen = 0;
    uint32_t via_addr = 0;
    uint16_t via_port = 0;
    char room[32]{};
    char name[32]{};
    char peer_name[32]{};
    uint64_t peer_cookie = 0;
    uint32_t reflex_addr = 0;
    uint16_t reflex_port = 0;
    uint32_t peer_addr = 0;
    uint16_t peer_port = 0;
    uint32_t stun_addr = 0;
    uint16_t stun_port = 0;
    int mode = 0;
    int relay_only = 0;
    int punches_sent = 0;
    int punches_got = 0;
    uint64_t rtt_min = 0;
    uint64_t rtt_avg = 0;
    uint64_t rtt_max = 0;
    uint64_t jitter = 0;
    int udp_mtu = 0;
    uint64_t bench_bytes = 0;
    uint64_t goodput_bps = 0;
    uint64_t bench_us = 0;
    uint64_t last_reg = 0;
    uint32_t target_addr = 0;
    uint16_t target_port = 0;
    uint32_t app_addr = 0;
    uint16_t app_port = 0;
    uint16_t listen_port = 0;
    char error[160]{};
};

struct genesis_nat {
    genesis::UdpSocket sock;
    genesis::NatHub* hub = nullptr;
    std::thread thr;
    std::atomic<int> stop{0};
    uint16_t port = 0;
};

namespace genesis {
namespace {

bool wait_flag(genesis_path* p, bool genesis_path::*flag, int ms) {
    std::unique_lock<std::mutex> lock(p->mu);
    return p->cv.wait_for(lock, std::chrono::milliseconds(ms > 0 ? ms : 1), [&] { return p->*flag; });
}

bool wait_probe(genesis_path* p, uint32_t id, int ms) {
    std::unique_lock<std::mutex> lock(p->mu);
    return p->cv.wait_for(lock, std::chrono::milliseconds(ms > 0 ? ms : 1), [&] { return p->probe_got == id; });
}

bool wait_bench(genesis_path* p, uint32_t id, int ms) {
    std::unique_lock<std::mutex> lock(p->mu);
    auto ready = [&] {
        for (uint32_t x : p->bench_acks)
            if (x == id) return true;
        return false;
    };
    if (!p->cv.wait_for(lock, std::chrono::milliseconds(ms > 0 ? ms : 1), ready)) return false;
    for (auto it = p->bench_acks.begin(); it != p->bench_acks.end(); ++it) {
        if (*it == id) {
            p->bench_acks.erase(it);
            break;
        }
    }
    return true;
}

void send_raw(genesis_path* p, const uint8_t* data, size_t n, uint32_t addr, uint16_t port) {
    if (addr && port) p->sock.send_to(data, n, addr, port);
}

void send_wrapped(genesis_path* p, const uint8_t* data, size_t n) {
    int mode;
    uint64_t cookie;
    uint32_t peer;
    uint16_t peer_port;
    uint32_t via;
    uint16_t via_port;
    {
        std::lock_guard<std::mutex> lock(p->mu);
        mode = p->mode;
        cookie = p->peer_cookie;
        peer = p->peer_addr;
        peer_port = p->peer_port;
        via = p->via_addr;
        via_port = p->via_port;
    }
    if (mode == 1 && peer && peer_port) {
        send_raw(p, data, n, peer, peer_port);
        return;
    }
    if (!cookie) return;
    NatMsg rel;
    rel.type = kNatRelay;
    std::memcpy(rel.room, p->room, sizeof(rel.room));
    std::memcpy(rel.name, p->name, sizeof(rel.name));
    rel.cookie = cookie;
    rel.data.assign(data, data + n);
    send_msg(p->sock, rel, via, via_port);
}

void send_kind(genesis_path* p, NatMsg msg) {
    std::memcpy(msg.room, p->room, sizeof(msg.room));
    std::memcpy(msg.name, p->name, sizeof(msg.name));
    uint8_t buf[1600];
    size_t n = nat_encode(buf, sizeof(buf), msg);
    if (n) send_wrapped(p, buf, n);
}

void remember_peer_cookie(genesis_path* p, uint64_t cookie) {
    if (!cookie) return;
    std::lock_guard<std::mutex> lock(p->mu);
    if (!p->peer_cookie) p->peer_cookie = cookie;
    if (p->mode == 0) p->mode = 2;
}

void on_tun(genesis_path* p, uint32_t seq, const std::vector<uint8_t>& data) {
    bool deliver = false;
    {
        std::lock_guard<std::mutex> lock(p->mu);
        if (p->tun_hi == 0 || seq > p->tun_hi) {
            uint32_t shift = p->tun_hi == 0 ? 64 : seq - p->tun_hi;
            if (shift >= 64) p->tun_seen = 0;
            else p->tun_seen <<= shift;
            p->tun_hi = seq;
            p->tun_seen |= 1ull;
            deliver = true;
        } else if (p->tun_hi - seq < 64) {
            uint64_t bit = 1ull << (p->tun_hi - seq);
            if ((p->tun_seen & bit) == 0) {
                p->tun_seen |= bit;
                deliver = true;
            }
        }
    }
    if (deliver && p->tun_fd >= 0 && !data.empty()) {
        ssize_t w = ::write(p->tun_fd, data.data(), data.size());
        (void)w;
    }
    NatMsg ack;
    ack.type = kNatTunAck;
    {
        std::lock_guard<std::mutex> lock(p->mu);
        ack.ack = p->tun_hi;
        ack.bitmap = p->tun_seen;
    }
    send_kind(p, ack);
}

void on_tun_ack(genesis_path* p, uint32_t ack, uint64_t bitmap) {
    std::lock_guard<std::mutex> lock(p->mu);
    for (auto& slot : p->tunq) {
        if (!slot.live) continue;
        bool free = false;
        if (slot.seq == ack) free = true;
        else if (ack > slot.seq && ack - slot.seq < 64 && (bitmap & (1ull << (ack - slot.seq)))) free = true;
        else if (ack > slot.seq && ack - slot.seq >= 64) free = true;
        if (free) slot.live = false;
    }
}

void handle_nat(genesis_path* p, const NatMsg& msg, uint32_t from, uint16_t from_port);

void handle_bytes(genesis_path* p, const uint8_t* data, size_t n, uint32_t from, uint16_t from_port) {
    if (nat_is(data, n)) {
        NatMsg msg;
        if (!nat_decode(data, n, msg)) return;
        handle_nat(p, msg, from, from_port);
        return;
    }
    if (!gcx1(data, n)) return;
    std::lock_guard<std::mutex> lock(p->mu);
    if (p->appq.size() < 256) p->appq.emplace_back(data, data + n);
    p->cv.notify_all();
}

void handle_nat(genesis_path* p, const NatMsg& msg, uint32_t from, uint16_t from_port) {
    if (msg.type == kNatRegistered) {
        std::lock_guard<std::mutex> lock(p->mu);
        p->reflex_addr = msg.addr;
        p->reflex_port = msg.port;
        p->got_reg = true;
        p->cv.notify_all();
        return;
    }
    if (msg.type == kNatPeer) {
        std::lock_guard<std::mutex> lock(p->mu);
        if (msg.ok) {
            p->peer_addr = msg.addr;
            p->peer_port = msg.port;
            p->peer_cookie = msg.cookie;
            p->got_peer = true;
        }
        p->cv.notify_all();
        return;
    }
    if (msg.type == kNatPunch && !p->relay_only) {
        {
            std::lock_guard<std::mutex> lock(p->mu);
            p->peer_addr = from;
            p->peer_port = from_port;
            p->mode = 1;
            p->punches_got++;
        }
        NatMsg ack;
        ack.type = kNatPunchAck;
        std::memcpy(ack.room, p->room, sizeof(ack.room));
        std::memcpy(ack.name, p->name, sizeof(ack.name));
        ack.cookie = msg.cookie;
        send_msg(p->sock, ack, from, from_port);
        return;
    }
    if (msg.type == kNatPunchAck) {
        std::lock_guard<std::mutex> lock(p->mu);
        p->mode = 1;
        p->peer_addr = from;
        p->peer_port = from_port;
        p->punches_got++;
        p->got_punch = true;
        p->cv.notify_all();
        return;
    }
    if (msg.type == kNatRelay) {
        remember_peer_cookie(p, msg.cookie);
        if (!msg.data.empty()) handle_bytes(p, msg.data.data(), msg.data.size(), from, from_port);
        return;
    }
    if (msg.type == kNatProbe) {
        NatMsg ack;
        ack.type = kNatProbeAck;
        ack.id = msg.id;
        ack.data.resize(msg.data.size());
        send_kind(p, ack);
        return;
    }
    if (msg.type == kNatProbeAck) {
        std::lock_guard<std::mutex> lock(p->mu);
        p->probe_got = msg.id;
        p->cv.notify_all();
        return;
    }
    if (msg.type == kNatBench) {
        NatMsg ack;
        ack.type = kNatBenchAck;
        ack.id = msg.id;
        send_kind(p, ack);
        return;
    }
    if (msg.type == kNatBenchAck) {
        std::lock_guard<std::mutex> lock(p->mu);
        p->bench_acks.push_back(msg.id);
        p->cv.notify_all();
        return;
    }
    if (msg.type == kNatTun) {
        on_tun(p, msg.id, msg.data);
        return;
    }
    if (msg.type == kNatTunAck) on_tun_ack(p, msg.ack, msg.bitmap);
}

void tun_retx(genesis_path* p, uint64_t now) {
    std::vector<std::pair<uint32_t, std::vector<uint8_t>>> due;
    {
        std::lock_guard<std::mutex> lock(p->mu);
        for (auto& slot : p->tunq) {
            if (!slot.live || now - slot.sent < 30000) continue;
            slot.sent = now;
            due.push_back({slot.seq, slot.data});
        }
    }
    for (const auto& item : due) {
        NatMsg msg;
        msg.type = kNatTun;
        msg.id = item.first;
        msg.data = item.second;
        send_kind(p, msg);
    }
}

void tun_read(genesis_path* p) {
    uint8_t buf[2048];
    ssize_t n = ::read(p->tun_fd, buf, sizeof(buf));
    if (n <= 0) return;
    uint32_t seq = 0;
    {
        std::lock_guard<std::mutex> lock(p->mu);
        GenesisTunSlot* slot = nullptr;
        for (auto& s : p->tunq)
            if (!s.live) slot = &s;
        if (!slot) return;
        seq = p->tun_next++;
        if (p->tun_next == 0) p->tun_next = 1;
        slot->live = true;
        slot->seq = seq;
        slot->sent = monotonic_us();
        slot->data.assign(buf, buf + n);
    }
    NatMsg msg;
    msg.type = kNatTun;
    msg.id = seq;
    msg.data.assign(buf, buf + n);
    send_kind(p, msg);
}

void rx_loop(genesis_path* p) {
    while (!p->stop.load()) {
        pollfd pf[2];
        pf[0].fd = p->sock.fd();
        pf[0].events = POLLIN;
        pf[0].revents = 0;
        int nfd = 1;
        int tun_slot = -1;
        bool tun_full = false;
        {
            std::lock_guard<std::mutex> lock(p->mu);
            int live = 0;
            for (const auto& s : p->tunq)
                if (s.live) ++live;
            tun_full = live >= 16;
        }
        if (p->tun_fd >= 0 && !tun_full) {
            tun_slot = nfd;
            pf[nfd].fd = p->tun_fd;
            pf[nfd].events = POLLIN;
            pf[nfd].revents = 0;
            ++nfd;
        }
        int pr = ::poll(pf, static_cast<nfds_t>(nfd), 20);
        uint64_t now = monotonic_us();
        if (pr > 0 && (pf[0].revents & POLLIN)) {
            uint8_t buf[2048];
            uint32_t addr = 0;
            uint16_t port = 0;
            int n = p->sock.recv_from(buf, sizeof(buf), &addr, &port, 0);
            if (n > 0) handle_bytes(p, buf, static_cast<size_t>(n), addr, port);
        }
        if (tun_slot >= 0 && pr > 0 && (pf[tun_slot].revents & POLLIN)) tun_read(p);
        tun_retx(p, now);
        if (now - p->last_reg > 2000000ull) {
            NatMsg reg;
            reg.type = kNatRegister;
            std::memcpy(reg.room, p->room, sizeof(reg.room));
            std::memcpy(reg.name, p->name, sizeof(reg.name));
            send_msg(p->sock, reg, p->via_addr, p->via_port);
            p->last_reg = now;
        }
    }
}

void proxy_loop(genesis_path* p) {
    while (!p->stop.load()) {
        std::deque<std::vector<uint8_t>> got;
        {
            std::unique_lock<std::mutex> lock(p->mu);
            p->cv.wait_for(lock, std::chrono::milliseconds(20), [&] { return p->stop.load() || !p->appq.empty(); });
            got.swap(p->appq);
        }
        for (const auto& pkt : got) {
            if (p->target_port) p->local.send_to(pkt.data(), pkt.size(), p->target_addr, p->target_port);
            else if (p->app_port) p->local.send_to(pkt.data(), pkt.size(), p->app_addr, p->app_port);
        }
        uint8_t buf[2048];
        uint32_t addr = 0;
        uint16_t port = 0;
        int n = p->local.fd() >= 0 ? p->local.recv_from(buf, sizeof(buf), &addr, &port, 0) : 0;
        if (n > 0) {
            if (!p->target_port) {
                p->app_addr = addr;
                p->app_port = port;
            }
            send_wrapped(p, buf, static_cast<size_t>(n));
        }
    }
}

bool register_self(genesis_path* p, int timeout_ms) {
    uint64_t deadline = monotonic_us() + static_cast<uint64_t>(timeout_ms) * 1000ull;
    while (monotonic_us() < deadline && !p->stop.load()) {
        NatMsg reg;
        reg.type = kNatRegister;
        std::memcpy(reg.room, p->room, sizeof(reg.room));
        std::memcpy(reg.name, p->name, sizeof(reg.name));
        send_msg(p->sock, reg, p->via_addr, p->via_port);
        p->last_reg = monotonic_us();
        if (wait_flag(p, &genesis_path::got_reg, 200)) return true;
    }
    std::snprintf(p->error, sizeof(p->error), "introducer did not answer");
    return false;
}

bool lookup_peer(genesis_path* p, int timeout_ms) {
    uint64_t deadline = monotonic_us() + static_cast<uint64_t>(timeout_ms) * 1000ull;
    while (monotonic_us() < deadline && !p->stop.load()) {
        NatMsg q;
        q.type = kNatLookup;
        std::memcpy(q.room, p->room, sizeof(q.room));
        std::memcpy(q.name, p->name, sizeof(q.name));
        std::memcpy(q.peer, p->peer_name, sizeof(q.peer));
        send_msg(p->sock, q, p->via_addr, p->via_port);
        if (wait_flag(p, &genesis_path::got_peer, 200)) return true;
    }
    std::snprintf(p->error, sizeof(p->error), "peer %s is not registered", p->peer_name);
    return false;
}

void punch_for(genesis_path* p, int punch_ms) {
    if (p->relay_only || punch_ms <= 0) {
        std::lock_guard<std::mutex> lock(p->mu);
        if (p->mode != 1) p->mode = 2;
        return;
    }
    uint64_t deadline = monotonic_us() + static_cast<uint64_t>(punch_ms) * 1000ull;
    while (monotonic_us() < deadline && !p->stop.load()) {
        {
            std::lock_guard<std::mutex> lock(p->mu);
            if (p->mode == 1) return;
        }
        NatMsg punch;
        punch.type = kNatPunch;
        std::memcpy(punch.room, p->room, sizeof(punch.room));
        std::memcpy(punch.name, p->name, sizeof(punch.name));
        punch.cookie = 1;
        uint32_t addr;
        uint16_t port;
        {
            std::lock_guard<std::mutex> lock(p->mu);
            addr = p->peer_addr;
            port = p->peer_port;
            p->punches_sent++;
        }
        send_msg(p->sock, punch, addr, port);
        if (wait_flag(p, &genesis_path::got_punch, 30)) return;
    }
    std::lock_guard<std::mutex> lock(p->mu);
    if (p->mode != 1) p->mode = 2;
}

bool probe_once(genesis_path* p, uint32_t id, size_t payload, int wait_ms, uint64_t* rtt) {
    NatMsg msg;
    msg.type = kNatProbe;
    msg.id = id;
    msg.data.assign(payload, 0x5a);
    std::memcpy(msg.room, p->room, sizeof(msg.room));
    std::memcpy(msg.name, p->name, sizeof(msg.name));
    uint8_t buf[1600];
    size_t n = nat_encode(buf, sizeof(buf), msg);
    if (!n || n > 1500) return false;
    {
        std::lock_guard<std::mutex> lock(p->mu);
        if (p->probe_got == id) p->probe_got = 0;
    }
    uint64_t t0 = monotonic_us();
    send_wrapped(p, buf, n);
    if (!wait_probe(p, id, wait_ms)) return false;
    if (rtt) *rtt = monotonic_us() - t0;
    return true;
}

}  // namespace

}  // namespace genesis

extern "C" genesis_nat* genesis_nat_serve(const genesis_config* cfg) {
    if (!cfg) return nullptr;
    auto* s = new genesis_nat();
    s->hub = genesis::nat_hub_create();
    const char* host = cfg->bind_host[0] ? cfg->bind_host : "0.0.0.0";
    if (!s->sock.open(host, cfg->bind_port, cfg->socket_buffer > 0 ? cfg->socket_buffer : 1 << 20, false)) {
        genesis::nat_hub_destroy(s->hub);
        delete s;
        return nullptr;
    }
    s->port = s->sock.local_port();
    s->thr = std::thread([s] {
        while (!s->stop.load()) {
            uint8_t buf[2048];
            uint32_t addr = 0;
            uint16_t port = 0;
            int n = s->sock.recv_from(buf, sizeof(buf), &addr, &port, 50);
            if (n > 0) genesis::nat_hub_packet(s->hub, s->sock, buf, static_cast<size_t>(n), addr, port);
        }
    });
    return s;
}

extern "C" uint16_t genesis_nat_port(const genesis_nat* nat) { return nat ? nat->port : 0; }

extern "C" void genesis_nat_stop(genesis_nat* nat) {
    if (!nat) return;
    nat->stop.store(1);
    if (nat->thr.joinable()) nat->thr.join();
    genesis::nat_hub_destroy(nat->hub);
    delete nat;
}

extern "C" genesis_path* genesis_path_open(const genesis_config* cfg, const char* via_host, uint16_t via_port,
                                           const char* room, const char* name, const char* peer, int timeout_ms,
                                           int punch_ms, int flags) {
    if (!cfg || !via_host || !via_host[0] || !via_port || !genesis::nat_name_ok(room) || !genesis::nat_name_ok(name))
        return nullptr;
    if (peer && peer[0] && !genesis::nat_name_ok(peer)) return nullptr;
    if (timeout_ms <= 0) timeout_ms = 4000;
    auto* p = new genesis_path();
    std::snprintf(p->room, sizeof(p->room), "%s", room);
    std::snprintf(p->name, sizeof(p->name), "%s", name);
    if (peer) std::snprintf(p->peer_name, sizeof(p->peer_name), "%s", peer);
    p->relay_only = (flags & 1) ? 1 : 0;
    if (!genesis::ipv4_resolve(via_host, &p->via_addr)) {
        delete p;
        return nullptr;
    }
    p->via_port = via_port;
    const char* bind = cfg->bind_host[0] ? cfg->bind_host : "0.0.0.0";
    if (!p->sock.open(bind, 0, cfg->socket_buffer > 0 ? cfg->socket_buffer : 1 << 20, false)) {
        delete p;
        return nullptr;
    }
    if (cfg->stun_host[0]) genesis::stun_query(p->sock, cfg->stun_host, cfg->stun_port, &p->stun_addr, &p->stun_port);
    p->rx = std::thread(genesis::rx_loop, p);
    if (!genesis::register_self(p, timeout_ms)) {
        p->stop.store(1);
        if (p->rx.joinable()) p->rx.join();
        delete p;
        return nullptr;
    }
    bool accept = (flags & 2) != 0 || !p->peer_name[0];
    if (!accept) {
        if (!genesis::lookup_peer(p, timeout_ms)) {
            p->stop.store(1);
            if (p->rx.joinable()) p->rx.join();
            delete p;
            return nullptr;
        }
        genesis::punch_for(p, punch_ms);
    } else {
        std::lock_guard<std::mutex> lock(p->mu);
        p->mode = 2;
    }
    return p;
}

extern "C" int genesis_path_measure(genesis_path* path, genesis_path_report* report) {
    if (!path || !report) return GENESIS_ERR_ARGS;
    std::memset(report, 0, sizeof(*report));
    uint64_t samples[8];
    int got = 0;
    uint64_t sum = 0;
    for (int i = 0; i < 8; ++i) {
        uint64_t rtt = 0;
        if (!genesis::probe_once(path, static_cast<uint32_t>(i + 1), 32, 250, &rtt)) continue;
        samples[got++] = rtt;
        sum += rtt;
    }
    if (!got) {
        std::snprintf(path->error, sizeof(path->error), "no probe reply");
        std::snprintf(report->error, sizeof(report->error), "%s", path->error);
        return GENESIS_ERR_TIMEOUT;
    }
    uint64_t mn = samples[0], mx = samples[0];
    for (int i = 0; i < got; ++i) {
        if (samples[i] < mn) mn = samples[i];
        if (samples[i] > mx) mx = samples[i];
    }
    uint64_t avg = sum / static_cast<uint64_t>(got);
    uint64_t jit = 0;
    for (int i = 1; i < got; ++i) {
        uint64_t d = samples[i] > samples[i - 1] ? samples[i] - samples[i - 1] : samples[i - 1] - samples[i];
        jit += d;
    }
    if (got > 1) jit /= static_cast<uint64_t>(got - 1);
    int lo = 200, hi = 1400, best = 0;
    uint32_t id = 100;
    while (lo <= hi) {
        int mid = (lo + hi) / 2;
        bool ok = genesis::probe_once(path, id++, static_cast<size_t>(mid), 80, nullptr) ||
                  genesis::probe_once(path, id++, static_cast<size_t>(mid), 80, nullptr);
        if (ok) {
            best = mid;
            lo = mid + 1;
        } else {
            hi = mid - 1;
        }
    }
    std::lock_guard<std::mutex> lock(path->mu);
    path->rtt_min = mn;
    path->rtt_avg = avg;
    path->rtt_max = mx;
    path->jitter = jit;
    path->udp_mtu = best;
    report->mode = path->mode;
    report->self_addr = path->reflex_addr;
    report->self_port = path->reflex_port;
    report->peer_addr = path->peer_addr;
    report->peer_port = path->peer_port;
    report->stun_addr = path->stun_addr;
    report->stun_port = path->stun_port;
    report->rtt_min_us = mn;
    report->rtt_avg_us = avg;
    report->rtt_max_us = mx;
    report->jitter_us = jit;
    report->udp_payload = best;
    report->path_mtu = best > 0 ? best + 28 : 0;
    report->punches_sent = path->punches_sent;
    report->punches_got = path->punches_got;
    return GENESIS_OK;
}

extern "C" int genesis_path_bench(genesis_path* path, uint64_t nbytes, genesis_path_report* report) {
    if (!path || !report || nbytes == 0) return GENESIS_ERR_ARGS;
    if (genesis_path_measure(path, report) != GENESIS_OK) return GENESIS_ERR_TIMEOUT;
    const size_t chunk = 1000;
    uint32_t next = 1;
    uint32_t acked_n = 0;
    uint32_t limit = static_cast<uint32_t>((nbytes + chunk - 1) / chunk);
    std::vector<int> acked(limit + 1, 0);
    uint64_t t0 = genesis::monotonic_us();
    auto send_one = [&](uint32_t id) {
        size_t n = chunk;
        if (static_cast<uint64_t>(id) * chunk > nbytes) n = static_cast<size_t>(nbytes - static_cast<uint64_t>(id - 1) * chunk);
        genesis::NatMsg msg;
        msg.type = genesis::kNatBench;
        msg.id = id;
        msg.total = static_cast<uint32_t>(nbytes);
        msg.data.assign(n, static_cast<uint8_t>(id));
        std::memcpy(msg.room, path->room, sizeof(msg.room));
        std::memcpy(msg.name, path->name, sizeof(msg.name));
        uint8_t buf[1600];
        size_t len = genesis::nat_encode(buf, sizeof(buf), msg);
        if (len) genesis::send_wrapped(path, buf, len);
    };
    while (acked_n < limit && genesis::monotonic_us() - t0 < 30000000ull) {
        while (next <= limit && next - acked_n <= 64) send_one(next++);
        uint32_t wait_id = acked_n + 1;
        if (!genesis::wait_bench(path, wait_id, 400)) send_one(wait_id);
        else {
            acked[wait_id] = 1;
            while (acked_n < limit && acked[acked_n + 1]) ++acked_n;
        }
    }
    uint64_t us = genesis::monotonic_us() - t0;
    if (!us) us = 1;
    uint64_t bytes = static_cast<uint64_t>(acked_n) * chunk;
    if (bytes > nbytes) bytes = nbytes;
    std::lock_guard<std::mutex> lock(path->mu);
    path->bench_bytes = bytes;
    path->bench_us = us;
    path->goodput_bps = bytes * 1000000ull / us;
    report->bench_bytes = bytes;
    report->elapsed_us = us;
    report->goodput_bps = path->goodput_bps;
    report->mode = path->mode;
    return acked_n == limit ? GENESIS_OK : GENESIS_ERR_TIMEOUT;
}

extern "C" int genesis_path_proxy(genesis_path* path, const char* listen_host, uint16_t listen_port, const char* target_host,
                                  uint16_t target_port) {
    if (!path) return GENESIS_ERR_ARGS;
    if (path->proxy.joinable()) return GENESIS_ERR_ARGS;
    if (target_host && target_host[0] && target_port) {
        if (!genesis::ipv4_resolve(target_host, &path->target_addr)) return GENESIS_ERR_NET;
        path->target_port = target_port;
    }
    const char* host = listen_host && listen_host[0] ? listen_host : "127.0.0.1";
    if (!path->local.open(host, listen_port, 1 << 20, false)) return GENESIS_ERR_NET;
    path->listen_port = path->local.local_port();
    path->proxy = std::thread(genesis::proxy_loop, path);
    return GENESIS_OK;
}

extern "C" uint16_t genesis_path_listen_port(const genesis_path* path) { return path ? path->listen_port : 0; }

extern "C" void genesis_path_status(const genesis_path* path, genesis_path_report* report) {
    if (!path || !report) return;
    std::lock_guard<std::mutex> lock(const_cast<genesis_path*>(path)->mu);
    std::memset(report, 0, sizeof(*report));
    report->mode = path->mode;
    report->self_addr = path->reflex_addr;
    report->self_port = path->reflex_port;
    report->peer_addr = path->peer_addr;
    report->peer_port = path->peer_port;
    report->stun_addr = path->stun_addr;
    report->stun_port = path->stun_port;
    report->rtt_min_us = path->rtt_min;
    report->rtt_avg_us = path->rtt_avg;
    report->rtt_max_us = path->rtt_max;
    report->jitter_us = path->jitter;
    report->udp_payload = path->udp_mtu;
    report->path_mtu = path->udp_mtu > 0 ? path->udp_mtu + 28 : 0;
    report->bench_bytes = path->bench_bytes;
    report->goodput_bps = path->goodput_bps;
    report->elapsed_us = path->bench_us;
    report->punches_sent = path->punches_sent;
    report->punches_got = path->punches_got;
    std::snprintf(report->error, sizeof(report->error), "%s", path->error);
}

extern "C" int genesis_path_tun(genesis_path* path, const char* dev, int tap, const char* cidr, int mtu) {
    if (!path || path->tun_fd >= 0) return GENESIS_ERR_ARGS;
    int fd = ::open("/dev/net/tun", O_RDWR | O_CLOEXEC);
    if (fd < 0) return GENESIS_ERR_IO;
    ifreq ifr{};
    ifr.ifr_flags = static_cast<short>((tap ? IFF_TAP : IFF_TUN) | IFF_NO_PI);
    if (dev && dev[0]) std::snprintf(ifr.ifr_name, IFNAMSIZ, "%s", dev);
    if (::ioctl(fd, TUNSETIFF, &ifr) != 0) {
        ::close(fd);
        return GENESIS_ERR_IO;
    }
    std::snprintf(path->tun_name, sizeof(path->tun_name), "%s", ifr.ifr_name);
    int ctl = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (ctl >= 0 && cidr && cidr[0]) {
        char addr[64];
        std::snprintf(addr, sizeof(addr), "%s", cidr);
        int prefix = 24;
        char* slash = std::strchr(addr, '/');
        if (slash) {
            *slash = '\0';
            prefix = std::atoi(slash + 1);
        }
        ifreq a{};
        std::snprintf(a.ifr_name, IFNAMSIZ, "%s", path->tun_name);
        auto* in = reinterpret_cast<sockaddr_in*>(&a.ifr_addr);
        in->sin_family = AF_INET;
        if (::inet_pton(AF_INET, addr, &in->sin_addr) == 1) {
            ::ioctl(ctl, SIOCSIFADDR, &a);
            uint32_t mask = prefix <= 0 ? 0 : prefix >= 32 ? 0xffffffffu : 0xffffffffu << (32 - prefix);
            in->sin_addr.s_addr = htonl(mask);
            ::ioctl(ctl, SIOCSIFNETMASK, &a);
        }
        if (mtu <= 0) mtu = path->udp_mtu > 64 ? path->udp_mtu - 48 : 1200;
        a.ifr_mtu = mtu;
        ::ioctl(ctl, SIOCSIFMTU, &a);
        a.ifr_flags = IFF_UP | IFF_RUNNING;
        ::ioctl(ctl, SIOCSIFFLAGS, &a);
        ::close(ctl);
    } else if (ctl >= 0) {
        ::close(ctl);
    }
    int flags = ::fcntl(fd, F_GETFL, 0);
    if (flags >= 0) ::fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    path->tun_fd = fd;
    return GENESIS_OK;
}

extern "C" void genesis_path_close(genesis_path* path) {
    if (!path) return;
    path->stop.store(1);
    path->cv.notify_all();
    if (path->proxy.joinable()) path->proxy.join();
    if (path->rx.joinable()) path->rx.join();
    if (path->tun_fd >= 0) ::close(path->tun_fd);
    delete path;
}
