#include "session.hpp"

#include "discovery.hpp"
#include "engine.hpp"
#include "log.hpp"
#include "udp.hpp"
#include "util.hpp"
#include "nat.hpp"
#include "nat_hub.hpp"
#include "vfs_hub.hpp"
#include "wire.hpp"

#include <atomic>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <poll.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

namespace genesis {
void flush_socket(Engine& eng, UdpSocket& sock);
namespace {

struct FileIO {
    FILE* f = nullptr;
    bool writing = false;
    bool nospace = false;
    const char* path = nullptr;
    char path_keep[512]{};
    char name_keep[256]{};
    uint64_t file_size = 0;
    uint64_t durable = 0;
    uint64_t since_flush = 0;
};

bool reserve_file(FILE* f, uint64_t from, uint64_t size) {
    if (!f || f == stdout || size == 0 || size < from) return true;
    int fd = fileno(f);
    if (fd < 0) return true;
    if (from > 0 && ftruncate(fd, static_cast<off_t>(from)) != 0) return false;
    if (ftruncate(fd, static_cast<off_t>(size)) != 0) return false;
    /* posix_fallocate reserves blocks so a full disk fails now, and on ext4/xfs
     * it is an unwritten extent rather than a zero fill. Past 1 GiB the call
     * can stall on filesystems that materialize zeros, so the size is left sparse. */
    uint64_t span = size - from;
    if (span == 0 || span > (1ull << 30)) return true;
    int rc = posix_fallocate(fd, static_cast<off_t>(from), static_cast<off_t>(span));
    if (rc == 0 || rc == EOPNOTSUPP || rc == EINVAL || rc == ENOSYS) return true;
    errno = rc;
    return false;
}

#ifndef SEEK_HOLE
#define SEEK_HOLE 4
#endif

void write_sidecar(const char* path, const char* name, uint64_t size, uint64_t durable) {
    char side[540];
    if (std::snprintf(side, sizeof(side), "%s.genesis", path) >= static_cast<int>(sizeof(side))) return;
    FILE* s = std::fopen(side, "w");
    if (!s) return;
    std::fprintf(s, "%s\n%llu\n%llu\n", name ? name : "", static_cast<unsigned long long>(size),
                 static_cast<unsigned long long>(durable));
    std::fclose(s);
}

bool sidecar_match(const char* path, const char* name, uint64_t size, uint64_t* durable) {
    if (durable) *durable = ~uint64_t{0};
    char side[540];
    if (std::snprintf(side, sizeof(side), "%s.genesis", path) >= static_cast<int>(sizeof(side))) return false;
    FILE* s = std::fopen(side, "r");
    if (!s) return false;
    char line[256];
    unsigned long long sz = 0;
    unsigned long long dur = 0;
    bool ok = std::fgets(line, sizeof(line), s) != nullptr && std::fscanf(s, "%llu", &sz) == 1;
    bool have_dur = ok && std::fscanf(s, "%llu", &dur) == 1;
    std::fclose(s);
    if (!ok) return false;
    size_t n = std::strlen(line);
    if (n && line[n - 1] == '\n') line[n - 1] = '\0';
    if (std::strcmp(line, name ? name : "") != 0 || sz != size) return false;
    if (have_dur && durable) *durable = dur;
    return true;
}

uint64_t open_resume(FileIO* io, const char* path, const char* name, uint64_t file_size, int align, ResumeAbsorb absorb,
                     void* arg) {
    if (!io) return 0;
    if (!path || std::strcmp(path, "-") == 0) {
        io->f = stdout;
        return 0;
    }
    uint64_t off = 0;
    struct stat st;
    uint64_t saved = ~uint64_t{0};
    if (align > 0 && file_size && sidecar_match(path, name, file_size, &saved) && ::stat(path, &st) == 0 &&
        S_ISREG(st.st_mode) && st.st_size > 0) {
        /* ftruncate sets st_size to the whole file before the bytes exist.
         * The sidecar's durable count is the prefix that was flushed. An older
         * sidecar has no count; the first hole is the same boundary. */
        if (saved != ~uint64_t{0} && saved <= file_size) off = saved;
        else {
            off = static_cast<uint64_t>(st.st_size);
            if (off > file_size) off = file_size;
            int fd = ::open(path, O_RDONLY);
            if (fd >= 0) {
                off_t hole = ::lseek(fd, 0, SEEK_HOLE);
                if (hole > 0 && static_cast<uint64_t>(hole) < off) off = static_cast<uint64_t>(hole);
                ::close(fd);
            }
            /* The last allocated block can contain a short write followed by
             * zeros. A fully allocated file is the whole object. */
            bool dense = static_cast<uint64_t>(st.st_blocks) * 512ull >= static_cast<uint64_t>(st.st_size);
            if (!(dense && off >= file_size)) {
                uint64_t blk = st.st_blksize > 0 ? static_cast<uint64_t>(st.st_blksize) : 4096ull;
                if (off > blk) off -= blk;
                else off = 0;
            }
        }
        off -= off % static_cast<uint64_t>(align);
    }
    io->f = std::fopen(path, off ? "r+b" : "wb");
    if (!io->f) return 0;
    if (off) {
        uint8_t buf[8192];
        uint64_t left = off;
        uint64_t got = 0;
        while (left) {
            size_t want = left > sizeof(buf) ? sizeof(buf) : static_cast<size_t>(left);
            size_t n = std::fread(buf, 1, want, io->f);
            if (n == 0) break;
            if (absorb) absorb(arg, buf, static_cast<int>(n));
            got += n;
            left -= n;
        }
        if (align > 0) got -= got % static_cast<uint64_t>(align);
        off = got;
        if (off == 0) {
            std::fclose(io->f);
            io->f = std::fopen(path, "wb");
        }
    }
    if (io->f && !reserve_file(io->f, off, file_size)) {
        io->nospace = true;
    }
    if (io->f && off) ::fseeko(io->f, static_cast<off_t>(off), SEEK_SET);
    if (path) std::snprintf(io->path_keep, sizeof(io->path_keep), "%s", path);
    if (name) std::snprintf(io->name_keep, sizeof(io->name_keep), "%s", name);
    io->path = io->path_keep;
    io->file_size = file_size;
    io->durable = off;
    if (io->f) write_sidecar(io->path_keep, io->name_keep, file_size, off);
    if (off) logf(1, "resume %s at %llu/%llu", path, static_cast<unsigned long long>(off),
                  static_cast<unsigned long long>(file_size));
    return off;
}

int file_read(void* u, uint8_t* d, int n) {
    auto* io = static_cast<FileIO*>(u);
    if (!io->f) return -1;
    size_t r = std::fread(d, 1, static_cast<size_t>(n), io->f);
    if (r == 0) return std::feof(io->f) ? 0 : -1;
    return static_cast<int>(r);
}

int file_write(void* u, const uint8_t* d, int n) {
    auto* io = static_cast<FileIO*>(u);
    if (!io->f || io->nospace) return -1;
    size_t w = std::fwrite(d, 1, static_cast<size_t>(n), io->f);
    if (w != static_cast<size_t>(n)) return -1;
    io->since_flush += static_cast<uint64_t>(n);
    if (io->f != stdout && io->since_flush >= 256ull * 1024ull) {
        std::fflush(io->f);
        io->durable += io->since_flush;
        io->since_flush = 0;
        if (io->path_keep[0]) write_sidecar(io->path_keep, io->name_keep, io->file_size, io->durable);
    }
    return n;
}

uint64_t file_resume_cb(void* user, const char* name, uint64_t file_size, int align, ResumeAbsorb absorb, void* arg) {
    auto* io = static_cast<FileIO*>(user);
    return open_resume(io, io->path, name, file_size, align, absorb, arg);
}

EngineOpts opts_from(const genesis_config* cfg) {
    EngineOpts o;
    o.profile = cfg->profile;
    o.fec_k = cfg->fec_k > 0 ? cfg->fec_k : 8;
    o.fec_r = cfg->fec_r > 0 ? cfg->fec_r : 1;
    o.plain_mss = cfg->plain_mss > 0 ? cfg->plain_mss : 1200;
    o.window = cfg->window_packets > 0 ? cfg->window_packets : 256;
    o.enable_fec = cfg->enable_fec;
    o.enable_nack = cfg->enable_nack;
    o.enable_dht = cfg->enable_dht;
    o.jitter_ms = cfg->jitter_ms;
    o.link_hint = cfg->link_hint;
    if (o.link_hint == 0) {
        char ifn[32];
        o.link_hint = primary_link(ifn, sizeof(ifn));
    }
    o.enable_mesh = cfg->enable_mesh != 0;
    o.punch_ms = cfg->punch_ms > 0 ? cfg->punch_ms : 2000;
    std::snprintf(o.node_name, sizeof(o.node_name), "%s", cfg->node_name);
    if (cfg->psk_hex[0]) {
        if (from_hex(cfg->psk_hex, o.psk, 32)) o.have_psk = true;
    }
    if (cfg->expect_pub_hex[0]) {
        if (from_hex(cfg->expect_pub_hex, o.expect_pub, 32)) o.have_expect_pub = true;
    }
    if (cfg->cookie_hex[0]) {
        if (from_hex(cfg->cookie_hex, o.cookie, 16)) o.have_cookie = true;
    }
    if (cfg->profile == GENESIS_PROFILE_CELLULAR) {
        if (cfg->fec_r < 2) o.fec_r = 2;
        if (cfg->plain_mss > 1100) o.plain_mss = 1100;
    } else if (cfg->profile == GENESIS_PROFILE_GBE) {
        if (cfg->fec_k < 16) o.fec_k = 16;
        if (cfg->plain_mss < 1300) o.plain_mss = 1336;
    } else if (cfg->profile == GENESIS_PROFILE_WIFI) {
        if (cfg->plain_mss > 1200) o.plain_mss = 1200;
    }
    return o;
}

void fill_stats(const Engine& eng, uint64_t now, genesis_stats* stats, int uring) {
    if (!stats) return;
    std::memset(stats, 0, sizeof(*stats));
    stats->bytes_payload = eng.payload_done();
    stats->file_size = eng.file_size();
    stats->bytes_wire_tx = eng.wire_tx();
    stats->bytes_wire_rx = eng.wire_rx();
    stats->retx = eng.retx();
    stats->fec_recovered = eng.fec_recovered();
    stats->pacing_bps = eng.pacing_bps();
    stats->rate_bps = eng.rate_bps(now);
    stats->min_rtt_us = eng.min_rtt_us();
    stats->profile = eng.profile();
    stats->phase = eng.phase();
    stats->io_uring = uring;
    stats->jitter_us = eng.jitter_us();
    stats->packets_tx = eng.packets_tx();
    stats->packets_rx = eng.packets_rx();
    stats->nacks_sent = eng.nacks_sent();
    stats->link_kind = eng.link_kind();
    stats->fec_enabled = eng.fec_on();
    stats->nack_enabled = eng.nack_on();
    stats->routes_alive = eng.routes_alive();
    stats->dht_peers = eng.dht_peers();
    stats->fec_tx_packets = eng.fec_tx_packets();
    stats->fec_rx_packets = eng.fec_rx_packets();
    stats->nack_tx_packets = eng.nack_tx_packets();
    stats->nack_rx_packets = eng.nack_rx_packets();
    stats->fec_tx_bytes = eng.fec_tx_bytes();
    stats->nack_tx_bytes = eng.nack_tx_bytes();
    stats->elapsed_us = now > eng.started_us() ? now - eng.started_us() : 0;
    eng.sha256_hex(stats->sha256_hex);
    if (eng.error()[0]) std::snprintf(stats->error, sizeof(stats->error), "%s", eng.error());
}

int drive(Engine& eng, UdpSocket& sock, genesis_progress_fn progress, void* user, int timeout_s, genesis_stats* stats) {
    uint64_t start = monotonic_us();
    uint64_t last_progress = start;
    uint64_t last_bytes = 0;
    uint64_t last_rate_us = start;
    uint64_t smooth_bps = 0;
    bool have_smooth = false;
    while (!eng.done()) {
        uint64_t now = monotonic_us();
        if (timeout_s > 0 && now > start + static_cast<uint64_t>(timeout_s) * 1000000ull) {
            if (stats) std::snprintf(stats->error, sizeof(stats->error), "timeout");
            return GENESIS_ERR_TIMEOUT;
        }
        eng.tick(now);
        flush_socket(eng, sock);
        int wait = 2;
        uint64_t wake = eng.next_wakeup_us();
        if (wake != 0 && wake <= now) wait = 0;
        else if (wake > now) {
            uint64_t us = wake - now;
            wait = us >= 1000 ? static_cast<int>(us / 1000) : 0;
            if (wait > 5) wait = 5;
        }
        uint8_t buf[1600];
        for (int burst = 0; burst < 64; ++burst) {
            uint32_t addr = 0;
            uint16_t port = 0;
            int n = sock.recv_from(buf, sizeof(buf), &addr, &port, burst == 0 ? wait : 0);
            if (n <= 0) break;
            eng.on_datagram(buf, static_cast<size_t>(n), Endpoint{addr, port}, monotonic_us());
        }
        now = monotonic_us();
        if (progress && now - last_progress > 100000) {
            uint64_t done = eng.payload_done();
            uint64_t total = eng.file_size();
            uint64_t dt = now - last_rate_us;
            if (dt == 0) dt = 1;
            uint64_t sample = (done - last_bytes) * 1000000ull / dt;
            /* 2 second time constant. A single 100 ms dip no longer rewrites the ETA. */
            constexpr uint64_t kTauUs = 2000000ull;
            if (!have_smooth) {
                smooth_bps = sample;
                have_smooth = true;
            } else if (sample >= smooth_bps) {
                smooth_bps += (sample - smooth_bps) * dt / (dt + kTauUs);
            } else {
                smooth_bps -= (smooth_bps - sample) * dt / (dt + kTauUs);
            }
            uint64_t life = eng.rate_bps(now);
            uint64_t rate = (smooth_bps + life) / 2;
            uint64_t eta = (rate && total > done) ? (total - done) * 1000ull / rate : ~0ull;
            progress(user, done, total, rate, eta);
            last_progress = now;
            last_bytes = done;
            last_rate_us = now;
        }
    }
    uint64_t now = monotonic_us();
    fill_stats(eng, now, stats, sock.io_uring() ? 1 : 0);
    if (progress) {
        uint64_t done = eng.payload_done();
        uint64_t life = eng.rate_bps(now);
        uint64_t rate = have_smooth ? (smooth_bps + life) / 2 : life;
        progress(user, done, eng.file_size(), rate, 0);
    }
    /* Drain a couple of trailing acks so the peer can finish. */
    uint64_t until = now + 200000;
    while (monotonic_us() < until) {
        eng.tick(monotonic_us());
        flush_socket(eng, sock);
        uint8_t buf[1600];
        uint32_t addr = 0;
        uint16_t port = 0;
        int n = sock.recv_from(buf, sizeof(buf), &addr, &port, 20);
        if (n > 0) eng.on_datagram(buf, static_cast<size_t>(n), Endpoint{addr, port}, monotonic_us());
    }
    return eng.success() ? GENESIS_OK : GENESIS_ERR_PROTO;
}

}  // namespace

void flush_socket(Engine& eng, UdpSocket& sock) {
    DatagramOut d;
    while (eng.pop(d)) {
        if (sock.send_to(d.data, d.len, d.addr_be, d.port)) continue;
        eng.push_front(d);
        int err = errno;
        if (err == EAGAIN || err == EWOULDBLOCK || err == ENOBUFS || err == EINTR) return;
        /* A vanished route otherwise retries this datagram in a tight loop. */
        static uint64_t last_log = 0;
        uint64_t now = monotonic_us();
        if (last_log == 0 || now - last_log > 1000000ull) {
            logf(1, "send failed: %s", std::strerror(err));
            last_log = now;
        }
        ::usleep(20000);
        return;
    }
}

int run_send(const genesis_config* cfg, const char* path, const char* host, uint16_t port,
             genesis_progress_fn progress, void* user, genesis_stats* stats) {
    if (!cfg || !path || !host || !port) return GENESIS_ERR_ARGS;
    log_set_verbose(cfg->verbose);
    if (cfg->pinned_core >= 0) pin_thread(cfg->pinned_core);
    FILE* f = std::strcmp(path, "-") == 0 ? stdin : std::fopen(path, "rb");
    if (!f) return GENESIS_ERR_IO;
    off_t sz = 0;
    if (f != stdin) {
        if (::fseeko(f, 0, SEEK_END) != 0) {
            std::fclose(f);
            return GENESIS_ERR_IO;
        }
        sz = ::ftello(f);
        if (::fseeko(f, 0, SEEK_SET) != 0 || sz < 0) {
            std::fclose(f);
            return GENESIS_ERR_IO;
        }
    }
    UdpSocket sock;
    bool want_uring = cfg->enable_io_uring != 0;
    if (!sock.open(cfg->bind_host, cfg->bind_port, cfg->socket_buffer, want_uring)) {
        std::fclose(f);
        return GENESIS_ERR_NET;
    }
    uint32_t peer = 0;
    if (!ipv4_resolve(host, &peer)) {
        std::fclose(f);
        return GENESIS_ERR_NET;
    }
    EngineOpts opt = opts_from(cfg);
    opt.file_size = static_cast<uint64_t>(sz);
    opt.local_port = sock.local_port();
    const char* base = std::strrchr(path, '/');
    std::snprintf(opt.file_name, sizeof(opt.file_name), "%s", base ? base + 1 : path);
    Engine eng(opt, true);
    eng.add_candidate(Endpoint{peer, port});
    if (cfg->routes[0]) {
        char buf[512];
        std::snprintf(buf, sizeof(buf), "%s", cfg->routes);
        char* save = nullptr;
        for (char* tok = strtok_r(buf, ",", &save); tok; tok = strtok_r(nullptr, ",", &save)) {
            while (*tok == ' ') ++tok;
            char* colon = std::strrchr(tok, ':');
            if (!colon || colon == tok) continue;
            *colon = '\0';
            int rp = std::atoi(colon + 1);
            uint32_t addr = 0;
            if (rp > 0 && rp <= 65535 && ipv4_resolve(tok, &addr)) eng.add_route(Endpoint{addr, static_cast<uint16_t>(rp)});
        }
    }
    if (cfg->stun_host[0]) {
        uint32_t mapped = 0;
        uint16_t mport = 0;
        if (stun_query(sock, cfg->stun_host, cfg->stun_port, &mapped, &mport))
            logf(1, "stun mapped %u.%u.%u.%u:%u", (mapped >> 24) & 255, (mapped >> 16) & 255, (mapped >> 8) & 255,
                 mapped & 255, mport);
    }
    FileIO io;
    io.f = f;
    eng.set_io(file_read, nullptr, &io);
    eng.start(monotonic_us());
    int rc = drive(eng, sock, progress, user, cfg->transfer_timeout_s, stats);
    if (f != stdin) std::fclose(f);
    return rc;
}

int run_recv(const genesis_config* cfg, const char* path, genesis_progress_fn progress, void* user,
             genesis_stats* stats) {
    if (!cfg || !path) return GENESIS_ERR_ARGS;
    log_set_verbose(cfg->verbose);
    if (cfg->pinned_core >= 0) pin_thread(cfg->pinned_core);
    UdpSocket sock;
    if (!sock.open(cfg->bind_host, cfg->bind_port, cfg->socket_buffer, cfg->enable_io_uring != 0)) return GENESIS_ERR_NET;
    EngineOpts opt = opts_from(cfg);
    opt.local_port = sock.local_port();
    Engine eng(opt, false);
    FileIO io;
    io.path = path;
    io.writing = true;
    eng.set_resume(file_resume_cb, &io);
    eng.set_io(nullptr, file_write, &io);
    eng.start(monotonic_us());
    if (cfg->ssh_pipe) {
        if (std::strcmp(path, "-") == 0) {
            return GENESIS_ERR_ARGS;
        }
        std::fprintf(stdout, "ready %u\n", static_cast<unsigned>(sock.local_port()));
        std::fflush(stdout);
    }
    int rc = drive(eng, sock, progress, user, cfg->transfer_timeout_s, stats);
    if (io.f && io.f != stdout) std::fclose(io.f);
    return rc;
}

struct Session {
    Engine* eng = nullptr;
    FileIO io;
    bool open = false;
    Node* node = nullptr;
    char path[512]{};
};

struct Node {
    genesis_config cfg{};
    UdpSocket sock;
    UdpSocket disco;
    /* Written by genesis_node_request_stop from a thread that is not polling. */
    std::atomic<bool> stop{false};
    Session sessions[4];
    uint64_t last_beacon = 0;
    genesis_stats last{};
    int ctrl_fd = -1;
    VfsHub* vfs = nullptr;
    NatHub* nat = nullptr;
    bool oneshot = false;
    char oneshot_path[512]{};
    uint64_t ctrl_prog_us = 0;
    bool have_base = false;
    genesis_config base_cfg{};
};

uint64_t session_resume(void* user, const char* name, uint64_t file_size, int align, ResumeAbsorb absorb, void* arg) {
    auto* s = static_cast<Session*>(user);
    if (!s || !s->node) return 0;
    char path[512];
    if (s->node->oneshot && s->node->oneshot_path[0]) {
        std::snprintf(path, sizeof(path), "%s", s->node->oneshot_path);
    } else if (genesis_path_is_safe(s->node->cfg.recv_dir, name, path, sizeof(path)) != GENESIS_OK) {
        std::snprintf(s->node->last.error, sizeof(s->node->last.error), "rejected path");
        return 0;
    }
    uint64_t off = open_resume(&s->io, path, name, file_size, align, absorb, arg);
    std::snprintf(s->path, sizeof(s->path), "%s", path);
    s->open = s->io.f != nullptr;
    return off;
}

Node* node_create(const genesis_config* cfg) {
    if (!cfg) return nullptr;
    Node* n = new Node();
    n->cfg = *cfg;
    log_set_verbose(cfg->verbose);
    if (!n->sock.open(cfg->bind_host, cfg->bind_port, cfg->socket_buffer, cfg->enable_io_uring != 0)) {
        delete n;
        return nullptr;
    }
    if (cfg->enable_discovery) {
        if (n->disco.open("0.0.0.0", kDiscoveryPort, 1 << 20, false)) n->disco.join_multicast(kDiscoveryGroup);
    }
    if (cfg->pinned_core >= 0) pin_thread(cfg->pinned_core);
    n->vfs = vfs_hub_create(cfg);
    n->nat = nat_hub_create();
    if (!n->vfs || !n->nat) {
        vfs_hub_destroy(n->vfs);
        nat_hub_destroy(n->nat);
        delete n;
        return nullptr;
    }
    return n;
}

static Session* find_session(Node* n, uint32_t conn) {
    (void)conn;
    for (auto& s : n->sessions)
        if (s.eng && !s.eng->done()) return &s;
    return nullptr;
}

void finish_control(Node* n, Session& s);

int node_poll(Node* n, int timeout_ms) {
    if (!n) return GENESIS_ERR_ARGS;
    if (n->stop.load(std::memory_order_acquire)) return 0;
    uint64_t now = monotonic_us();
    if (n->cfg.enable_discovery && now - n->last_beacon > 2000000) {
        Beacon b;
        b.port = n->sock.local_port();
        b.features = kFeatFile | kFeatBbr | kFeatDiscovery;
        if (n->cfg.export_count > 0) b.features |= kFeatVfs;
        std::snprintf(b.name, sizeof(b.name), "%s", n->cfg.node_name);
        uint8_t pkt[512];
        size_t len = beacon_encode(pkt, sizeof(pkt), b);
        if (len && n->cfg.export_count > 0)
            len = beacon_append_exports(pkt, sizeof(pkt), len, n->cfg.export_name, n->cfg.export_rw, n->cfg.export_count);
        if (len && n->disco.fd() >= 0) n->disco.send_to(pkt, len, kDiscoveryGroup, kDiscoveryPort);
        n->last_beacon = now;
    }
    pollfd pf[9];
    pf[0].fd = n->sock.fd();
    pf[0].events = POLLIN;
    pf[0].revents = 0;
    int extra_fds[8];
    int extra = vfs_hub_fill_fds(n->vfs, extra_fds, 8);
    for (int i = 0; i < extra; ++i) {
        pf[1 + i].fd = extra_fds[i];
        pf[1 + i].events = POLLIN;
        pf[1 + i].revents = 0;
    }
    int pr = ::poll(pf, static_cast<nfds_t>(1 + extra), timeout_ms);
    if (pr > 0) {
        for (int i = 0; i < extra; ++i)
            if (pf[1 + i].revents & (POLLIN | POLLHUP | POLLERR)) vfs_hub_on_fd(n->vfs, extra_fds[i]);
    }
    uint8_t buf[2048];
    uint32_t addr = 0;
    uint16_t port = 0;
    int got = 0;
    if (pr > 0 && (pf[0].revents & (POLLIN | POLLERR | POLLHUP)))
        got = n->sock.recv_from(buf, sizeof(buf), &addr, &port, 0);
    bool nat_pkt = got > 0 && nat_is(buf, static_cast<size_t>(got));
    if (nat_pkt) nat_hub_packet(n->nat, n->sock, buf, static_cast<size_t>(got), addr, port);
    bool vfs_pkt = got > 0 && !nat_pkt && vfs_is_packet(buf, static_cast<size_t>(got));
    if (vfs_pkt) vfs_hub_packet(n->vfs, n->sock, buf, static_cast<size_t>(got), addr, port);
    if (got > 0 && !vfs_pkt && !nat_pkt) {
        Session* s = find_session(n, 0);
        if (!s) {
            for (auto& slot : n->sessions) {
                if (!slot.eng) {
                    s = &slot;
                    break;
                }
            }
            if (!s) return GENESIS_ERR;
            EngineOpts opt = opts_from(&n->cfg);
            opt.local_port = n->sock.local_port();
            s->node = n;
            s->eng = new Engine(opt, false);
            s->eng->set_resume(session_resume, s);
            s->eng->set_io(nullptr, file_write, &s->io);
            s->eng->start(now);
        }
        s->eng->on_datagram(buf, static_cast<size_t>(got), Endpoint{addr, port}, monotonic_us());
        if (!s->open && s->eng->peer_file_name()[0] && !s->io.f) {
            char safe[512];
            if (n->oneshot && n->oneshot_path[0]) std::snprintf(safe, sizeof(safe), "%s", n->oneshot_path);
            else if (genesis_path_is_safe(n->cfg.recv_dir, s->eng->peer_file_name(), safe, sizeof(safe)) != GENESIS_OK) {
                std::snprintf(n->last.error, sizeof(n->last.error), "rejected path");
                safe[0] = '\0';
            }
            if (safe[0]) {
                s->io.f = std::fopen(safe, "wb");
                if (s->io.f) {
                    s->open = true;
                    std::snprintf(s->path, sizeof(s->path), "%s", safe);
                }
            }
        } else if (s->io.f) {
            s->open = true;
        }
        s->eng->tick(monotonic_us());
        flush_socket(*s->eng, n->sock);
        if (n->ctrl_fd >= 0 && s->eng && !s->eng->done()) {
            uint64_t t = monotonic_us();
            if (t - n->ctrl_prog_us > 100000) {
                n->ctrl_prog_us = t;
                uint64_t done = s->eng->payload_done();
                uint64_t total = s->eng->file_size();
                uint64_t rate = s->eng->rate_bps(t);
                uint64_t eta = (rate && total > done) ? (total - done) * 1000ull / rate : ~uint64_t{0};
                if (dprintf(n->ctrl_fd, "P %llu %llu %llu %llu\n", static_cast<unsigned long long>(done),
                            static_cast<unsigned long long>(total), static_cast<unsigned long long>(rate),
                            static_cast<unsigned long long>(eta)) < 0) {
                    close(n->ctrl_fd);
                    n->ctrl_fd = -1;
                }
            }
        }
        if (s->eng->done()) finish_control(n, *s);
    } else {
        for (auto& s : n->sessions) {
            if (!s.eng) continue;
            s.eng->tick(monotonic_us());
            flush_socket(*s.eng, n->sock);
            if (s.eng->done()) finish_control(n, s);
        }
    }
    return GENESIS_OK;
}

void finish_control(Node* n, Session& s) {
    if (!s.eng || !s.eng->done()) return;
    fill_stats(*s.eng, monotonic_us(), &n->last, n->sock.io_uring() ? 1 : 0);
    if (n->ctrl_fd >= 0) {
        if (s.eng->success()) {
            char hash[65];
            s.eng->sha256_hex(hash);
            dprintf(n->ctrl_fd, "OK sha256=%s rate=%llu pacing=%llu wire_tx=%llu\n", hash,
                    static_cast<unsigned long long>(n->last.rate_bps),
                    static_cast<unsigned long long>(n->last.pacing_bps),
                    static_cast<unsigned long long>(n->last.bytes_wire_tx));
        } else {
            dprintf(n->ctrl_fd, "ERR %d %s\n", GENESIS_ERR_PROTO, s.eng->error());
        }
        close(n->ctrl_fd);
        n->ctrl_fd = -1;
        n->oneshot = false;
        n->oneshot_path[0] = '\0';
    }
    if (n->have_base) {
        n->cfg = n->base_cfg;
        n->have_base = false;
    }
    if (s.io.f) {
        std::fclose(s.io.f);
        s.io.f = nullptr;
    }
    delete s.eng;
    s.eng = nullptr;
    s.open = false;
}

int node_arm_recv(Node* n, int client_fd, const char* path, const genesis_config* cfg) {
    if (!n || client_fd < 0 || !path || !path[0] || std::strcmp(path, "-") == 0) return GENESIS_ERR_ARGS;
    if (n->ctrl_fd >= 0) return GENESIS_ERR;
    for (auto& s : n->sessions)
        if (s.eng && !s.eng->done()) return GENESIS_ERR;
    if (cfg) {
        if (!n->have_base) {
            n->base_cfg = n->cfg;
            n->have_base = true;
        }
        genesis_config keep = n->cfg;
        n->cfg = *cfg;
        std::snprintf(n->cfg.bind_host, sizeof(n->cfg.bind_host), "%s", keep.bind_host);
        n->cfg.bind_port = keep.bind_port;
        std::snprintf(n->cfg.recv_dir, sizeof(n->cfg.recv_dir), "%s", keep.recv_dir);
        std::snprintf(n->cfg.chroot_dir, sizeof(n->cfg.chroot_dir), "%s", keep.chroot_dir);
        std::snprintf(n->cfg.drop_user, sizeof(n->cfg.drop_user), "%s", keep.drop_user);
        std::snprintf(n->cfg.pid_file, sizeof(n->cfg.pid_file), "%s", keep.pid_file);
        std::snprintf(n->cfg.control, sizeof(n->cfg.control), "%s", keep.control);
        n->cfg.export_count = keep.export_count;
        std::memcpy(n->cfg.export_name, keep.export_name, sizeof(n->cfg.export_name));
        std::memcpy(n->cfg.export_path, keep.export_path, sizeof(n->cfg.export_path));
        std::memcpy(n->cfg.export_rw, keep.export_rw, sizeof(n->cfg.export_rw));
    }
    std::snprintf(n->oneshot_path, sizeof(n->oneshot_path), "%s", path);
    n->oneshot = true;
    n->ctrl_fd = client_fd;
    n->ctrl_prog_us = 0;
    return GENESIS_OK;
}

void node_stop(Node* n) {
    if (n) n->stop.store(true, std::memory_order_release);
}

void node_destroy(Node* n) {
    if (!n) return;
    for (auto& s : n->sessions) {
        delete s.eng;
        if (s.io.f) std::fclose(s.io.f);
    }
    vfs_hub_destroy(n->vfs);
    nat_hub_destroy(n->nat);
    delete n;
}

uint16_t node_port(const Node* n) {
    return n ? n->sock.local_port() : 0;
}

int node_vfs_attach(Node* n, int client_fd, const char* export_name) {
    if (!n || !n->vfs) return -1;
    return vfs_hub_attach(n->vfs, client_fd, export_name);
}

int node_stats(const Node* n, genesis_stats* stats) {
    if (!n || !stats) return GENESIS_ERR_ARGS;
    *stats = n->last;
    return GENESIS_OK;
}

}  // namespace genesis
