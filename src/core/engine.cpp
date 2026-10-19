#include "engine.hpp"

#include "bbr.hpp"
#include "crypto.hpp"
#include "dht.hpp"
#include "endian.hpp"
#include "fec.hpp"
#include "handshake.hpp"
#include "jitter.hpp"
#include "link.hpp"
#include "log.hpp"
#include "mesh.hpp"
#include "util.hpp"
#include "wire.hpp"

#include <cstdio>
#include <cstring>
#include <new>

namespace genesis {
namespace {

constexpr int kSlots = 512;
constexpr int kOutQ = 64;
constexpr int kPrefix = 18;
constexpr uint64_t kUnknownSize = ~0ull;

enum Phase : int { PhInit = 0, PhHello = 1, PhConfirm = 2, PhXfer = 3, PhFin = 4, PhDone = 5, PhFail = 6 };

struct Slot {
    bool used = false;
    bool acked = false;
    bool is_data = false;
    bool is_fec = false;
    bool is_fin = false;
    bool loss_marked = false;
    uint64_t seq = 0;
    uint16_t plain_len = 0;
    uint16_t wire_len = 0;
    uint64_t sent_us = 0;
    int sends = 0;
    uint32_t group = 0;
    int route = -1;
    uint8_t plain[1400]{};
    uint8_t wire[1500]{};
};

struct Group {
    bool used = false;
    uint32_t id = 0;
    uint64_t base_seq = 0;
    int k = 0;
    int r = 0;
    int block = 0;
    uint8_t have_d[kFecMaxData]{};
    uint8_t have_p[kFecMaxParity]{};
    uint8_t data[kFecMaxData][1400]{};
    uint8_t par[kFecMaxParity][1400]{};
};

}  // namespace

struct Engine::Impl {
    EngineOpts opt;
    bool sender = false;
    Phase phase = PhInit;
    char err[160]{};
    IoRead read_fn = nullptr;
    IoWrite write_fn = nullptr;
    void* io_user = nullptr;

    uint8_t secret[32]{};
    uint8_t pubkey[32]{};
    uint8_t node_id[16]{};
    uint8_t nonce[16]{};
    uint8_t tx_key[32]{};
    uint8_t rx_key[32]{};
    bool keys = false;
    uint32_t conn = 0;
    uint64_t tx_seq = 1;
    uint64_t fec_seq = 1ull << 63;
    uint64_t fin_seq = 0;
    bool fin_sent = false;
    bool eof = false;
    bool peer_locked = false;
    Endpoint peer{};
    Endpoint cands[kMaxCandidates]{};
    int ncand = 0;

    PeerView local{};
    PeerView remote{};
    bool have_remote = false;
    uint32_t negotiated = 0;
    bool use_fec = true;

    uint8_t hello_pkt[700]{};
    uint16_t hello_len = 0;
    uint8_t confirm_pkt[200]{};
    uint16_t confirm_len = 0;
    uint8_t hello_raw[700]{};
    uint16_t hello_raw_len = 0;
    uint8_t ack_raw[700]{};
    uint16_t ack_raw_len = 0;
    bool have_hello_raw = false;
    bool have_ack_raw = false;
    uint8_t transcript[32]{};
    bool have_transcript = false;
    bool sent_confirm = false;
    bool got_confirm = false;

    Bbr bbr;
    Slot slots[kSlots];
    uint64_t file_off = 0;
    uint64_t resume_off = 0;
    ResumeFn resume_fn = nullptr;
    void* resume_user = nullptr;
    uint32_t group_id = 1;
    int group_index = 0;
    uint64_t group_base = 0;
    uint8_t group_plain[kFecMaxData][1400]{};
    uint16_t group_len[kFecMaxData]{};
    int group_n = 0;

    struct Rb {
        bool have = false;
        uint16_t len = 0;
        uint8_t data[1400]{};
    };
    Rb reorder[kSlots];
    uint64_t expect_off = 0;
    bool got_seq[kSlots]{};
    uint64_t cum_ack = 1;
    uint64_t highest_seq = 0;
    Group groups[8];
    uint64_t fec_recovered = 0;

    DatagramOut outq[kOutQ];
    int qh = 0;
    int qt = 0;

    Sha256 sha;
    bool sha_done = false;
    uint8_t file_hash[32]{};
    uint64_t payload = 0;
    uint64_t acked_payload = 0;
    uint64_t tx_bytes = 0;
    uint64_t rx_bytes = 0;
    uint64_t pkts_tx = 0;
    uint64_t pkts_rx = 0;
    uint64_t fec_tx_pkts = 0;
    uint64_t fec_rx_pkts = 0;
    uint64_t nack_tx_pkts = 0;
    uint64_t nack_rx_pkts = 0;
    uint64_t fec_tx_bytes = 0;
    uint64_t nack_tx_bytes = 0;
    uint64_t fec_rx_bytes = 0;
    uint64_t nack_rx_bytes = 0;
    uint64_t retx_count = 0;
    bool hs_logged = false;
    bool end_logged = false;
    uint64_t start_us = 0;
    uint64_t next_send_us = 0;
    uint64_t last_rx_us = 0;
    uint64_t last_hello_us = 0;
    uint64_t last_ack_us = 0;
    bool ack_needed = false;
    int plain_mss = 1200;
    int chunk = 1182;
    bool chunk_locked = false;
    MeshTable mesh{};
    JitterMeter jitter;
    int link_kind = 0;
    bool use_nack = false;
    bool enable_dht = true;
    struct Held {
        bool used = false;
        uint64_t seq = 0;
        uint64_t in_us = 0;
        uint16_t len = 0;
        uint8_t plain[1400]{};
    };
    Held held[48]{};
    uint64_t hole_since = 0;
    uint64_t last_nack_us = 0;
    uint64_t nacks_sent = 0;
    struct Route {
        Endpoint ep{};
        bool alive = true;
        int fails = 0;
    };
    Route routes[8]{};
    int nroutes = 0;
    DhtTable dht{};

    explicit Impl(const EngineOpts& o, bool is_sender) : opt(o), sender(is_sender) {
        if (opt.fec_k < 1) opt.fec_k = 1;
        if (opt.fec_k > 16) opt.fec_k = 16;
        if (opt.fec_r < 1) opt.fec_r = 1;
        if (opt.fec_r > 4) opt.fec_r = 4;
        if (opt.plain_mss < 256) opt.plain_mss = 256;
        if (opt.plain_mss > 1360) opt.plain_mss = 1360;
        if (opt.window < 16) opt.window = 16;
        if (opt.window > kSlots) opt.window = kSlots;
        plain_mss = opt.plain_mss;
        chunk = plain_mss - kPrefix;
        link_kind = opt.link_hint;
        if (link_kind < 0 || link_kind > 3) link_kind = 0;
        if (link_kind == 0) {
            if (opt.profile == 2) link_kind = 3;
            else if (opt.profile == 3) link_kind = 2;
            else if (opt.profile == 1) link_kind = 1;
        }
        /* Unknown link is treated as ethernet. Wi-Fi wants FEC. Ethernet accepts
         * it so a wi-fi peer is not left with NACK only, and does not force FEC
         * on another ethernet peer. Cellular wants neither. An explicit 0 or 1
         * overrides the guess. */
        bool auto_fec = link_kind == 2;
        bool auto_nack = link_kind != 3;
        if (link_kind == 0) {
            auto_fec = false;
            auto_nack = true;
        }
        use_fec = opt.enable_fec < 0 ? auto_fec : opt.enable_fec > 0;
        use_nack = opt.enable_nack < 0 ? auto_nack : opt.enable_nack > 0;
        enable_dht = opt.enable_dht != 0;
        random_bytes(secret, 32);
        random_bytes(node_id, 16);
        random_bytes(nonce, 16);
        random_bytes(reinterpret_cast<uint8_t*>(&conn), 4);
        if (conn == 0) conn = 1;
        tx_seq = 2;
        x25519_base(pubkey, secret);
        local = PeerView{};
        local.hs_version = kHsVersion;
        local.profile = static_cast<uint8_t>(opt.profile);
        local.features = kFeatBbr | kFeatFile | kFeatRelay | kFeatDiscovery | kFeatJitter | kFeatResume;
        if (use_fec) local.features |= kFeatFec;
        else if (opt.enable_fec < 0 && link_kind != 3) local.features |= kFeatFecAccept;
        if (use_nack) local.features |= kFeatNack;
        if (enable_dht) local.features |= kFeatDht;
        if (opt.enable_mesh) local.features |= kFeatMesh;
        if (link_kind == 3 || opt.profile == 2) local.features |= kFeatCellular;
        else if (link_kind == 2 || opt.profile == 3) local.features |= kFeatWifi;
        else local.features |= kFeatGbe;
        if (opt.file_size == 0 && !sender) local.features |= kFeatStream;
        std::memcpy(local.pubkey, pubkey, 32);
        std::memcpy(local.nonce, nonce, 16);
        std::memcpy(local.node_id, node_id, 16);
        local.udp_port = opt.local_port;
        std::snprintf(local.name, sizeof(local.name), "%s", opt.node_name);
        std::snprintf(local.file_name, sizeof(local.file_name), "%s", opt.file_name);
        local.file_size = sender ? opt.file_size : 0;
        int bbr_profile = 1;
        if (link_kind == 3 || opt.profile == 2) bbr_profile = 2;
        else if (link_kind == 2 || opt.profile == 3) bbr_profile = 3;
        bbr.reset(static_cast<uint32_t>(plain_mss), bbr_profile);
        mesh_upsert(mesh, node_id);
        dht.set_self(node_id);
    }

    void fail(const char* why) {
        if (phase == PhFail || phase == PhDone) return;
        phase = PhFail;
        std::snprintf(err, sizeof(err), "%s", why);
    }

    int qcount() const { return (qt - qh + kOutQ) % kOutQ; }

    static void absorb_cb(void* self, const uint8_t* p, int n) {
        if (n > 0) static_cast<Impl*>(self)->sha.update(p, static_cast<size_t>(n));
    }

    bool absorb_prefix(uint64_t off) {
        uint8_t buf[4096];
        uint64_t left = off;
        while (left) {
            int want = left > sizeof(buf) ? static_cast<int>(sizeof(buf)) : static_cast<int>(left);
            if (!read_fn) return false;
            int n = read_fn(io_user, buf, want);
            if (n <= 0) return false;
            sha.update(buf, static_cast<size_t>(n));
            left -= static_cast<uint64_t>(n);
        }
        file_off = off;
        acked_payload = off;
        resume_off = off;
        return true;
    }

    bool enqueue(const uint8_t* data, uint16_t len, Endpoint to) {
        if (qcount() >= kOutQ - 1) return false;
        DatagramOut& d = outq[qt];
        if (len > sizeof(d.data)) return false;
        std::memcpy(d.data, data, len);
        d.len = len;
        d.addr_be = to.addr_be;
        d.port = to.port;
        qt = (qt + 1) % kOutQ;
        tx_bytes += len;
        ++pkts_tx;
        return true;
    }

    const char* link_name() const {
        if (link_kind == 1) return "ethernet";
        if (link_kind == 2) return "wifi";
        if (link_kind == 3) return "cellular";
        return "unknown";
    }

    void log_init() {
        if (hs_logged || log_verbose() < 1) return;
        hs_logged = true;
        const char* name = opt.file_name[0] ? opt.file_name : remote.file_name;
        uint32_t a = peer.addr_be;
        logf(1,
             "transfer init %u.%u.%u.%u:%u file=%s fec=%s nack=%s link=%s features=0x%08x jitter=%s dht=%s resume=%llu",
             (a >> 24) & 255, (a >> 16) & 255, (a >> 8) & 255, a & 255, peer.port, name[0] ? name : "-",
             use_fec ? "on" : "off", use_nack ? "on" : "off", link_name(), negotiated,
             (negotiated & kFeatJitter) ? "on" : "off", (negotiated & kFeatDht) ? "on" : "off",
             static_cast<unsigned long long>(resume_off));
    }

    void log_end(uint64_t now) {
        if (end_logged) return;
        if (phase != PhDone && phase != PhFail) return;
        end_logged = true;
        if (log_verbose() < 1) return;
        const char* name = opt.file_name[0] ? opt.file_name : remote.file_name;
        uint32_t a = peer.addr_be;
        uint64_t elapsed = now > start_us ? now - start_us : 1;
        uint64_t avg_tx = pkts_tx * 1000000ull / elapsed;
        uint64_t over_tx = fec_tx_bytes + nack_tx_bytes;
        uint64_t over_rx = fec_rx_bytes + nack_rx_bytes;
        uint64_t pct_tx = tx_bytes ? over_tx * 1000ull / tx_bytes : 0;
        uint64_t pct_rx = rx_bytes ? over_rx * 1000ull / rx_bytes : 0;
        char hash[65];
        to_hex(file_hash, 32, hash);
        logf(1,
             "transfer end %u.%u.%u.%u:%u file=%s %s bytes=%llu sha256=%s tx=%llu rx=%llu avg_tx=%llu/s "
             "fec_tx=%llu fec_rx=%llu nack_tx=%llu nack_rx=%llu nack_seqs=%llu retx=%llu fec_recovered=%llu "
             "overhead_tx=%llu.%llu%% overhead_rx=%llu.%llu%%",
             (a >> 24) & 255, (a >> 16) & 255, (a >> 8) & 255, a & 255, peer.port, name[0] ? name : "-",
             phase == PhDone ? "ok" : err, static_cast<unsigned long long>(sender ? acked_payload : payload), hash,
             static_cast<unsigned long long>(pkts_tx), static_cast<unsigned long long>(pkts_rx),
             static_cast<unsigned long long>(avg_tx), static_cast<unsigned long long>(fec_tx_pkts),
             static_cast<unsigned long long>(fec_rx_pkts), static_cast<unsigned long long>(nack_tx_pkts),
             static_cast<unsigned long long>(nack_rx_pkts), static_cast<unsigned long long>(nacks_sent),
             static_cast<unsigned long long>(retx_count), static_cast<unsigned long long>(fec_recovered),
             static_cast<unsigned long long>(pct_tx / 10), static_cast<unsigned long long>(pct_tx % 10),
             static_cast<unsigned long long>(pct_rx / 10), static_cast<unsigned long long>(pct_rx % 10));
    }

    void fanout(const uint8_t* data, uint16_t len) {
        if (peer_locked) {
            enqueue(data, len, peer);
            return;
        }
        if (ncand == 0 && peer.port) {
            enqueue(data, len, peer);
            return;
        }
        for (int i = 0; i < ncand; ++i) enqueue(data, len, cands[i]);
    }

    bool seal(uint8_t* packet, uint16_t* out_len, Header h, const uint8_t* plain, size_t plain_len) {
        h.version = kProtoVersion;
        h.flags = static_cast<uint16_t>(h.flags | kFlagEncrypted);
        h.ext_len = 0;
        h.payload_len = static_cast<uint16_t>(plain_len + 16);
        h.conn_id = conn;
        if (!encode_header(packet, 1500, h)) return false;
        uint8_t nonce12[12] = {};
        store_le64(nonce12 + 4, h.seq);
        size_t clen = 0;
        if (!aead_encrypt(packet + kHeaderBytes, 1500 - kHeaderBytes, &clen, plain, plain_len, packet, kHeaderBytes,
                          tx_key, nonce12))
            return false;
        *out_len = static_cast<uint16_t>(kHeaderBytes + clen);
        return true;
    }

    bool open(uint8_t* plain, size_t* plain_len, const Header& h, const uint8_t* packet) {
        if (!(h.flags & kFlagEncrypted)) {
            if (h.payload_len > 1400) return false;
            std::memcpy(plain, packet + kHeaderBytes + h.ext_len, h.payload_len);
            *plain_len = h.payload_len;
            return true;
        }
        if (!keys) return false;
        uint8_t nonce12[12] = {};
        store_le64(nonce12 + 4, h.seq);
        const uint8_t* c = packet + kHeaderBytes + h.ext_len;
        return aead_decrypt(plain, 1400, plain_len, c, h.payload_len, packet, kHeaderBytes, rx_key, nonce12);
    }

    void build_hello_packet() {
        uint8_t body[600];
        size_t blen = 0;
        local.cand_count = 0;
        for (int i = 0; i < ncand && local.cand_count < kMaxCandidates; ++i) {
            int c = local.cand_count++;
            local.cand_kind[c] = 1;
            uint32_t a = cands[i].addr_be;
            local.cand_addr[c][0] = static_cast<uint8_t>(a >> 24);
            local.cand_addr[c][1] = static_cast<uint8_t>(a >> 16);
            local.cand_addr[c][2] = static_cast<uint8_t>(a >> 8);
            local.cand_addr[c][3] = static_cast<uint8_t>(a);
            local.cand_port[c] = cands[i].port;
        }
        if (!encode_hello(body, sizeof(body), &blen, local)) {
            fail("hello encode");
            return;
        }
        blen = hello_append_tail(body, sizeof(body), blen, static_cast<uint16_t>(chunk), sender ? 0 : resume_off);
        Header h;
        h.type = sender ? kHello : kHelloAck;
        h.seq = 0;
        h.conn_id = conn;
        h.timestamp_us = start_us;
        h.payload_len = static_cast<uint16_t>(blen);
        h.version = kProtoVersion;
        encode_header(hello_pkt, sizeof(hello_pkt), h);
        std::memcpy(hello_pkt + kHeaderBytes, body, blen);
        hello_len = static_cast<uint16_t>(kHeaderBytes + blen);
    }

    void queue_hello(uint64_t now) {
        if (!hello_len) build_hello_packet();
        fanout(hello_pkt, hello_len);
        last_hello_us = now;
        if (phase == PhInit) phase = PhHello;
    }

    void derive(bool i_am_initiator) {
        const uint8_t* n_i = i_am_initiator ? nonce : remote.nonce;
        const uint8_t* n_r = i_am_initiator ? remote.nonce : nonce;
        uint8_t shared[32];
        x25519(shared, secret, remote.pubkey);
        derive_transport_keys(shared, opt.psk, opt.have_psk, n_i, n_r, tx_key, rx_key);
        if (!i_am_initiator) {
            uint8_t tmp[32];
            std::memcpy(tmp, tx_key, 32);
            std::memcpy(tx_key, rx_key, 32);
            std::memcpy(rx_key, tmp, 32);
        }
        secure_zero(shared, 32);
        keys = true;
        negotiated = local.features & remote.features;
        bool fec_want = (local.features & kFeatFec) || (remote.features & kFeatFec);
        bool fec_ok = (local.features & (kFeatFec | kFeatFecAccept)) &&
                      (remote.features & (kFeatFec | kFeatFecAccept));
        use_fec = fec_want && fec_ok;
        if ((negotiated & kFeatNack) == 0) use_nack = false;
        if (remote.profile == 2 || local.profile == 2 || link_kind == 3) bbr.reset(static_cast<uint32_t>(plain_mss), 2);
        mesh_observe(mesh, remote.node_id, 1000, 100000, start_us);
    }

    void compute_transcript() {
        if (!have_hello_raw || !have_ack_raw) return;
        Sha256 s;
        s.update(hello_raw, hello_raw_len);
        s.update(ack_raw, ack_raw_len);
        s.final(transcript);
        have_transcript = true;
    }

    void queue_confirm(uint64_t now) {
        if (!have_transcript || !keys) return;
        if (!confirm_len) {
            Header h;
            h.type = kKeyConfirm;
            h.seq = 1;
            h.conn_id = conn;
            h.timestamp_us = now;
            uint16_t len = 0;
            if (!seal(confirm_pkt, &len, h, transcript, 32)) {
                fail("confirm seal");
                return;
            }
            confirm_len = len;
        }
        fanout(confirm_pkt, confirm_len);
        sent_confirm = true;
        if (phase < PhConfirm) phase = PhConfirm;
        (void)now;
    }

    void enter_transfer() {
        if (sent_confirm && got_confirm && phase < PhXfer) {
            phase = PhXfer;
            log_init();
        }
    }

    Slot* slot_for(uint64_t seq) { return &slots[seq % static_cast<uint64_t>(opt.window)]; }

    int inflight_pkts() const {
        int n = 0;
        for (int i = 0; i < opt.window; ++i)
            if (slots[i].used && !slots[i].acked) ++n;
        return n;
    }

    void note_seq_received(uint64_t seq) {
        if (seq == 0) return;
        /* A retransmission of a sequence we already accepted means the ACK that
         * moved cum_ack was lost. Refresh it; ignoring the duplicate leaves the
         * sender retrying a packet we will never acknowledge again. */
        if (seq <= cum_ack) {
            ack_needed = true;
            return;
        }
        if (seq - cum_ack >= static_cast<uint64_t>(opt.window)) return;
        got_seq[seq % static_cast<uint64_t>(opt.window)] = true;
        if (seq > highest_seq) highest_seq = seq;
        while (got_seq[(cum_ack + 1) % static_cast<uint64_t>(opt.window)]) {
            got_seq[(cum_ack + 1) % static_cast<uint64_t>(opt.window)] = false;
            ++cum_ack;
        }
        ack_needed = true;
    }

    uint64_t sack_word(int word) const {
        uint64_t bits = 0;
        uint64_t base = cum_ack + 1 + static_cast<uint64_t>(word) * 64ull;
        for (int i = 0; i < 64; ++i) {
            uint64_t s = base + static_cast<uint64_t>(i);
            if (s <= cum_ack || s - cum_ack >= static_cast<uint64_t>(opt.window)) break;
            if (got_seq[s % static_cast<uint64_t>(opt.window)]) bits |= (1ull << i);
        }
        return bits;
    }

    uint64_t sack_bits() const { return sack_word(0); }

    void queue_ack(uint64_t now) {
        if (!keys || !peer_locked) return;
        Header h;
        h.type = kAck;
        h.seq = tx_seq++;
        h.ack = cum_ack;
        h.sack = sack_bits();
        h.timestamp_us = now;
        h.conn_id = conn;
        uint8_t body[32];
        for (int w = 0; w < 4; ++w) store_be64(body + w * 8, sack_word(w + 1));
        uint8_t pkt[128];
        uint16_t len = 0;
        if (!seal(pkt, &len, h, body, sizeof(body))) return;
        enqueue(pkt, len, peer);
        last_ack_us = now;
        ack_needed = false;
    }

    void accept_peer(Endpoint from) {
        peer = from;
        peer_locked = true;
    }

    bool cookie_ok(const uint8_t* c) const {
        if (!opt.have_cookie) return true;
        return ct_equal(c, opt.cookie, 16);
    }

    void on_hello(const uint8_t* payload, size_t len, const uint8_t* raw, size_t raw_len, Endpoint from, bool ack,
                  uint64_t now) {
        PeerView view;
        if (!decode_hello(payload, len, view)) {
            fail("bad hello");
            return;
        }
        if (view.hs_version != kHsVersion) {
            fail("unsupported handshake version");
            return;
        }
        if (opt.have_expect_pub && !ct_equal(view.pubkey, opt.expect_pub, 32)) {
            fail("peer key mismatch");
            return;
        }
        remote = view;
        have_remote = true;
        if (!sender && view.file_size) opt.file_size = view.file_size;
        accept_peer(from);
        if (enable_dht && from.port) {
            DhtNode dn;
            std::memcpy(dn.id, view.node_id, 16);
            dn.addr = from.addr_be;
            dn.port = from.port;
            dn.rtt_us = 1000;
            dn.used = true;
            if (dht.insert(dn)) log_dht(dn);
        }
        if (!sender) conn = load_be32(raw + 8);
        if (!ack) {
            if (raw_len > sizeof(hello_raw)) return;
            std::memcpy(hello_raw, raw, raw_len);
            hello_raw_len = static_cast<uint16_t>(raw_len);
            have_hello_raw = true;
            derive(false);
            if (!have_ack_raw && (negotiated & kFeatResume) && resume_fn && view.file_size) {
                uint16_t peer_chunk = 0;
                uint64_t ignored = 0;
                hello_read_tail(payload, len, &peer_chunk, &ignored);
                int align = peer_chunk > 0 ? peer_chunk : chunk;
                uint64_t off = resume_fn(resume_user, view.file_name, view.file_size, align, &Impl::absorb_cb, this);
                if (align > 0 && off % static_cast<uint64_t>(align) == 0 && off <= view.file_size) {
                    resume_off = off;
                    expect_off = off;
                    this->payload = off;
                    if (peer_chunk > 0) {
                        chunk = peer_chunk;
                        chunk_locked = true;
                    }
                } else {
                    resume_off = 0;
                }
            }
            build_hello_packet();
            if (hello_len > sizeof(ack_raw)) return;
            std::memcpy(ack_raw, hello_pkt, hello_len);
            ack_raw_len = hello_len;
            have_ack_raw = true;
            compute_transcript();
            fanout(hello_pkt, hello_len);
            queue_confirm(now);
        } else {
            if (raw_len > sizeof(ack_raw)) return;
            std::memcpy(ack_raw, raw, raw_len);
            ack_raw_len = static_cast<uint16_t>(raw_len);
            have_ack_raw = true;
            derive(true);
            if ((negotiated & kFeatResume) && resume_off == 0) {
                uint16_t peer_chunk = 0;
                uint64_t off = 0;
                hello_read_tail(payload, len, &peer_chunk, &off);
                if (off > 0 && chunk > 0 && (opt.file_size == 0 || off <= opt.file_size) &&
                    off % static_cast<uint64_t>(chunk) == 0) {
                    if (!absorb_prefix(off)) {
                        fail("resume read");
                        return;
                    }
                }
            }
            compute_transcript();
            queue_confirm(now);
        }
        enter_transfer();
    }

    void on_confirm(const Header& h, const uint8_t* packet, uint64_t now) {
        uint8_t plain[64];
        size_t plen = 0;
        if (!open(plain, &plen, h, packet) || plen != 32 || !have_transcript || !ct_equal(plain, transcript, 32)) {
            fail("handshake confirm failed");
            return;
        }
        got_confirm = true;
        enter_transfer();
        (void)now;
    }

    bool fin_seen = false;
    uint64_t fin_size = 0;
    uint64_t fin_seq_rx = 0;
    uint8_t fin_hash[32]{};

    void flush_reorder() {
        if (!write_fn) return;
        while (expect_off % static_cast<uint64_t>(chunk) == 0) {
            uint64_t eidx = expect_off / static_cast<uint64_t>(chunk);
            Rb& cur = reorder[eidx % kSlots];
            if (!cur.have) break;
            if (write_fn(io_user, cur.data, cur.len) != cur.len) {
                fail("write failed");
                return;
            }
            sha.update(cur.data, cur.len);
            payload += cur.len;
            uint16_t n = cur.len;
            expect_off += n;
            cur.have = false;
            cur.len = 0;
            if (n != static_cast<uint16_t>(chunk)) break;
        }
        finish_if_ready(0);
    }

    void finish_if_ready(uint64_t now) {
        if (!fin_seen || phase == PhDone || phase == PhFail) return;
        if (expect_off != fin_size) return;
        if (!sha_done) {
            sha.final(file_hash);
            sha_done = true;
        }
        if (!ct_equal(file_hash, fin_hash, 32)) {
            fail("checksum mismatch");
            return;
        }
        Header ah;
        ah.type = kFinAck;
        ah.seq = tx_seq++;
        ah.ack = fin_seq_rx;
        ah.timestamp_us = now;
        ah.conn_id = conn;
        uint8_t pkt[128];
        uint16_t len = 0;
        uint8_t dummy = 0;
        if (keys && peer_locked && seal(pkt, &len, ah, &dummy, 0)) enqueue(pkt, len, peer);
        phase = PhDone;
    }

    void insert_file_bytes(uint64_t offset, const uint8_t* bytes, uint16_t nbytes) {
        if (!write_fn || nbytes > 1400) return;
        if (offset < expect_off) return;
        if (offset % static_cast<uint64_t>(chunk) != 0) return;
        uint64_t idx = offset / static_cast<uint64_t>(chunk);
        uint64_t expect_idx = expect_off / static_cast<uint64_t>(chunk);
        if (idx >= expect_idx + static_cast<uint64_t>(kSlots)) return;
        Rb& rb = reorder[idx % kSlots];
        if (!rb.have) {
            std::memcpy(rb.data, bytes, nbytes);
            rb.len = nbytes;
            rb.have = true;
        }
        flush_reorder();
    }

    void deliver_data_plain(const uint8_t* plain, size_t plen, uint64_t seq) {
        if (plen < kPrefix) return;
        uint64_t offset = load_be64(plain);
        uint32_t gid = load_be32(plain + 8);
        uint8_t index = plain[12];
        uint8_t k = plain[13];
        uint8_t r = plain[14];
        uint16_t nbytes = load_be16(plain + 16);
        if (static_cast<size_t>(kPrefix + nbytes) > plen || index >= kFecMaxData) return;
        /* The stride is the sender's chunk, which follows its MSS, not ours.
         * The first block is a full chunk (or the whole file). Later blocks are
         * acknowledged only after they land on that stride, so a peer with a
         * different profile cannot ACK bytes it dropped. */
        if (!chunk_locked) {
            if (offset != 0 || nbytes == 0) return;
            chunk = nbytes;
            chunk_locked = true;
        }
        /* Bytes already flushed still need a duplicate ACK, or a lost ACK makes
         * the sender burn its retransmit budget. Bytes before the resume point
         * were never stored, so acknowledging them would skip a hole. */
        if (offset < resume_off) return;
        if (offset < expect_off) {
            note_seq_received(seq);
            return;
        }
        if (offset % static_cast<uint64_t>(chunk) != 0) return;
        note_seq_received(seq);
        insert_file_bytes(offset, plain + kPrefix, nbytes);
        if (!use_fec) return;
        Group* g = nullptr;
        for (auto& gr : groups)
            if (gr.used && gr.id == gid) g = &gr;
        if (!g) {
            for (auto& gr : groups)
                if (!gr.used) {
                    g = &gr;
                    break;
                }
            if (!g) g = &groups[gid % 8];
            if (g->used && g->id != gid) {
                *g = Group{};
            }
            g->used = true;
            g->id = gid;
            g->k = k ? k : opt.fec_k;
            g->r = r ? r : opt.fec_r;
            g->block = plain_mss;
            g->base_seq = seq - index;
        }
        if (index < g->k || index < kFecMaxData) {
            std::memset(g->data[index], 0, plain_mss);
            size_t copy = plen < static_cast<size_t>(plain_mss) ? plen : static_cast<size_t>(plain_mss);
            std::memcpy(g->data[index], plain, copy);
            g->have_d[index] = 1;
            if (index == 0) g->base_seq = seq;
        }
        (void)k;
        (void)r;
    }

    void try_recover(Group& g) {
        if (!g.used || g.k < 1) return;
        int miss = 0;
        for (int j = 0; j < g.k; ++j)
            if (!g.have_d[j]) ++miss;
        if (miss == 0) return;
        uint8_t* dp[kFecMaxData];
        const uint8_t* pp[kFecMaxParity];
        for (int j = 0; j < g.k; ++j) dp[j] = g.data[j];
        for (int i = 0; i < g.r; ++i) pp[i] = g.par[i];
        if (!fec_recover(dp, pp, g.have_d, g.have_p, g.k, g.r, g.block)) return;
        for (int j = 0; j < g.k; ++j) {
            if (g.have_d[j]) continue;
            g.have_d[j] = 1;
            ++fec_recovered;
            uint64_t seq = g.base_seq + static_cast<uint64_t>(j);
            deliver_data_plain(g.data[j], static_cast<size_t>(g.block), seq);
        }
    }

    void on_fec(const uint8_t* plain, size_t plen) {
        if (plen < 18) return;
        uint32_t gid = load_be32(plain);
        uint64_t base = load_be64(plain + 4);
        int k = plain[12];
        int r = plain[13];
        int index = plain[14];
        uint16_t block = load_be16(plain + 16);
        if (k < 1 || k > kFecMaxData || r < 1 || index >= r || index >= kFecMaxParity) return;
        if (18u + block > plen || block > 1400) return;
        Group* g = nullptr;
        for (auto& gr : groups)
            if (gr.used && gr.id == gid) g = &gr;
        if (!g) {
            for (auto& gr : groups)
                if (!gr.used) {
                    g = &gr;
                    break;
                }
            if (!g) return;
            *g = Group{};
            g->used = true;
            g->id = gid;
        }
        g->k = k;
        g->r = r;
        g->block = block;
        g->base_seq = base;
        std::memcpy(g->par[index], plain + 18, block);
        g->have_p[index] = 1;
        try_recover(*g);
    }

    void on_fin(const uint8_t* plain, size_t plen, const Header& h, uint64_t now) {
        note_seq_received(h.seq);
        if (plen < 40) return;
        fin_seen = true;
        fin_size = load_be64(plain);
        fin_seq_rx = h.seq;
        std::memcpy(fin_hash, plain + 8, 32);
        opt.file_size = fin_size;
        finish_if_ready(now);
    }

    void touch_hole(uint64_t now) {
        if (highest_seq > cum_ack) {
            if (!hole_since) hole_since = now;
        } else {
            hole_since = 0;
        }
    }

    void stash_data(const uint8_t* plain, size_t plen, uint64_t seq, uint64_t now) {
        if (plen == 0 || plen > 1400) return;
        for (auto& h : held)
            if (h.used && h.seq == seq) return;
        for (auto& h : held) {
            if (h.used) continue;
            h.used = true;
            h.seq = seq;
            h.in_us = now;
            h.len = static_cast<uint16_t>(plen);
            std::memcpy(h.plain, plain, plen);
            return;
        }
        /* The hold queue is full. Deliver now so the reorder buffer keeps the bytes. */
        deliver_data_plain(plain, plen, seq);
    }

    void release_ordered(uint64_t now) {
        bool progressed = true;
        while (progressed) {
            progressed = false;
            for (auto& h : held) {
                if (!h.used || h.seq > cum_ack + 1) continue;
                deliver_data_plain(h.plain, h.len, h.seq);
                h.used = false;
                progressed = true;
            }
        }
        touch_hole(now);
    }

    void flush_aged(uint64_t now) {
        uint64_t hold = jitter_hold_us(jitter.jitter_us, link_kind, opt.jitter_ms);
        for (auto& h : held) {
            if (!h.used || now < h.in_us + hold) continue;
            deliver_data_plain(h.plain, h.len, h.seq);
            h.used = false;
        }
        release_ordered(now);
    }

    void maybe_nack(uint64_t now) {
        if (sender || !use_nack || !peer_locked || !keys || !hole_since || highest_seq <= cum_ack) return;
        uint64_t hold = jitter_hold_us(jitter.jitter_us, link_kind, opt.jitter_ms);
        if (now < hole_since + hold) return;
        if (last_nack_us && now < last_nack_us + hold) return;
        uint8_t body[2 + 8 * 8];
        int n = 0;
        for (uint64_t seq = cum_ack + 1; n < 8 && seq <= highest_seq && seq - cum_ack < static_cast<uint64_t>(opt.window);
             ++seq) {
            if (got_seq[seq % static_cast<uint64_t>(opt.window)]) continue;
            store_be64(body + 2 + n * 8, seq);
            ++n;
        }
        if (!n) {
            hole_since = 0;
            return;
        }
        store_be16(body, static_cast<uint16_t>(n));
        Header h;
        h.type = kNack;
        h.seq = tx_seq++;
        h.ack = cum_ack;
        h.sack = sack_bits();
        h.timestamp_us = now;
        h.conn_id = conn;
        uint8_t pkt[160];
        uint16_t len = 0;
        if (!seal(pkt, &len, h, body, static_cast<size_t>(2 + n * 8))) return;
        if (!enqueue(pkt, len, peer)) return;
        ++nack_tx_pkts;
        nack_tx_bytes += len;
        nacks_sent += static_cast<uint64_t>(n);
        last_nack_us = now;
    }

    int alive_routes() const {
        int n = 0;
        for (int i = 0; i < nroutes; ++i)
            if (routes[i].alive) ++n;
        return n;
    }

    int pick_route(uint32_t salt) const {
        int live[8];
        int n = 0;
        for (int i = 0; i < nroutes; ++i)
            if (routes[i].alive) live[n++] = i;
        if (!n) return -1;
        return live[salt % static_cast<uint32_t>(n)];
    }

    Endpoint dest_for(const Slot& s) const {
        if (s.route >= 0 && s.route < nroutes && routes[s.route].alive) return routes[s.route].ep;
        if (peer_locked && peer.port) return peer;
        if (nroutes) return routes[0].ep;
        if (ncand) return cands[0];
        return peer;
    }

    void log_dht(const DhtNode& node) {
        if (log_verbose() < 1 || !node.port) return;
        char id[33];
        to_hex(node.id, 16, id);
        uint32_t a = node.addr;
        logf(1, "dht %s %s %u.%u.%u.%u:%u rtt_us=%u", dht_proximity(dht.self, node) ? "near" : "far", id,
             (a >> 24) & 255, (a >> 16) & 255, (a >> 8) & 255, a & 255, node.port, node.rtt_us);
    }

    void on_dht(const uint8_t* data, size_t len, Endpoint from, uint64_t now) {
        (void)now;
        if (!enable_dht) return;
        DhtMessage msg;
        if (!dht_decode(data, len, msg)) return;
        DhtNode who;
        std::memcpy(who.id, msg.sender, 16);
        who.addr = from.addr_be;
        who.port = from.port;
        who.used = from.port != 0;
        if (dht.insert(who)) log_dht(who);
        for (int i = 0; i < msg.count; ++i)
            if (dht.insert(msg.nodes[i])) log_dht(msg.nodes[i]);
        if (msg.type != kDhtPing && msg.type != kDhtFind) return;
        DhtMessage reply;
        reply.type = kDhtNodes;
        std::memcpy(reply.sender, dht.self, 16);
        std::memcpy(reply.target, msg.target, 16);
        DhtNode found[kDhtK];
        const uint8_t* target = msg.target;
        bool zero = true;
        for (int i = 0; i < 16; ++i)
            if (msg.target[i]) zero = false;
        if (zero) target = msg.sender;
        int n = dht.closest(target, found, kDhtK);
        reply.count = static_cast<uint8_t>(n);
        for (int i = 0; i < n; ++i) reply.nodes[i] = found[i];
        uint8_t pkt[512];
        size_t nlen = dht_encode(pkt, sizeof(pkt), reply);
        if (nlen) enqueue(pkt, static_cast<uint16_t>(nlen), from);
    }

    void handle_packet(const uint8_t* data, size_t len, Endpoint from, uint64_t now) {
        Header h;
        if (!decode_header(data, len, h)) return;
        if (h.version != kProtoVersion) return;
        rx_bytes += len;
        ++pkts_rx;
        last_rx_us = now;
        const uint8_t* payload = data + kHeaderBytes + h.ext_len;
        jitter.observe(h.timestamp_us, now);
        if (h.type == kPing) {
            if (h.payload_len < 32 || !cookie_ok(payload)) return;
            accept_peer(from);
            Header p;
            p.type = kPong;
            p.seq = 0;
            p.conn_id = h.conn_id ? h.conn_id : conn;
            p.timestamp_us = now;
            p.payload_len = 32;
            p.version = kProtoVersion;
            uint8_t pkt[80];
            encode_header(pkt, sizeof(pkt), p);
            std::memcpy(pkt + kHeaderBytes, payload, 32);
            enqueue(pkt, static_cast<uint16_t>(kHeaderBytes + 32), from);
            return;
        }
        if (h.type == kPong) {
            if (h.payload_len < 16 || !cookie_ok(payload)) return;
            accept_peer(from);
            if (sender && phase <= PhHello) queue_hello(now);
            return;
        }
        if (h.type == kHello || h.type == kHelloAck) {
            on_hello(payload, h.payload_len, data, kHeaderBytes + h.ext_len + h.payload_len, from, h.type == kHelloAck, now);
            return;
        }
        if (conn && h.conn_id != conn) return;
        if (h.type == kKeyConfirm) {
            accept_peer(from);
            on_confirm(h, data, now);
            return;
        }
        if (!keys || !got_confirm) return;
        accept_peer(from);
        if (h.type == kAck || h.type == kFinAck) {
            uint8_t plain[64];
            size_t plen = 0;
            if (!open(plain, &plen, h, data)) return;
            on_ack(h, plain, plen, now);
            if (h.type == kFinAck && fin_sent && h.ack == fin_seq) phase = PhDone;
            return;
        }
        if (h.type == kNack) {
            ++nack_rx_pkts;
            nack_rx_bytes += len;
            uint8_t plain[200];
            size_t plen = 0;
            if (!open(plain, &plen, h, data) || plen < 2) return;
            uint16_t n = load_be16(plain);
            size_t o = 2;
            for (uint16_t i = 0; i < n && o + 8 <= plen; ++i, o += 8) {
                uint64_t seq = load_be64(plain + o);
                Slot* s = slot_for(seq);
                if (s->used && s->seq == seq && !s->acked && s->sends <= 1) {
                    /* The first NACK can hurry one retransmission. Later NACKs
                     * leave the retransmission timer alone, so a NACK stream
                     * cannot spend the send budget in one RTT. */
                    uint64_t gap = bbr.min_rtt_us();
                    if (gap < 20000) gap = 20000;
                    if (s->sent_us == 0 || now >= s->sent_us + gap) s->sent_us = 0;
                }
            }
            return;
        }
        if (h.type == kData || h.type == kFec || h.type == kFin || h.type == kPeerUpdate || h.type == kGossip) {
            uint8_t plain[1400];
            size_t plen = 0;
            if (!open(plain, &plen, h, data)) return;
            if (h.ack) on_ack(h, nullptr, 0, now);
            if (h.type == kData) {
                if (!sender && h.seq > cum_ack + 1) {
                    if (!hole_since) hole_since = now;
                    stash_data(plain, plen, h.seq, now);
                } else {
                    deliver_data_plain(plain, plen, h.seq);
                    release_ordered(now);
                }
            } else if (h.type == kFec) {
                ++fec_rx_pkts;
                fec_rx_bytes += len;
                on_fec(plain, plen);
            }
            else if (h.type == kFin) {
                if (!sender) on_fin(plain, plen, h, now);
            } else if (h.type == kPeerUpdate) {
                note_seq_received(h.seq);
                apply_peer_update(remote, plain, plen);
            } else if (h.type == kGossip) {
                note_seq_received(h.seq);
                mesh_apply_gossip(mesh, plain, plen, node_id);
            }
        }
    }

    void on_ack(const Header& h, const uint8_t* extra, size_t extra_len, uint64_t now) {
        auto mark = [&](uint64_t seq) {
            if (seq == 0) return;
            Slot* s = slot_for(seq);
            if (!s->used || s->seq != seq || s->acked) return;
            s->acked = true;
            if (s->is_data && s->plain_len >= kPrefix)
                acked_payload += static_cast<uint64_t>(s->plain_len - kPrefix);
            bbr.on_ack(seq, s->wire_len ? s->wire_len : s->plain_len, now);
        };
        for (int i = 0; i < opt.window; ++i) {
            Slot& s = slots[i];
            if (!s.used || s.acked) continue;
            if (s.seq <= h.ack) mark(s.seq);
            else if (s.seq > h.ack && s.seq <= h.ack + 64) {
                uint64_t bit = s.seq - h.ack - 1;
                if ((h.sack & (1ull << bit))) mark(s.seq);
            }
        }
        if (extra && extra_len >= 8) {
            size_t words = extra_len / 8;
            if (words > 4) words = 4;
            for (size_t w = 0; w < words; ++w) {
                uint64_t bits = load_be64(extra + w * 8);
                uint64_t base = h.ack + 65 + w * 64;
                for (int b = 0; b < 64; ++b) {
                    if (bits & (1ull << b)) mark(base + static_cast<uint64_t>(b));
                }
            }
        }
        if (fin_sent && fin_seq && fin_seq <= h.ack) phase = PhDone;
    }

    bool send_wire(Slot& s, uint64_t now) {
        Header h;
        h.type = s.is_fin ? kFin : (s.is_fec ? kFec : kData);
        h.seq = s.seq;
        h.ack = cum_ack;
        h.sack = sack_bits();
        h.timestamp_us = now;
        h.conn_id = conn;
        uint16_t len = 0;
        if (!seal(s.wire, &len, h, s.plain, s.plain_len)) return false;
        s.wire_len = len;
        s.sent_us = now;
        s.sends++;
        if (!enqueue(s.wire, len, dest_for(s))) return false;
        bbr.on_sent(s.seq, len, now);
        uint64_t rate = bbr.pacing_bps();
        if (!rate) rate = 1;
        next_send_us += (static_cast<uint64_t>(len) * 1000000ull) / rate;
        if (next_send_us < now) next_send_us = now;
        return true;
    }

    bool pump_retx(uint64_t now) {
        uint64_t rtt = bbr.min_rtt_us();
        int best = -1;
        uint64_t best_seq = ~0ull;
        for (int i = 0; i < opt.window; ++i) {
            Slot& s = slots[i];
            if (!s.used || s.acked) continue;
            if (s.is_fec && s.sends >= 2) {
                s.acked = true;
                continue;
            }
            uint64_t rto = rtt ? rtt * 3 : 50000;
            rto += jitter.jitter_us;
            if (rto < 20000) rto = 20000;
            int shift = s.sends > 4 ? 4 : s.sends;
            rto <<= shift;
            if (!use_nack && link_kind == 3) {
                uint64_t hold = jitter_hold_us(jitter.jitter_us, link_kind, opt.jitter_ms);
                if (rto < hold) rto = hold;
            }
            if (rto > 1000000) rto = 1000000;
            if (now < s.sent_us + rto && s.sent_us != 0) continue;
            if (s.route >= 0 && alive_routes() > 1 && s.sends >= 4) {
                int alt = pick_route(static_cast<uint32_t>(s.route + 1 + s.sends));
                if (alt >= 0 && alt != s.route) {
                    routes[s.route].fails++;
                    if (routes[s.route].fails >= 3) routes[s.route].alive = false;
                    s.route = alt;
                    s.sends = 0;
                    s.sent_us = 0;
                    s.loss_marked = false;
                }
            }
            if (s.sends > 128) {
                fail("too many retransmits");
                return false;
            }
            if (s.seq < best_seq) {
                best = i;
                best_seq = s.seq;
            }
        }
        if (best < 0) return false;
        Slot& s = slots[best];
        if (!s.loss_marked && s.sends > 0) {
            bbr.on_loss(s.wire_len ? s.wire_len : plain_mss, now);
            s.loss_marked = true;
            ++retx_count;
        }
        if (qcount() > kOutQ - 4) return false;
        return send_wire(s, now);
    }

    void send_fec_parity(const uint8_t* plain, uint16_t plain_len, uint64_t now) {
        uint8_t pkt[1500];
        Header h;
        h.type = kFec;
        h.seq = fec_seq++;
        h.ack = cum_ack;
        h.sack = sack_bits();
        h.timestamp_us = now;
        h.conn_id = conn;
        uint16_t len = 0;
        if (!seal(pkt, &len, h, plain, plain_len)) return;
        Endpoint to = peer_locked ? peer : (ncand ? cands[0] : peer);
        /* Two copies. Parity is not retransmitted; a single loss must not be fatal. */
        if (enqueue(pkt, len, to)) {
            ++fec_tx_pkts;
            fec_tx_bytes += len;
        }
        if (enqueue(pkt, len, to)) {
            ++fec_tx_pkts;
            fec_tx_bytes += len;
        }
        uint64_t rate = bbr.pacing_bps();
        if (!rate) rate = 1;
        next_send_us += (static_cast<uint64_t>(len) * 2ull * 1000000ull) / rate;
        if (next_send_us < now) next_send_us = now;
    }

    void close_group(uint64_t now) {
        if (group_n <= 0) return;
        if (use_fec && qcount() + opt.fec_r * 2 < kOutQ - 4) {
            const uint8_t* ptrs[kFecMaxData];
            uint8_t parity[kFecMaxParity][1400];
            uint8_t* pptrs[kFecMaxParity];
            for (int j = 0; j < group_n; ++j) ptrs[j] = group_plain[j];
            for (int i = 0; i < opt.fec_r; ++i) pptrs[i] = parity[i];
            if (fec_encode(ptrs, group_n, opt.fec_r, plain_mss, pptrs)) {
                for (int i = 0; i < opt.fec_r; ++i) {
                    uint8_t body[1400];
                    store_be32(body, group_id);
                    store_be64(body + 4, group_base);
                    body[12] = static_cast<uint8_t>(group_n);
                    body[13] = static_cast<uint8_t>(opt.fec_r);
                    body[14] = static_cast<uint8_t>(i);
                    body[15] = 0;
                    store_be16(body + 16, static_cast<uint16_t>(plain_mss));
                    std::memcpy(body + 18, parity[i], static_cast<size_t>(plain_mss));
                    send_fec_parity(body, static_cast<uint16_t>(18 + plain_mss), now);
                }
            }
        }
        group_n = 0;
        group_index = 0;
        ++group_id;
    }

    bool pump_new(uint64_t now) {
        if (eof) return false;
        if (inflight_pkts() + 2 >= opt.window) return false;
        /* Reserve the sequence slot before touching the file. seq % window can
         * still name an unacked packet while other slots are free (SACK moved
         * the window around a hole). Reading first would drop those bytes. */
        uint64_t seq = tx_seq;
        Slot* s = slot_for(seq);
        if (s->used && !s->acked) return false;
        if (!read_fn) {
            eof = true;
            return false;
        }
        uint8_t buf[1400];
        int n = read_fn(io_user, buf, chunk);
        if (n < 0) {
            fail("read failed");
            return false;
        }
        if (n == 0) {
            eof = true;
            close_group(now);
            sha_done = false;
            return false;
        }
        ++tx_seq;
        sha.update(buf, static_cast<size_t>(n));
        if (group_n == 0) group_base = seq;
        *s = Slot{};
        s->used = true;
        s->is_data = true;
        s->seq = seq;
        s->group = group_id;
        s->route = pick_route(group_id);
        uint8_t* p = s->plain;
        store_be64(p, file_off);
        store_be32(p + 8, group_id);
        p[12] = static_cast<uint8_t>(group_index);
        p[13] = static_cast<uint8_t>(opt.fec_k);
        p[14] = static_cast<uint8_t>(opt.fec_r);
        p[15] = 0;
        store_be16(p + 16, static_cast<uint16_t>(n));
        std::memcpy(p + kPrefix, buf, static_cast<size_t>(n));
        s->plain_len = static_cast<uint16_t>(kPrefix + n);
        std::memset(group_plain[group_index], 0, plain_mss);
        std::memcpy(group_plain[group_index], s->plain, s->plain_len);
        group_len[group_index] = s->plain_len;
        file_off += static_cast<uint64_t>(n);
        ++group_index;
        ++group_n;
        if (group_n >= opt.fec_k) close_group(now);
        return send_wire(*s, now);
    }

    void pump_fin(uint64_t now) {
        if (!eof || fin_sent) return;
        for (int i = 0; i < opt.window; ++i) {
            if (slots[i].used && slots[i].is_data && !slots[i].acked) return;
        }
        if (!sha_done) {
            sha.final(file_hash);
            sha_done = true;
        }
        uint64_t seq = tx_seq;
        Slot* s = slot_for(seq);
        if (s->used && !s->acked) return;
        ++tx_seq;
        *s = Slot{};
        s->used = true;
        s->is_fin = true;
        s->seq = seq;
        store_be64(s->plain, file_off);
        std::memcpy(s->plain + 8, file_hash, 32);
        uint16_t namelen = 0;
        while (opt.file_name[namelen] && namelen < 200) ++namelen;
        store_be16(s->plain + 40, namelen);
        std::memcpy(s->plain + 42, opt.file_name, namelen);
        s->plain_len = static_cast<uint16_t>(42 + namelen);
        fin_seq = seq;
        fin_sent = true;
        phase = PhFin;
        send_wire(*s, now);
    }

    void tick(uint64_t now) {
        if (phase == PhDone || phase == PhFail) {
            log_end(now);
            return;
        }
        bbr.tick(now);
        if (sender && phase <= PhHello && (last_hello_us == 0 || now - last_hello_us > 30000)) queue_hello(now);
        if (sender && sent_confirm && !got_confirm && phase <= PhConfirm && now - last_hello_us > 30000) queue_confirm(now);
        if (!sender && phase <= PhHello && hello_len && last_hello_us && now - last_hello_us > 30000) fanout(hello_pkt, hello_len);
        if (phase < PhXfer) return;
        if (!sender) {
            flush_aged(now);
            maybe_nack(now);
            if (peer_locked && (last_ack_us == 0 || now - last_ack_us > 50000)) ack_needed = true;
            if (ack_needed && peer_locked && (last_ack_us == 0 || now - last_ack_us > 200)) queue_ack(now);
            if (ack_needed) {
                if (next_send_us < now) next_send_us = now;
            } else if (next_send_us < now + 2000) {
                next_send_us = now + 2000;
            }
            return;
        }
        if (!peer_locked && ncand == 0) return;
        int budget = 128;
        while (budget-- && phase != PhFail && phase != PhDone) {
            if (next_send_us > now) break;
            if (qcount() > kOutQ - 4) break;
            uint64_t before = next_send_us;
            if (pump_retx(now)) continue;
            if (eof && !fin_sent) {
                pump_fin(now);
                break;
            }
            if (!pump_new(now)) break;
            if (next_send_us == before) break;
        }
        if (!sender && ack_needed && (last_ack_us == 0 || now - last_ack_us > 2000)) queue_ack(now);
        if (sender && eof && fin_sent && phase != PhDone) {
            /* FIN is a reliable slot; retx handles it. Completion is on FIN-ACK. */
        }
        if (phase == PhDone || phase == PhFail) log_end(now);
    }
};

Engine::Engine(const EngineOpts& opt, bool sender) : impl_(new Impl(opt, sender)) {}
Engine::~Engine() { delete impl_; }

void Engine::add_candidate(Endpoint ep) {
    if (impl_->ncand >= kMaxCandidates) return;
    impl_->cands[impl_->ncand++] = ep;
}

void Engine::add_route(Endpoint ep) {
    if (!ep.port || impl_->nroutes >= 8) return;
    for (int i = 0; i < impl_->nroutes; ++i) {
        if (impl_->routes[i].ep.addr_be == ep.addr_be && impl_->routes[i].ep.port == ep.port) return;
    }
    impl_->routes[impl_->nroutes].ep = ep;
    impl_->routes[impl_->nroutes].alive = true;
    impl_->nroutes++;
    add_candidate(ep);
}

void Engine::set_io(IoRead read, IoWrite write, void* user) {
    impl_->read_fn = read;
    impl_->write_fn = write;
    impl_->io_user = user;
}

void Engine::set_resume(ResumeFn fn, void* user) {
    impl_->resume_fn = fn;
    impl_->resume_user = user;
}

uint64_t Engine::resume_offset() const { return impl_->resume_off; }

void Engine::start(uint64_t now_us) {
    impl_->start_us = now_us;
    impl_->next_send_us = now_us;
    impl_->last_rx_us = now_us;
    if (impl_->sender) {
        uint8_t ping[kHeaderBytes + 32];
        Header h;
        h.type = kPing;
        h.version = kProtoVersion;
        h.conn_id = impl_->conn;
        h.timestamp_us = now_us;
        h.payload_len = 32;
        encode_header(ping, sizeof(ping), h);
        std::memcpy(ping + kHeaderBytes, impl_->opt.cookie, 16);
        std::memcpy(ping + kHeaderBytes + 16, impl_->node_id, 16);
        impl_->fanout(ping, static_cast<uint16_t>(sizeof(ping)));
        impl_->queue_hello(now_us);
        if (impl_->sender) {
            std::memcpy(impl_->hello_raw, impl_->hello_pkt, impl_->hello_len);
            impl_->hello_raw_len = impl_->hello_len;
            impl_->have_hello_raw = true;
        }
    }
}

void Engine::on_datagram(const uint8_t* data, size_t len, Endpoint from, uint64_t now_us) {
    if (len >= 4 && load_be32(data) == kDhtMagic) {
        impl_->on_dht(data, len, from, now_us);
        return;
    }
    impl_->handle_packet(data, len, from, now_us);
    impl_->log_end(now_us);
}

void Engine::tick(uint64_t now_us) { impl_->tick(now_us); }

bool Engine::pop(DatagramOut& out) {
    if (impl_->qh == impl_->qt) return false;
    out = impl_->outq[impl_->qh];
    impl_->qh = (impl_->qh + 1) % kOutQ;
    return true;
}

void Engine::push_front(const DatagramOut& out) {
    impl_->qh = (impl_->qh + kOutQ - 1) % kOutQ;
    impl_->outq[impl_->qh] = out;
}

bool Engine::done() const { return impl_->phase == PhDone || impl_->phase == PhFail; }
bool Engine::success() const { return impl_->phase == PhDone; }
const char* Engine::error() const { return impl_->err; }
uint64_t Engine::payload_done() const { return impl_->sender ? impl_->acked_payload : impl_->payload; }
uint64_t Engine::file_size() const {
    if (impl_->opt.file_size && impl_->opt.file_size != ~uint64_t{0}) return impl_->opt.file_size;
    return impl_->sender ? impl_->file_off : impl_->payload;
}
uint64_t Engine::pacing_bps() const { return impl_->bbr.pacing_bps(); }
uint64_t Engine::rate_bps(uint64_t now_us) const {
    uint64_t dt = now_us > impl_->start_us ? now_us - impl_->start_us : 1;
    return payload_done() * 1000000ull / dt;
}
uint64_t Engine::min_rtt_us() const { return impl_->bbr.min_rtt_us(); }
uint64_t Engine::next_wakeup_us() const { return impl_->next_send_us; }
int Engine::profile() const { return impl_->bbr.effective_profile(); }
int Engine::phase() const { return static_cast<int>(impl_->phase); }
uint32_t Engine::peer_features() const { return impl_->negotiated; }
int Engine::peer_handshake_version() const { return impl_->remote.hs_version; }
const char* Engine::peer_name() const { return impl_->remote.name; }
const char* Engine::peer_file_name() const { return impl_->remote.file_name; }
uint64_t Engine::retx() const { return impl_->retx_count; }
uint64_t Engine::fec_recovered() const { return impl_->fec_recovered; }
uint64_t Engine::wire_tx() const { return impl_->tx_bytes; }
uint64_t Engine::wire_rx() const { return impl_->rx_bytes; }
uint64_t Engine::jitter_us() const { return impl_->jitter.jitter_us; }
uint64_t Engine::nacks_sent() const { return impl_->nacks_sent; }
uint64_t Engine::packets_tx() const { return impl_->pkts_tx; }
uint64_t Engine::packets_rx() const { return impl_->pkts_rx; }
uint64_t Engine::fec_tx_packets() const { return impl_->fec_tx_pkts; }
uint64_t Engine::fec_rx_packets() const { return impl_->fec_rx_pkts; }
uint64_t Engine::nack_tx_packets() const { return impl_->nack_tx_pkts; }
uint64_t Engine::nack_rx_packets() const { return impl_->nack_rx_pkts; }
uint64_t Engine::fec_tx_bytes() const { return impl_->fec_tx_bytes; }
uint64_t Engine::nack_tx_bytes() const { return impl_->nack_tx_bytes; }
uint64_t Engine::started_us() const { return impl_->start_us; }
int Engine::link_kind() const { return impl_->link_kind; }
int Engine::fec_on() const { return impl_->use_fec ? 1 : 0; }
int Engine::nack_on() const { return impl_->use_nack ? 1 : 0; }
int Engine::routes_alive() const { return impl_->alive_routes(); }
int Engine::dht_peers() const { return impl_->dht.count(); }
void Engine::sha256_hex(char out[65]) const { to_hex(impl_->file_hash, 32, out); }

}  // namespace genesis
