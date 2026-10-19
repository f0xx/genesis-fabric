#include "bbr.hpp"
#include "crypto.hpp"
#include "dht.hpp"
#include "discovery.hpp"
#include "endian.hpp"
#include "engine.hpp"
#include "fec.hpp"
#include "genesis/api.h"
#include "handshake.hpp"
#include "jitter.hpp"
#include "link.hpp"
#include "mesh.hpp"
#include "ring.hpp"
#include "stun.hpp"
#include "util.hpp"
#include "wire.hpp"

#include <atomic>
#include <cstdio>
#include <cstring>
#include <string>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>
#include <vector>

namespace {

int g_fails = 0;

void fail(const char* what) {
    std::fprintf(stderr, "FAIL %s\n", what);
    ++g_fails;
}

void expect(bool cond, const char* what) {
    if (!cond) fail(what);
}

void expect_hex(const char* name, const uint8_t* got, size_t n, const char* hex) {
    uint8_t want[160];
    if (n > sizeof(want) || !genesis::from_hex(hex, want, n) || !genesis::ct_equal(got, want, n)) {
        std::fprintf(stderr, "FAIL %s\n got ", name);
        for (size_t i = 0; i < n; ++i) std::fprintf(stderr, "%02x", got[i]);
        std::fprintf(stderr, "\n");
        ++g_fails;
    }
}

void test_crypto() {
    uint8_t out[64];
    genesis::Sha256::hash(reinterpret_cast<const uint8_t*>("abc"), 3, out);
    expect_hex("sha256 abc", out, 32, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    genesis::Sha256::hash(reinterpret_cast<const uint8_t*>(""), 0, out);
    expect_hex("sha256 empty", out, 32, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    genesis::Sha1::hash(reinterpret_cast<const uint8_t*>("abc"), 3, out);
    expect_hex("sha1 abc", out, 20, "a9993e364706816aba3e25717850c26c9cd0d89d");
    genesis::Md5::hash(reinterpret_cast<const uint8_t*>(""), 0, out);
    expect_hex("md5 empty", out, 16, "d41d8cd98f00b204e9800998ecf8427e");
    genesis::Md5::hash(reinterpret_cast<const uint8_t*>("abc"), 3, out);
    expect_hex("md5 abc", out, 16, "900150983cd24fb0d6963f7d28e17f72");

    uint8_t ikm[22];
    for (int i = 0; i < 22; ++i) ikm[i] = 0x0b;
    uint8_t salt[13], info[10], okm[42];
    genesis::from_hex("000102030405060708090a0b0c", salt, 13);
    genesis::from_hex("f0f1f2f3f4f5f6f7f8f9", info, 10);
    expect(genesis::hkdf_sha256(ikm, 22, salt, 13, info, 10, okm, 42), "hkdf call");
    expect_hex("hkdf", okm, 42, "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865");

    uint8_t key[32], nonce[12]{}, block[64], zeros[64]{};
    for (int i = 0; i < 32; ++i) key[i] = static_cast<uint8_t>(i);
    nonce[7] = 0x4a;
    genesis::chacha20_xor(block, zeros, 64, key, nonce, 1);
    expect_hex("chacha", block, 64,
               "224f51f3401bd9e12fde276fb8631ded8c131f823d2c06e27e4fcaec9ef3cf788a3b0aa372600a92b57974cded2b9334794cba40c63e34cdea212c4cf07d41b7");

    uint8_t akey[32], anonce[12], aad[12], plain[114], cipher[140];
    genesis::from_hex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f", akey, 32);
    genesis::from_hex("070000004041424344454647", anonce, 12);
    genesis::from_hex("50515253c0c1c2c3c4c5c6c7", aad, 12);
    const char* poem =
        "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    std::memcpy(plain, poem, 114);
    size_t clen = 0;
    expect(genesis::aead_encrypt(cipher, sizeof(cipher), &clen, plain, 114, aad, 12, akey, anonce), "aead enc");
    expect(clen == 130, "aead len");
    expect_hex("aead", cipher, 130,
               "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b61161ae10b594f09e26a7e902ecbd0600691");
    uint8_t back[114];
    size_t plen = 0;
    cipher[20] ^= 1;
    expect(!genesis::aead_decrypt(back, sizeof(back), &plen, cipher, clen, aad, 12, akey, anonce), "aead tamper");
    cipher[20] ^= 1;
    expect(genesis::aead_decrypt(back, sizeof(back), &plen, cipher, clen, aad, 12, akey, anonce) && plen == 114 &&
               std::memcmp(back, plain, 114) == 0,
           "aead roundtrip");

    uint8_t alice_priv[32], bob_priv[32], alice_pub[32], bob_pub[32], s1[32], s2[32];
    genesis::from_hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a", alice_priv, 32);
    genesis::from_hex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb", bob_priv, 32);
    genesis::x25519_base(alice_pub, alice_priv);
    genesis::x25519_base(bob_pub, bob_priv);
    expect_hex("alice", alice_pub, 32, "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
    expect_hex("bob", bob_pub, 32, "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
    genesis::x25519(s1, alice_priv, bob_pub);
    genesis::x25519(s2, bob_priv, alice_pub);
    expect_hex("shared", s1, 32, "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
    expect(std::memcmp(s1, s2, 32) == 0, "shared match");
    expect(genesis::field_selftest() == 0, "field selftest");
}

void test_fec() {
    constexpr int k = 8, r = 2, block = 64;
    uint8_t data_store[k][block]{};
    uint8_t par_store[r][block]{};
    const uint8_t* data[k];
    uint8_t* data_mut[k];
    uint8_t* par_ptrs[r];
    const uint8_t* par[r];
    uint8_t have_d[k], have_p[r];
    for (int i = 0; i < k; ++i) {
        for (int j = 0; j < block; ++j) data_store[i][j] = static_cast<uint8_t>(i * 17 + j);
        data[i] = data_store[i];
        data_mut[i] = data_store[i];
        have_d[i] = 1;
    }
    for (int i = 0; i < r; ++i) {
        par_ptrs[i] = par_store[i];
        par[i] = par_store[i];
        have_p[i] = 1;
    }
    expect(genesis::fec_encode(data, k, r, block, par_ptrs), "fec encode");
    uint8_t xor_row[block]{};
    for (int i = 0; i < k; ++i)
        for (int j = 0; j < block; ++j) xor_row[j] = static_cast<uint8_t>(xor_row[j] ^ data_store[i][j]);
    expect(std::memcmp(xor_row, par_store[0], block) == 0, "parity0 is xor");
    std::memset(data_store[1], 0, block);
    std::memset(data_store[4], 0, block);
    have_d[1] = 0;
    have_d[4] = 0;
    expect(genesis::fec_recover(data_mut, par, have_d, have_p, k, r, block), "recover 2");
    for (int j = 0; j < block; ++j) {
        if (data_store[1][j] != static_cast<uint8_t>(1 * 17 + j) || data_store[4][j] != static_cast<uint8_t>(4 * 17 + j)) {
            fail("recovered bytes");
            break;
        }
    }
    std::memset(data_store[2], 0, block);
    have_d[2] = 0;
    expect(!genesis::fec_recover(data_mut, par, have_d, have_p, k, r, block), "3 erasures fail");
}

void test_wire() {
    genesis::Header h;
    h.version = 1;
    h.type = genesis::kData;
    h.flags = genesis::kFlagEncrypted;
    h.conn_id = 0x11223344;
    h.seq = 0x0102030405060708ull;
    h.ack = 2;
    h.sack = 0x8000000000000001ull;
    h.timestamp_us = 99;
    h.payload_len = 4;
    h.ext_len = 0;
    uint8_t buf[64]{};
    buf[48] = 1;
    buf[49] = 2;
    buf[50] = 3;
    buf[51] = 4;
    expect(genesis::encode_header(buf, sizeof(buf), h), "encode");
    expect(buf[0] == 'G' && buf[1] == 'C' && buf[2] == 'X' && buf[3] == '1', "magic ascii");
    expect(buf[12] == 0x01 && buf[19] == 0x08, "seq big endian");
    genesis::Header o;
    expect(genesis::decode_header(buf, 52, o), "decode");
    expect(o.seq == h.seq && o.ack == 2 && o.sack == h.sack && o.type == genesis::kData, "fields");
    buf[4] = 9;
    expect(!genesis::decode_header(buf, 52, o), "future version rejected");
}

void test_handshake() {
    genesis::PeerView a;
    a.features = genesis::kFeatFec | genesis::kFeatBbr | genesis::kFeatFile;
    a.profile = 1;
    a.udp_port = 37420;
    a.file_size = 123456;
    std::snprintf(a.name, sizeof(a.name), "alpha");
    std::snprintf(a.file_name, sizeof(a.file_name), "clip.bin");
    a.cand_count = 1;
    a.cand_kind[0] = 1;
    a.cand_addr[0][0] = 192;
    a.cand_addr[0][1] = 168;
    a.cand_addr[0][2] = 4;
    a.cand_addr[0][3] = 110;
    a.cand_port[0] = 9;
    for (int i = 0; i < 32; ++i) a.pubkey[i] = static_cast<uint8_t>(i + 1);
    uint8_t buf[512];
    size_t n = 0;
    expect(genesis::encode_hello(buf, sizeof(buf), &n, a) && n > 32, "hello encode");
    genesis::PeerView b;
    expect(genesis::decode_hello(buf, n, b), "hello decode");
    expect(b.hs_version == genesis::kHsVersion, "hs version");
    expect(b.features == a.features && b.udp_port == 37420 && b.file_size == 123456, "hello fields");
    expect(std::strcmp(b.file_name, "clip.bin") == 0, "file name");
    expect(b.cand_count == 1 && b.cand_port[0] == 9 && b.cand_addr[0][3] == 110, "candidate");
    buf[0] = 2;
    expect(!genesis::decode_hello(buf, n, b), "hs version 2 rejected");

    genesis::PeerView u = a;
    u.features = genesis::kFeatMesh;
    u.profile = 2;
    uint8_t upd[128];
    size_t un = genesis::encode_peer_update(upd, sizeof(upd), 1, u);
    expect(un > 0, "update encode");
    genesis::PeerView got = a;
    expect(genesis::apply_peer_update(got, upd, un), "update apply");
    expect(got.features == genesis::kFeatMesh && got.profile == 2 && got.update_seq == 1, "update fields");
    expect(!genesis::apply_peer_update(got, upd, un), "replay rejected");
    uint8_t junk[16]{};
    genesis::store_be64(junk, 5);
    junk[8] = 1;
    junk[9] = 7;
    junk[10] = 3;
    junk[11] = 1;
    junk[12] = 2;
    junk[13] = 3;
    expect(genesis::apply_peer_update(got, junk, 14), "unknown tlv skipped");
    expect(got.update_seq == 5 && got.profile == 2, "unknown tlv kept profile");
}

void test_stun() {
    uint8_t tid[12];
    for (int i = 0; i < 12; ++i) tid[i] = static_cast<uint8_t>(i + 3);
    uint8_t req[128];
    expect(genesis::stun_binding_request(req, sizeof(req), tid) == 20, "stun req");
    expect(req[0] == 0x00 && req[1] == 0x01, "binding type");
    expect(req[4] == 0x21 && req[5] == 0x12 && req[6] == 0xa4 && req[7] == 0x42, "cookie");

    uint8_t msg[64]{};
    msg[0] = 0x01;
    msg[1] = 0x01;
    msg[2] = 0x00;
    msg[3] = 12;
    msg[4] = 0x21;
    msg[5] = 0x12;
    msg[6] = 0xa4;
    msg[7] = 0x42;
    std::memcpy(msg + 8, tid, 12);
    msg[20] = 0x00;
    msg[21] = 0x20;
    msg[22] = 0x00;
    msg[23] = 8;
    msg[24] = 0x00;
    msg[25] = 0x01;
    uint16_t xport = static_cast<uint16_t>(20000 ^ 0x2112);
    msg[26] = static_cast<uint8_t>(xport >> 8);
    msg[27] = static_cast<uint8_t>(xport);
    uint32_t xip = 0xC0A8010Au ^ 0x2112A442u;
    msg[28] = static_cast<uint8_t>(xip >> 24);
    msg[29] = static_cast<uint8_t>(xip >> 16);
    msg[30] = static_cast<uint8_t>(xip >> 8);
    msg[31] = static_cast<uint8_t>(xip);
    genesis::StunResult parsed;
    expect(genesis::stun_parse_binding_response(msg, 32, tid, parsed) && parsed.ok, "xor mapped");
    expect(parsed.port == 20000 && parsed.addr[0] == 192 && parsed.addr[3] == 10, "mapped addr");

    uint8_t key[16];
    for (int i = 0; i < 16; ++i) key[i] = static_cast<uint8_t>(i);
    size_t len = 20;
    expect(genesis::stun_add_integrity_and_fingerprint(req, &len, sizeof(req), key, sizeof(key)), "mi");
    expect(genesis::stun_check_integrity(req, len, key, sizeof(key)), "mi check");
    req[30] ^= 0x01;
    expect(!genesis::stun_check_integrity(req, len, key, sizeof(key)), "mi tamper");
}

void test_mesh() {
    expect(genesis::mesh_metric(1000, 1000) == 1000, "metric");
    genesis::MeshTable t;
    uint8_t id[16]{};
    id[0] = 7;
    uint8_t self[16]{};
    self[0] = 1;
    genesis::mesh_observe(t, id, 2000, 10000, 50);
    uint8_t plain[256];
    size_t n = genesis::mesh_encode_gossip(t, plain, sizeof(plain), 50);
    expect(n > 18, "gossip");
    genesis::MeshTable o;
    expect(genesis::mesh_apply_gossip(o, plain, n, self), "apply");
    expect(!genesis::mesh_apply_gossip(o, plain, n, self), "gossip replay");
    uint8_t hop[16];
    uint32_t metric = 0;
    expect(genesis::mesh_best_hop(o, id, hop, &metric) && metric == genesis::mesh_metric(2000, 10000), "hop");
    genesis::mesh_observe(o, id, 100, 100000, 80);
    uint32_t before = 0;
    genesis::mesh_best_hop(o, id, hop, &before);
    genesis::MeshTable worse;
    genesis::mesh_observe(worse, id, 99999, 1, 90);
    uint8_t plain2[256];
    genesis::mesh_encode_gossip(worse, plain2, sizeof(plain2), 90);
    size_t n2 = genesis::mesh_encode_gossip(worse, plain2, sizeof(plain2), 90);
    expect(genesis::mesh_apply_gossip(o, plain2, n2, self), "worse gossip accepted by seq");
    uint32_t after = 0;
    genesis::mesh_best_hop(o, id, hop, &after);
    /* Direct observation is better, so a worse advertisement must not replace it.
     * apply returns true because the seq advanced, but the metric stays. */
    expect(after == before, "direct beats worse gossip");
}

void test_config_and_jail() {
    genesis_config cfg;
    genesis_config_init(&cfg);
    expect(cfg.fec_k == 8 && cfg.profile == GENESIS_PROFILE_AUTO, "defaults");
    const char* path = "tmp/unit_genesis.conf";
    mkdir("tmp", 0755);
    FILE* f = std::fopen(path, "w");
    if (!f) {
        fail("open config");
        return;
    }
    std::fputs("profile = CELLULAR_5G\n# comment\nfec_k = 8\nfec_r = 2\nbind_port = 41000\n", f);
    std::fclose(f);
    expect(genesis_config_load(&cfg, path) == GENESIS_OK, "load");
    expect(cfg.profile == GENESIS_PROFILE_CELLULAR && cfg.fec_r == 2 && cfg.bind_port == 41000, "loaded values");
    expect(genesis_config_set(&cfg, "nope", "1") == GENESIS_ERR_ARGS, "unknown key");

    char resolved[256];
    expect(genesis_path_is_safe("/var/genesis", "clip.bin", resolved, sizeof(resolved)) == GENESIS_OK, "safe");
    expect(std::strcmp(resolved, "/var/genesis/clip.bin") == 0, "joined");
    expect(genesis_path_is_safe("/var/genesis", "../etc/passwd", resolved, sizeof(resolved)) == GENESIS_ERR_JAIL, "dotdot");
    expect(genesis_path_is_safe("/var/genesis", "/etc/passwd", resolved, sizeof(resolved)) == GENESIS_ERR_JAIL, "absolute");
    expect(genesis_path_is_safe(".", "clip.bin", resolved, sizeof(resolved)) == GENESIS_OK, "relative root");
    char err[160];
    if (geteuid() != 0) {
        expect(genesis_jail_apply("/tmp", "nobody", err, sizeof(err)) == GENESIS_ERR_JAIL, "unprivileged jail fails closed");
        return;
    }
    /* As root the call really chroots and drops uid. Do that in a child so the
     * rest of this process, including the control-socket test, stays put. */
    expect(genesis_jail_apply("/tmp", "no-such-genesis-user", err, sizeof(err)) == GENESIS_ERR_JAIL,
           "unknown drop user fails closed");
    pid_t pid = fork();
    if (pid < 0) {
        fail("fork jail");
        return;
    }
    if (pid == 0) {
        int rc = genesis_jail_apply("/tmp", "nobody", err, sizeof(err));
        if (rc != GENESIS_OK) {
            std::fprintf(stderr, "root jail: %s\n", err);
            _exit(2);
        }
        if (geteuid() == 0 || setuid(0) == 0) _exit(3);
        _exit(0);
    }
    int status = 0;
    if (waitpid(pid, &status, 0) < 0 || !WIFEXITED(status) || WEXITSTATUS(status) != 0)
        fail("root jail drops privileges");
}

void test_ring() {
    genesis::SpscRing<uint32_t, 1024> ring;
    uint32_t dummy = 0;
    expect(!ring.pop(dummy), "empty pop");
    std::atomic<int> bad{0};
    constexpr uint32_t kN = 100000;
    std::thread prod([&] {
        for (uint32_t i = 0; i < kN; ++i)
            while (!ring.push(i)) {
            }
    });
    std::thread cons([&] {
        for (uint32_t i = 0; i < kN; ++i) {
            uint32_t v = 0;
            while (!ring.pop(v)) {
            }
            if (v != i) bad.store(1);
        }
    });
    prod.join();
    cons.join();
    expect(bad.load() == 0, "spsc threads");
}

void test_bbr() {
    genesis::Bbr b;
    b.reset(1200, 1);
    expect(b.pacing_bps() == 80000000ull && b.mode() == genesis::BbrMode::Startup, "gbe start");
    expect(b.pacing_gain() > 2.7 && b.pacing_gain() < 2.8, "startup gain");
    b.reset(1200, 2);
    expect(b.pacing_bps() == 5000000ull && b.pacing_gain() == 2.0, "cellular start");
    b.reset(1200, 1);
    b.on_sent(1, 1200, 1000);
    b.on_ack(1, 1200, 1000 + 1500);
    expect(b.min_rtt_us() == 1500, "min rtt");
    uint64_t floor = 1200ull * 4;
    expect(b.cwnd_bytes() >= floor, "cwnd floor");
    b.on_loss(1200, 5000);
    expect(b.mode() == genesis::BbrMode::Startup, "one loss stays in startup");
    for (int i = 0; i < 20; ++i) b.on_loss(1200, 6000 + static_cast<uint64_t>(i));
    expect(b.mode() == genesis::BbrMode::Drain, "sustained loss leaves startup");
}

struct Buf {
    std::vector<uint8_t> data;
    size_t off = 0;
};

int rd(void* u, uint8_t* d, int n) {
    auto* b = static_cast<Buf*>(u);
    if (b->off >= b->data.size()) return 0;
    size_t left = b->data.size() - b->off;
    if (static_cast<size_t>(n) < left) left = static_cast<size_t>(n);
    std::memcpy(d, b->data.data() + b->off, left);
    b->off += left;
    return static_cast<int>(left);
}

int wr(void* u, const uint8_t* d, int n) {
    auto* b = static_cast<Buf*>(u);
    b->data.insert(b->data.end(), d, d + n);
    return n;
}

bool xfer(genesis::Engine& tx, genesis::Engine& rx, int drop_mod, int steps) {
    uint64_t now = 1000;
    tx.start(now);
    rx.start(now);
    int serial = 0;
    auto pump = [&](genesis::Engine& a, genesis::Engine& b) {
        genesis::DatagramOut d;
        while (a.pop(d)) {
            ++serial;
            if (drop_mod && (serial % drop_mod) == 0) continue;
            genesis::Endpoint ep;
            ep.addr_be = d.addr_be ? d.addr_be : 0x7f000001u;
            ep.port = d.port ? d.port : 2;
            b.on_datagram(d.data, d.len, ep, now);
        }
    };
    for (int step = 0; step < steps && !(tx.success() && rx.success()); ++step) {
        tx.tick(now);
        rx.tick(now);
        pump(tx, rx);
        pump(rx, tx);
        now += 1000;
    }
    return tx.success() && rx.success();
}

void test_engine() {
    const int N = 200000;
    Buf src, dst;
    src.data.resize(static_cast<size_t>(N));
    for (int i = 0; i < N; ++i) src.data[static_cast<size_t>(i)] = static_cast<uint8_t>(i * 17 + 3);
    genesis::EngineOpts o;
    o.fec_k = 8;
    o.fec_r = 2;
    o.plain_mss = 1200;
    o.window = 128;
    o.file_size = static_cast<uint64_t>(N);
    std::snprintf(o.file_name, sizeof(o.file_name), "blob.bin");
    genesis::Engine tx(o, true);
    genesis::Engine rx(o, false);
    tx.add_candidate({0x7f000001u, 1});
    tx.set_io(rd, nullptr, &src);
    rx.set_io(nullptr, wr, &dst);
    expect(xfer(tx, rx, 0, 20000), "clean transfer");
    expect(dst.data == src.data, "clean bytes");

    src.off = 0;
    dst.data.clear();
    genesis::Engine tx2(o, true);
    genesis::Engine rx2(o, false);
    tx2.add_candidate({0x7f000001u, 1});
    tx2.set_io(rd, nullptr, &src);
    rx2.set_io(nullptr, wr, &dst);
    expect(xfer(tx2, rx2, 11, 40000), "lossy transfer");
    expect(dst.data == src.data, "lossy bytes");
    expect(rx2.fec_recovered() > 0 || tx2.retx() > 0, "loss recovered");

    /* Hold ACKs until the send window is full and a sequence slot is reused
     * under a hole, then release them. Bytes must not be skipped. */
    src.off = 0;
    dst.data.clear();
    genesis::Engine tx3(o, true);
    genesis::Engine rx3(o, false);
    tx3.add_candidate({0x7f000001u, 1});
    tx3.set_io(rd, nullptr, &src);
    rx3.set_io(nullptr, wr, &dst);
    {
        uint64_t now = 1000;
        tx3.start(now);
        rx3.start(now);
        std::vector<genesis::DatagramOut> held;
        bool release = false;
        for (int step = 0; step < 80000 && !(tx3.success() && rx3.success()); ++step) {
            tx3.tick(now);
            rx3.tick(now);
            genesis::DatagramOut d;
            while (tx3.pop(d)) rx3.on_datagram(d.data, d.len, {0x7f000001u, 2}, now);
            while (rx3.pop(d)) {
                if (!release) held.push_back(d);
                else tx3.on_datagram(d.data, d.len, {0x7f000001u, 1}, now);
            }
            if (!release && held.size() > static_cast<size_t>(o.window)) release = true;
            if (release) {
                for (auto& h : held) tx3.on_datagram(h.data, h.len, {0x7f000001u, 1}, now);
                held.clear();
            }
            now += 1000;
        }
    }
    expect(tx3.success() && rx3.success(), "delayed-ack transfer");
    expect(dst.data == src.data, "delayed-ack bytes");

    /* Drop every cumulative ACK until the sender retransmits. The receiver
     * already has those bytes, so only a duplicate-triggered ACK can finish. */
    src.off = 0;
    dst.data.clear();
    genesis::Engine tx4(o, true);
    genesis::Engine rx4(o, false);
    tx4.add_candidate({0x7f000001u, 1});
    tx4.set_io(rd, nullptr, &src);
    rx4.set_io(nullptr, wr, &dst);
    {
        uint64_t now = 1000;
        tx4.start(now);
        rx4.start(now);
        bool drop_acks = true;
        for (int step = 0; step < 80000 && !(tx4.success() && rx4.success()); ++step) {
            tx4.tick(now);
            rx4.tick(now);
            genesis::DatagramOut d;
            while (tx4.pop(d)) rx4.on_datagram(d.data, d.len, {0x7f000001u, 2}, now);
            while (rx4.pop(d)) {
                bool ack = d.len > 5 && d.data[5] == genesis::kAck;
                if (drop_acks && ack) continue;
                tx4.on_datagram(d.data, d.len, {0x7f000001u, 1}, now);
            }
            if (drop_acks && tx4.retx() > 0) drop_acks = false;
            now += 1000;
        }
    }
    expect(tx4.success() && rx4.success(), "lost-ack transfer");
    expect(dst.data == src.data, "lost-ack bytes");

    Buf empty_src, empty_dst;
    genesis::EngineOpts z = o;
    z.file_size = 0;
    std::snprintf(z.file_name, sizeof(z.file_name), "empty.bin");
    genesis::Engine txe(z, true);
    genesis::Engine rxe(z, false);
    txe.add_candidate({0x7f000001u, 1});
    txe.set_io(rd, nullptr, &empty_src);
    rxe.set_io(nullptr, wr, &empty_dst);
    expect(xfer(txe, rxe, 0, 5000), "empty file");
    expect(empty_dst.data.empty(), "empty bytes");
}

void test_discovery_beacon() {
    genesis::Beacon b;
    b.port = 37420;
    b.features = genesis::kFeatFile;
    std::snprintf(b.name, sizeof(b.name), "node-a");
    uint8_t pkt[64];
    size_t n = genesis::beacon_encode(pkt, sizeof(pkt), b);
    genesis::Beacon o;
    expect(n > 8 && genesis::beacon_decode(pkt, n, o), "beacon");
    expect(o.port == 37420 && std::strcmp(o.name, "node-a") == 0, "beacon fields");
    pkt[0] ^= 0xff;
    expect(!genesis::beacon_decode(pkt, n, o), "beacon magic");
}

void test_jitter_link_dht() {
    genesis::JitterMeter m;
    m.observe(1000, 5000);
    m.observe(2000, 7000);
    expect(m.jitter_us < 5000, "jitter stable when spacing matches");
    m.observe(3000, 20000);
    expect(m.jitter_us > 0, "jitter rises on a late packet");
    expect(genesis::jitter_hold_us(0, 1, 0) <= 20000, "ethernet hold is short");
    expect(genesis::jitter_hold_us(0, 3, 0) >= 40000, "cellular hold absorbs jitter");
    expect(genesis::classify_iface("wlan0") == 2, "wifi name");
    expect(genesis::classify_iface("enp0s3") == 1, "ethernet name");
    expect(genesis::classify_iface("wwan0") == 3, "cellular name");
    expect(genesis::choose_link(1, 3) == 1, "ethernet name wins over a slow rtt");
    expect(genesis::classify_rtt(500, 100) == 1, "sub-2ms is ethernet");
    expect(genesis::classify_rtt(80000, 10000) == 3, "high rtt is cellular");

    genesis::DhtTable table;
    uint8_t self[16]{};
    self[0] = 0x10;
    table.set_self(self);
    genesis::DhtNode near;
    near.used = true;
    near.port = 1;
    near.addr = 0x7f000001;
    near.rtt_us = 1000;
    std::memcpy(near.id, self, 16);
    near.id[15] = 0x02;
    genesis::DhtNode far;
    far.used = true;
    far.port = 2;
    far.addr = 0x0a000002;
    far.rtt_us = 80000;
    far.id[0] = 0xff;
    expect(table.insert(near) && table.insert(far), "dht insert");
    expect(genesis::dht_proximity(self, near) == 1, "near peer");
    expect(genesis::dht_proximity(self, far) == 0, "far peer");
    genesis::DhtNode got[8];
    int n = table.closest(self, got, 8);
    expect(n == 2 && std::memcmp(got[0].id, near.id, 16) == 0, "closest is the near id");
    genesis::DhtMessage msg;
    msg.type = genesis::kDhtNodes;
    std::memcpy(msg.sender, self, 16);
    msg.count = 1;
    msg.nodes[0] = near;
    uint8_t pkt[128];
    size_t len = genesis::dht_encode(pkt, sizeof(pkt), msg);
    genesis::DhtMessage back;
    expect(len > 40 && genesis::dht_decode(pkt, len, back), "dht codec");
    expect(back.count == 1 && back.nodes[0].port == 1, "dht node fields");
    pkt[0] ^= 0xff;
    expect(!genesis::dht_decode(pkt, len, back), "dht magic");
}

void test_routes_and_fec_nack() {
    const int N = 40000;
    Buf src, dst;
    src.data.resize(static_cast<size_t>(N));
    for (int i = 0; i < N; ++i) src.data[static_cast<size_t>(i)] = static_cast<uint8_t>(i * 3 + 1);
    genesis::EngineOpts o;
    o.fec_k = 8;
    o.fec_r = 1;
    o.plain_mss = 1200;
    o.window = 64;
    o.file_size = static_cast<uint64_t>(N);
    o.enable_fec = 1;
    o.enable_nack = 1;
    std::snprintf(o.file_name, sizeof(o.file_name), "stripe.bin");
    genesis::Engine tx(o, true);
    genesis::Engine rx(o, false);
    tx.add_route({0x7f000001u, 10});
    tx.add_route({0x7f000001u, 11});
    tx.set_io(rd, nullptr, &src);
    rx.set_io(nullptr, wr, &dst);
    {
        uint64_t now = 1000;
        tx.start(now);
        rx.start(now);
        for (int step = 0; step < 60000 && !(tx.success() && rx.success()); ++step) {
            tx.tick(now);
            rx.tick(now);
            genesis::DatagramOut d;
            while (tx.pop(d)) {
                bool data = d.len > 5 && d.data[5] == genesis::kData;
                if (d.port == 10 && data) continue;
                uint16_t rp = d.port ? d.port : 2;
                rx.on_datagram(d.data, d.len, {0x7f000001u, rp}, now);
            }
            while (rx.pop(d)) tx.on_datagram(d.data, d.len, {0x7f000001u, 1}, now);
            now += 1000;
        }
    }
    expect(tx.success() && rx.success(), "route failover");
    expect(dst.data == src.data, "route bytes");
    expect(tx.routes_alive() >= 1, "a route stayed up");

    for (int fec = 0; fec <= 1; ++fec) {
        for (int nack = 0; nack <= 1; ++nack) {
            src.off = 0;
            dst.data.clear();
            genesis::EngineOpts opt = o;
            opt.enable_fec = fec;
            opt.enable_nack = nack;
            opt.link_hint = 1;
            genesis::Engine a(opt, true);
            genesis::Engine b(opt, false);
            a.add_candidate({0x7f000001u, 1});
            a.set_io(rd, nullptr, &src);
            b.set_io(nullptr, wr, &dst);
            char label[64];
            std::snprintf(label, sizeof(label), "matrix fec=%d nack=%d", fec, nack);
            expect(xfer(a, b, 11, 50000), label);
            expect(dst.data == src.data, "matrix bytes");
            expect(a.fec_on() == fec, "fec negotiated");
            expect(b.nack_on() == nack, "nack negotiated");
        }
    }
}

void test_resume_and_control() {
    genesis::PeerView peer{};
    peer.file_size = 1000;
    std::snprintf(peer.name, sizeof(peer.name), "n");
    std::snprintf(peer.file_name, sizeof(peer.file_name), "f.bin");
    uint8_t raw[600];
    size_t n = 0;
    expect(genesis::encode_hello(raw, sizeof(raw), &n, peer), "hello encode");
    n = genesis::hello_append_tail(raw, sizeof(raw), n, 238, 476);
    uint16_t chunk = 0;
    uint64_t tail_off = 0;
    genesis::hello_read_tail(raw, n, &chunk, &tail_off);
    expect(chunk == 238 && tail_off == 476, "hello tail");
    genesis::PeerView back{};
    expect(genesis::decode_hello(raw, n, back) && back.file_size == 1000, "hello ignores tail");

    constexpr int kChunk = 238;
    constexpr int kBytes = kChunk * 3;
    Buf src;
    Buf dst;
    src.data.resize(kBytes);
    for (int i = 0; i < kBytes; ++i) src.data[static_cast<size_t>(i)] = static_cast<uint8_t>(i * 3 + 1);
    dst.data.assign(src.data.begin(), src.data.begin() + kChunk);
    genesis::EngineOpts opt;
    opt.plain_mss = 256;
    opt.window = 64;
    opt.fec_k = 4;
    opt.fec_r = 1;
    opt.enable_fec = 1;
    opt.enable_nack = 0;
    opt.file_size = kBytes;
    std::snprintf(opt.file_name, sizeof(opt.file_name), "f.bin");
    genesis::Engine tx(opt, true);
    genesis::Engine rx(opt, false);
    tx.add_candidate({0x7f000001u, 1});
    tx.set_io(rd, nullptr, &src);
    rx.set_io(nullptr, wr, &dst);
    rx.set_resume(
        [](void* user, const char*, uint64_t, int align, genesis::ResumeAbsorb absorb, void* arg) -> uint64_t {
            auto* b = static_cast<Buf*>(user);
            if (align != kChunk || b->data.size() < static_cast<size_t>(align)) return 0;
            absorb(arg, b->data.data(), align);
            return static_cast<uint64_t>(align);
        },
        &dst);
    expect(xfer(tx, rx, 0, 20000), "resume transfer");
    expect(dst.data == src.data, "resume bytes");
    expect(tx.resume_offset() == static_cast<uint64_t>(kChunk), "sender resume offset");
    expect(rx.resume_offset() == static_cast<uint64_t>(kChunk), "receiver resume offset");

    char err[80];
    const char* path = "/tmp/genesis-ctl-test.sock";
    ::unlink(path);
    int lfd = genesis_control_listen(path, err, sizeof(err));
    expect(lfd >= 0, "control listen");
    std::string reply;
    std::thread client([&] {
        if (lfd < 0) return;
        int fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
        sockaddr_un addr{};
        addr.sun_family = AF_UNIX;
        std::snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", path);
        for (int i = 0; i < 50 && ::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0; ++i)
            ::usleep(10000);
        const char* msg = "command=nope\n\n";
        if (::write(fd, msg, std::strlen(msg)) > 0) {
            char buf[128]{};
            ssize_t got = ::read(fd, buf, sizeof(buf) - 1);
            if (got > 0) reply.assign(buf, static_cast<size_t>(got));
        }
        ::close(fd);
    });
    if (lfd >= 0) {
        int accepted = -1;
        for (int i = 0; i < 50 && accepted < 0; ++i) {
            accepted = genesis_control_take(lfd);
            if (accepted < 0) ::usleep(10000);
        }
        expect(accepted >= 0, "control accept");
        if (accepted >= 0) {
            genesis_config cfg{};
            genesis_config_init(&cfg);
            cfg.bind_port = 1;
            genesis_control_dispatch(accepted, &cfg, nullptr);
        }
        ::close(lfd);
        ::unlink(path);
    }
    client.join();
    expect(reply.compare(0, 4, "ERR ") == 0, "control rejects unknown command");
}

}  // namespace

int main() {
    test_crypto();
    test_fec();
    test_wire();
    test_handshake();
    test_stun();
    test_mesh();
    test_config_and_jail();
    test_ring();
    test_bbr();
    test_engine();
    test_discovery_beacon();
    test_jitter_link_dht();
    test_routes_and_fec_nack();
    test_resume_and_control();
    if (g_fails) {
        std::fprintf(stderr, "%d failure(s)\n", g_fails);
        return 1;
    }
    std::printf("all tests passed\n");
    return 0;
}
