#include "genesis/api.h"

#include "crypto.hpp"
#include "dht.hpp"
#include "discovery.hpp"
#include "log.hpp"
#include "session.hpp"
#include "udp.hpp"
#include "util.hpp"

#include <cstdio>
#include <cstring>

const char* genesis_version(void) { return "1.2.0"; }

void genesis_log_syslog(int on) { genesis::log_use_syslog(on); }

int genesis_send_file(const genesis_config* cfg, const char* local_path, const char* peer_host, uint16_t peer_port,
                      genesis_progress_fn progress, void* user, genesis_stats* stats) {
    return genesis::run_send(cfg, local_path, peer_host, peer_port, progress, user, stats);
}

int genesis_recv_file(const genesis_config* cfg, const char* output_path, genesis_progress_fn progress, void* user,
                      genesis_stats* stats) {
    return genesis::run_recv(cfg, output_path, progress, user, stats);
}

int genesis_stun_discover(const genesis_config* cfg, char* mapped_host, size_t host_cap, uint16_t* mapped_port) {
    if (!cfg || !mapped_host || !mapped_port) return GENESIS_ERR_ARGS;
    genesis::UdpSocket sock;
    if (!sock.open(cfg->bind_host, cfg->bind_port, cfg->socket_buffer, false)) return GENESIS_ERR_NET;
    uint32_t addr = 0;
    uint16_t port = 0;
    if (!genesis::stun_query(sock, cfg->stun_host, cfg->stun_port, &addr, &port)) return GENESIS_ERR_NET;
    if (!genesis::ipv4_format(addr, mapped_host, host_cap)) return GENESIS_ERR_NET;
    *mapped_port = port;
    return GENESIS_OK;
}

int genesis_discover_once(const genesis_config* cfg, int timeout_ms, char* peer_line, size_t line_cap) {
    if (!cfg || !peer_line || line_cap < 8) return GENESIS_ERR_ARGS;
    genesis::UdpSocket sock;
    if (!sock.open("0.0.0.0", genesis::kDiscoveryPort, 1 << 20, false)) return GENESIS_ERR_NET;
    sock.join_multicast(genesis::kDiscoveryGroup);
    uint8_t buf[256];
    uint32_t addr = 0;
    uint16_t port = 0;
    int n = sock.recv_from(buf, sizeof(buf), &addr, &port, timeout_ms);
    if (n <= 0) return GENESIS_ERR_TIMEOUT;
    genesis::Beacon b;
    if (!genesis::beacon_decode(buf, static_cast<size_t>(n), b)) return GENESIS_ERR_PROTO;
    char ip[32];
    genesis::ipv4_format(addr, ip, sizeof(ip));
    std::snprintf(peer_line, line_cap, "%s name=%s port=%u", ip, b.name, b.port);
    return GENESIS_OK;
}

genesis_node* genesis_node_create(const genesis_config* cfg) {
    return reinterpret_cast<genesis_node*>(genesis::node_create(cfg));
}
int genesis_node_poll(genesis_node* node, int timeout_ms) {
    return genesis::node_poll(reinterpret_cast<genesis::Node*>(node), timeout_ms);
}
void genesis_node_request_stop(genesis_node* node) {
    genesis::node_stop(reinterpret_cast<genesis::Node*>(node));
}
void genesis_node_destroy(genesis_node* node) {
    genesis::node_destroy(reinterpret_cast<genesis::Node*>(node));
}
int genesis_node_stats(const genesis_node* node, genesis_stats* stats) {
    return genesis::node_stats(reinterpret_cast<const genesis::Node*>(node), stats);
}

uint16_t genesis_node_port(const genesis_node* node) {
    return genesis::node_port(reinterpret_cast<const genesis::Node*>(node));
}

int genesis_detect_link(char* ifname, size_t ifname_cap) {
    return genesis::primary_link(ifname, ifname_cap);
}

int genesis_dht_query(const genesis_config* cfg, const char* host, uint16_t port, int timeout_ms, char* out,
                      size_t out_cap) {
    if (!cfg || !host || !port || !out || out_cap < 8) return GENESIS_ERR_ARGS;
    out[0] = '\0';
    genesis::UdpSocket sock;
    if (!sock.open(cfg->bind_host, 0, 1 << 20, false)) return GENESIS_ERR_NET;
    genesis::DhtMessage msg;
    msg.type = genesis::kDhtFind;
    genesis::random_bytes(msg.sender, 16);
    genesis::random_bytes(msg.target, 16);
    uint8_t pkt[128];
    size_t n = genesis::dht_encode(pkt, sizeof(pkt), msg);
    uint32_t addr = 0;
    if (!n || !genesis::ipv4_resolve(host, &addr)) return GENESIS_ERR_NET;
    if (!sock.send_to(pkt, n, addr, port)) return GENESIS_ERR_NET;
    uint8_t buf[512];
    uint32_t from = 0;
    uint16_t from_port = 0;
    int got = sock.recv_from(buf, sizeof(buf), &from, &from_port, timeout_ms > 0 ? timeout_ms : 1000);
    if (got <= 0) return GENESIS_ERR_TIMEOUT;
    genesis::DhtMessage reply;
    if (!genesis::dht_decode(buf, static_cast<size_t>(got), reply)) return GENESIS_ERR_PROTO;
    size_t used = 0;
    for (int i = 0; i < reply.count; ++i) {
        char ip[32];
        char id[40];
        if (!genesis::ipv4_format(reply.nodes[i].addr, ip, sizeof(ip))) continue;
        genesis::to_hex(reply.nodes[i].id, 16, id);
        const char* prox = genesis::dht_proximity(msg.sender, reply.nodes[i]) ? "near" : "far";
        int wrote = std::snprintf(out + used, out_cap - used, "%s %s %s:%u rtt_us=%u\n", prox, id, ip,
                                  reply.nodes[i].port, reply.nodes[i].rtt_us);
        if (wrote < 0 || static_cast<size_t>(wrote) >= out_cap - used) break;
        used += static_cast<size_t>(wrote);
    }
    return GENESIS_OK;
}
