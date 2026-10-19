#pragma once

/*
 * Thin C++20 wrapper. Clients include this header only; it does not pull
 * sockets, the congestion controller, or the crypto implementation into the
 * application binary.
 */

#include "genesis/api.h"

#include <cstdint>
#include <cstring>
#include <string>

namespace genesis {

struct Version {
    static const char* string() { return genesis_version(); }
};

class Config {
public:
    Config() { genesis_config_init(&raw_); }
    explicit Config(const genesis_config& raw) : raw_(raw) {}

    genesis_config& raw() { return raw_; }
    const genesis_config& raw() const { return raw_; }

    int load(const std::string& path) { return genesis_config_load(&raw_, path.c_str()); }
    int set(const std::string& key, const std::string& value) {
        return genesis_config_set(&raw_, key.c_str(), value.c_str());
    }

private:
    genesis_config raw_{};
};

class Node {
public:
    explicit Node(const Config& cfg) : node_(genesis_node_create(&cfg.raw())) {}
    ~Node() { if (node_) genesis_node_destroy(node_); }
    Node(const Node&) = delete;
    Node& operator=(const Node&) = delete;
    Node(Node&& other) noexcept : node_(other.node_) { other.node_ = nullptr; }
    Node& operator=(Node&& other) noexcept {
        if (this != &other) {
            if (node_) genesis_node_destroy(node_);
            node_ = other.node_;
            other.node_ = nullptr;
        }
        return *this;
    }

    explicit operator bool() const { return node_ != nullptr; }
    genesis_node* handle() const { return node_; }
    int poll(int timeout_ms) { return genesis_node_poll(node_, timeout_ms); }
    void request_stop() { if (node_) genesis_node_request_stop(node_); }
    int stats(genesis_stats* out) const { return genesis_node_stats(node_, out); }

private:
    genesis_node* node_ = nullptr;
};

inline int send_file(const Config& cfg, const std::string& path,
                     const std::string& host, uint16_t port,
                     genesis_progress_fn progress, void* user, genesis_stats* stats) {
    return genesis_send_file(&cfg.raw(), path.c_str(), host.c_str(), port, progress, user, stats);
}

inline int recv_file(const Config& cfg, const std::string& path,
                     genesis_progress_fn progress, void* user, genesis_stats* stats) {
    return genesis_recv_file(&cfg.raw(), path.c_str(), progress, user, stats);
}

}  // namespace genesis
