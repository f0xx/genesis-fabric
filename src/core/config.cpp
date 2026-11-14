#include "genesis/api.h"

#include "util.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>

namespace genesis {
namespace {

void trim(char* s) {
    char* b = s;
    while (*b == ' ' || *b == '\t') ++b;
    if (b != s) std::memmove(s, b, std::strlen(b) + 1);
    size_t n = std::strlen(s);
    while (n && (s[n - 1] == ' ' || s[n - 1] == '\t' || s[n - 1] == '\r' || s[n - 1] == '\n')) s[--n] = '\0';
}

bool tri_state(int* dst, const char* v) {
    if (std::strcmp(v, "auto") == 0) {
        *dst = -1;
        return true;
    }
    if (std::strcmp(v, "on") == 0 || std::strcmp(v, "true") == 0 || std::strcmp(v, "1") == 0) {
        *dst = 1;
        return true;
    }
    if (std::strcmp(v, "off") == 0 || std::strcmp(v, "false") == 0 || std::strcmp(v, "0") == 0) {
        *dst = 0;
        return true;
    }
    return false;
}

bool set_int(int* dst, const char* v) {
    char* end = nullptr;
    long x = std::strtol(v, &end, 10);
    if (!end || end == v || *end) return false;
    *dst = static_cast<int>(x);
    return true;
}

}  // namespace
}  // namespace genesis

void genesis_config_init(genesis_config* cfg) {
    if (!cfg) return;
    std::memset(cfg, 0, sizeof(*cfg));
    std::snprintf(cfg->bind_host, sizeof(cfg->bind_host), "0.0.0.0");
    cfg->bind_port = 37420;
    std::snprintf(cfg->node_name, sizeof(cfg->node_name), "genesis");
    std::snprintf(cfg->stun_host, sizeof(cfg->stun_host), "stun.l.google.com");
    cfg->stun_port = 19302;
    cfg->turn_port = 3478;
    cfg->profile = GENESIS_PROFILE_AUTO;
    cfg->fec_k = 8;
    cfg->fec_r = 1;
    cfg->plain_mss = 1200;
    cfg->window_packets = 512;
    cfg->enable_fec = -1;
    cfg->enable_nack = -1;
    cfg->enable_dht = 1;
    cfg->enable_mesh = 1;
    cfg->enable_discovery = 1;
    cfg->enable_io_uring = -1;
    cfg->pinned_core = -1;
    cfg->socket_buffer = 8 * 1024 * 1024;
    std::snprintf(cfg->recv_dir, sizeof(cfg->recv_dir), ".");
    cfg->trust = GENESIS_TRUST_ANY;
    cfg->punch_ms = 2000;
    cfg->transfer_timeout_s = 0;
    cfg->verbose = 0;
}

int genesis_config_set(genesis_config* cfg, const char* key, const char* value) {
    if (!cfg || !key || !value) return GENESIS_ERR_ARGS;
    char k[64];
    char v[768];
    std::snprintf(k, sizeof(k), "%s", key);
    std::snprintf(v, sizeof(v), "%s", value);
    genesis::trim(k);
    genesis::trim(v);
    auto eq = [&](const char* name) { return std::strcmp(k, name) == 0; };
    if (eq("bind_host") || eq("bind_address") || eq("bind_ip"))
        genesis::copy_cstr(cfg->bind_host, sizeof(cfg->bind_host), v);
    else if (eq("port") || eq("bind_port")) {
        int x = 0;
        if (!genesis::set_int(&x, v) || x < 0 || x > 65535) return GENESIS_ERR_ARGS;
        cfg->bind_port = static_cast<uint16_t>(x);
    } else if (eq("node_name"))
        genesis::copy_cstr(cfg->node_name, sizeof(cfg->node_name), v);
    else if (eq("stun_host") || eq("stun_server"))
        genesis::copy_cstr(cfg->stun_host, sizeof(cfg->stun_host), v);
    else if (eq("stun_port")) {
        int x = 0;
        if (!genesis::set_int(&x, v)) return GENESIS_ERR_ARGS;
        cfg->stun_port = static_cast<uint16_t>(x);
    } else if (eq("turn_host") || eq("turn_server"))
        genesis::copy_cstr(cfg->turn_host, sizeof(cfg->turn_host), v);
    else if (eq("turn_port")) {
        int x = 0;
        if (!genesis::set_int(&x, v)) return GENESIS_ERR_ARGS;
        cfg->turn_port = static_cast<uint16_t>(x);
    } else if (eq("turn_username"))
        genesis::copy_cstr(cfg->turn_username, sizeof(cfg->turn_username), v);
    else if (eq("turn_password"))
        genesis::copy_cstr(cfg->turn_password, sizeof(cfg->turn_password), v);
    else if (eq("network_profile") || eq("profile")) {
        if (std::strcmp(v, "auto") == 0) cfg->profile = GENESIS_PROFILE_AUTO;
        else if (std::strcmp(v, "gbe") == 0 || std::strcmp(v, "LOCAL_LAN_10G") == 0) cfg->profile = GENESIS_PROFILE_GBE;
        else if (std::strcmp(v, "cellular") == 0 || std::strcmp(v, "CELLULAR_5G") == 0)
            cfg->profile = GENESIS_PROFILE_CELLULAR;
        else if (std::strcmp(v, "wifi") == 0 || std::strcmp(v, "WLAN") == 0)
            cfg->profile = GENESIS_PROFILE_WIFI;
        else return GENESIS_ERR_ARGS;
    } else if (eq("fec_k") || eq("fec_data")) {
        if (!genesis::set_int(&cfg->fec_k, v)) return GENESIS_ERR_ARGS;
    } else if (eq("fec_r") || eq("fec_parity")) {
        if (!genesis::set_int(&cfg->fec_r, v)) return GENESIS_ERR_ARGS;
    } else if (eq("plain_mss") || eq("mss")) {
        if (!genesis::set_int(&cfg->plain_mss, v)) return GENESIS_ERR_ARGS;
    } else if (eq("window_packets") || eq("window")) {
        if (!genesis::set_int(&cfg->window_packets, v)) return GENESIS_ERR_ARGS;
    } else if (eq("enable_fec") || eq("fec")) {
        if (!genesis::tri_state(&cfg->enable_fec, v)) return GENESIS_ERR_ARGS;
    } else if (eq("enable_nack") || eq("nack")) {
        if (!genesis::tri_state(&cfg->enable_nack, v)) return GENESIS_ERR_ARGS;
    } else if (eq("enable_dht") || eq("dht")) {
        if (!genesis::tri_state(&cfg->enable_dht, v)) return GENESIS_ERR_ARGS;
        if (cfg->enable_dht < 0) cfg->enable_dht = 1;
    } else if (eq("enable_mesh")) {
        cfg->enable_mesh = (std::strcmp(v, "1") == 0 || std::strcmp(v, "true") == 0);
    } else if (eq("enable_discovery") || eq("enable_upnp")) {
        cfg->enable_discovery = (std::strcmp(v, "1") == 0 || std::strcmp(v, "true") == 0);
    } else if (eq("enable_io_uring") || eq("io_uring")) {
        if (std::strcmp(v, "auto") == 0) cfg->enable_io_uring = -1;
        else if (!genesis::set_int(&cfg->enable_io_uring, v)) return GENESIS_ERR_ARGS;
    } else if (eq("pinned_core")) {
        if (!genesis::set_int(&cfg->pinned_core, v)) return GENESIS_ERR_ARGS;
    } else if (eq("socket_buffer")) {
        if (!genesis::set_int(&cfg->socket_buffer, v)) return GENESIS_ERR_ARGS;
    } else if (eq("psk_hex") || eq("psk"))
        genesis::copy_cstr(cfg->psk_hex, sizeof(cfg->psk_hex), v);
    else if (eq("expect_pub_hex"))
        genesis::copy_cstr(cfg->expect_pub_hex, sizeof(cfg->expect_pub_hex), v);
    else if (eq("cookie_hex") || eq("cookie"))
        genesis::copy_cstr(cfg->cookie_hex, sizeof(cfg->cookie_hex), v);
    else if (eq("recv_dir"))
        genesis::copy_cstr(cfg->recv_dir, sizeof(cfg->recv_dir), v);
    else if (eq("chroot") || eq("chroot_dir"))
        genesis::copy_cstr(cfg->chroot_dir, sizeof(cfg->chroot_dir), v);
    else if (eq("user") || eq("drop_user"))
        genesis::copy_cstr(cfg->drop_user, sizeof(cfg->drop_user), v);
    else if (eq("pid_file"))
        genesis::copy_cstr(cfg->pid_file, sizeof(cfg->pid_file), v);
    else if (eq("tofu_path"))
        genesis::copy_cstr(cfg->tofu_path, sizeof(cfg->tofu_path), v);
    else if (eq("trust")) {
        if (std::strcmp(v, "any") == 0) cfg->trust = GENESIS_TRUST_ANY;
        else if (std::strcmp(v, "tofu") == 0) cfg->trust = GENESIS_TRUST_TOFU;
        else if (std::strcmp(v, "psk") == 0) cfg->trust = GENESIS_TRUST_PSK;
        else return GENESIS_ERR_ARGS;
    } else if (eq("verbose")) {
        if (!genesis::set_int(&cfg->verbose, v)) return GENESIS_ERR_ARGS;
    } else if (eq("punch_ms")) {
        if (!genesis::set_int(&cfg->punch_ms, v)) return GENESIS_ERR_ARGS;
    } else if (eq("transfer_timeout_s")) {
        if (!genesis::set_int(&cfg->transfer_timeout_s, v)) return GENESIS_ERR_ARGS;
    } else if (eq("ssh_pipe")) {
        cfg->ssh_pipe = (std::strcmp(v, "1") == 0 || std::strcmp(v, "true") == 0);
    } else if (eq("jitter_ms")) {
        if (!genesis::set_int(&cfg->jitter_ms, v) || cfg->jitter_ms < 0 || cfg->jitter_ms > 1000)
            return GENESIS_ERR_ARGS;
    } else if (eq("link") || eq("link_hint")) {
        if (std::strcmp(v, "auto") == 0 || std::strcmp(v, "unknown") == 0) cfg->link_hint = GENESIS_LINK_UNKNOWN;
        else if (std::strcmp(v, "ethernet") == 0 || std::strcmp(v, "gbe") == 0)
            cfg->link_hint = GENESIS_LINK_ETHERNET;
        else if (std::strcmp(v, "wifi") == 0) cfg->link_hint = GENESIS_LINK_WIFI;
        else if (std::strcmp(v, "cellular") == 0) cfg->link_hint = GENESIS_LINK_CELLULAR;
        else return GENESIS_ERR_ARGS;
    } else if (eq("routes") || eq("via")) {
        genesis::copy_cstr(cfg->routes, sizeof(cfg->routes), v);
    }     else if (eq("control")) {
        genesis::copy_cstr(cfg->control, sizeof(cfg->control), v);
    } else if (eq("export")) {
        if (cfg->export_count >= GENESIS_EXPORT_MAX) return GENESIS_ERR_ARGS;
        char buf[768];
        std::snprintf(buf, sizeof(buf), "%s", v);
        char name[32];
        char path[256];
        int rw = 1;
        char* eqpos = std::strchr(buf, '=');
        char* sp = std::strchr(buf, ' ');
        if (eqpos && (!sp || eqpos < sp)) {
            *eqpos = '\0';
            if (std::strlen(buf) == 0 || std::strlen(buf) > 31) return GENESIS_ERR_ARGS;
            std::memcpy(name, buf, std::strlen(buf) + 1);
            char* rest = eqpos + 1;
            size_t L = std::strlen(rest);
            if (L > 3 && std::strcmp(rest + L - 3, ",ro") == 0) {
                rw = 0;
                rest[L - 3] = '\0';
            } else if (L > 3 && std::strcmp(rest + L - 3, ",rw") == 0) {
                rest[L - 3] = '\0';
            }
            if (std::strlen(rest) == 0 || std::strlen(rest) > 255) return GENESIS_ERR_ARGS;
            std::memcpy(path, rest, std::strlen(rest) + 1);
        } else {
            if (!sp) return GENESIS_ERR_ARGS;
            *sp = '\0';
            if (std::strlen(buf) == 0 || std::strlen(buf) > 31) return GENESIS_ERR_ARGS;
            std::memcpy(name, buf, std::strlen(buf) + 1);
            char* rest = sp + 1;
            while (*rest == ' ') ++rest;
            char* last = std::strrchr(rest, ' ');
            if (last && (std::strcmp(last + 1, "ro") == 0 || std::strcmp(last + 1, "rw") == 0)) {
                rw = std::strcmp(last + 1, "rw") == 0 ? 1 : 0;
                *last = '\0';
                while (last > rest && last[-1] == ' ') {
                    --last;
                    *last = '\0';
                }
            }
            if (std::strlen(rest) == 0 || std::strlen(rest) > 255) return GENESIS_ERR_ARGS;
            std::memcpy(path, rest, std::strlen(rest) + 1);
        }
        if (!name[0] || std::strlen(name) > 31 || !path[0]) return GENESIS_ERR_ARGS;
        for (const char* p = name; *p; ++p) {
            char c = *p;
            bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' ||
                      c == '_' || c == '-' || c == '+';
            if (!ok) return GENESIS_ERR_ARGS;
        }
        if (std::strchr(path, '\n') || std::strchr(path, '\\')) return GENESIS_ERR_ARGS;
        for (const char* p = path; *p;) {
            if (p[0] == '.' && p[1] == '.' && (p[2] == '/' || p[2] == '\0') && (p == path || p[-1] == '/'))
                return GENESIS_ERR_ARGS;
            ++p;
        }
        for (int i = 0; i < cfg->export_count; ++i)
            if (std::strcmp(cfg->export_name[i], name) == 0) return GENESIS_ERR_ARGS;
        int slot = cfg->export_count++;
        genesis::copy_cstr(cfg->export_name[slot], sizeof(cfg->export_name[slot]), name);
        genesis::copy_cstr(cfg->export_path[slot], sizeof(cfg->export_path[slot]), path);
        cfg->export_rw[slot] = static_cast<uint8_t>(rw);
    } else
        return GENESIS_ERR_ARGS;
    return GENESIS_OK;
}

int genesis_config_load(genesis_config* cfg, const char* path) {
    if (!cfg || !path) return GENESIS_ERR_ARGS;
    FILE* f = std::fopen(path, "r");
    if (!f) return GENESIS_ERR_IO;
    char line[1024];
    while (std::fgets(line, sizeof(line), f)) {
        genesis::trim(line);
        if (!line[0] || line[0] == '#') continue;
        char* eq = std::strchr(line, '=');
        if (!eq) {
            std::fclose(f);
            return GENESIS_ERR_ARGS;
        }
        *eq = '\0';
        if (genesis_config_set(cfg, line, eq + 1) != GENESIS_OK) {
            std::fclose(f);
            return GENESIS_ERR_ARGS;
        }
    }
    std::fclose(f);
    return GENESIS_OK;
}
