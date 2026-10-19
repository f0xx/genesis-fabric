#include "genesis/api.h"

#include "session.hpp"

#include <arpa/inet.h>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

namespace {

bool is_unix_spec(const char* spec, const char** path) {
    if (!spec || !spec[0]) return false;
    if (std::strncmp(spec, "unix:", 5) == 0) {
        *path = spec + 5;
        return true;
    }
    if (std::strchr(spec, '/')) {
        *path = spec;
        return true;
    }
    return false;
}

bool split_host_port(const char* spec, char* host, size_t host_cap, int* port) {
    const char* colon = std::strrchr(spec, ':');
    if (!colon || colon == spec) return false;
    size_t n = static_cast<size_t>(colon - spec);
    if (n >= host_cap) return false;
    std::memcpy(host, spec, n);
    host[n] = '\0';
    *port = ::atoi(colon + 1);
    return *port > 0 && *port <= 65535;
}

struct Req {
    char command[16]{};
    char file[512]{};
    char host[128]{};
    char output[512]{};
    char via[512]{};
    int port = 37420;
    genesis_config cfg{};
};

void apply_kv(Req* r, const char* key, const char* val) {
    if (std::strcmp(key, "command") == 0) std::snprintf(r->command, sizeof(r->command), "%s", val);
    else if (std::strcmp(key, "file") == 0) std::snprintf(r->file, sizeof(r->file), "%s", val);
    else if (std::strcmp(key, "host") == 0) std::snprintf(r->host, sizeof(r->host), "%s", val);
    else if (std::strcmp(key, "output") == 0) std::snprintf(r->output, sizeof(r->output), "%s", val);
    else if (std::strcmp(key, "port") == 0) r->port = ::atoi(val);
    else if (std::strcmp(key, "via") == 0) std::snprintf(r->via, sizeof(r->via), "%s", val);
    else genesis_config_set(&r->cfg, key, val);
}

bool read_req(int fd, Req* r) {
    char buf[8192];
    size_t n = 0;
    while (n + 1 < sizeof(buf)) {
        char c;
        ssize_t k = ::read(fd, &c, 1);
        if (k <= 0) return false;
        buf[n++] = c;
        if (n >= 2 && buf[n - 2] == '\n' && buf[n - 1] == '\n') break;
    }
    buf[n] = '\0';
    char* save = nullptr;
    for (char* line = strtok_r(buf, "\n", &save); line; line = strtok_r(nullptr, "\n", &save)) {
        char* eq = std::strchr(line, '=');
        if (!eq || eq == line) continue;
        *eq = '\0';
        apply_kv(r, line, eq + 1);
    }
    return r->command[0] != '\0';
}

void ctrl_progress(void* user, uint64_t done, uint64_t total, uint64_t rate, uint64_t eta) {
    int fd = *static_cast<int*>(user);
    if (fd < 0) return;
    dprintf(fd, "P %llu %llu %llu %llu\n", static_cast<unsigned long long>(done), static_cast<unsigned long long>(total),
            static_cast<unsigned long long>(rate), static_cast<unsigned long long>(eta));
}

}  // namespace

int genesis_control_listen(const char* spec, char* err, size_t err_cap) {
    auto seterr = [&](const char* m) {
        if (err && err_cap) std::snprintf(err, err_cap, "%s", m);
    };
    const char* path = nullptr;
    int fd = -1;
    if (is_unix_spec(spec, &path)) {
        if (!path[0] || std::strlen(path) >= sizeof(sockaddr_un{}.sun_path)) {
            seterr("control socket path is too long");
            return -1;
        }
        ::unlink(path);
        fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
        if (fd < 0) {
            seterr(std::strerror(errno));
            return -1;
        }
        sockaddr_un addr{};
        addr.sun_family = AF_UNIX;
        std::snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", path);
        if (::bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0 || ::listen(fd, 4) != 0) {
            seterr(std::strerror(errno));
            ::close(fd);
            return -1;
        }
        ::chmod(path, 0600);
    } else {
        char host[128];
        int port = 0;
        if (!split_host_port(spec, host, sizeof(host), &port)) {
            seterr("control spec must be a socket path or host:port");
            return -1;
        }
        fd = ::socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) {
            seterr(std::strerror(errno));
            return -1;
        }
        int one = 1;
        ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(static_cast<uint16_t>(port));
        if (std::strcmp(host, "*") == 0 || std::strcmp(host, "0.0.0.0") == 0) addr.sin_addr.s_addr = htonl(INADDR_ANY);
        else if (::inet_pton(AF_INET, host, &addr.sin_addr) != 1) {
            seterr("control host must be an IPv4 address");
            ::close(fd);
            return -1;
        }
        if (::bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0 || ::listen(fd, 4) != 0) {
            seterr(std::strerror(errno));
            ::close(fd);
            return -1;
        }
    }
    int flags = ::fcntl(fd, F_GETFL, 0);
    if (flags >= 0) ::fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    return fd;
}

int genesis_control_take(int listen_fd) {
    if (listen_fd < 0) return -1;
    int fd = ::accept(listen_fd, nullptr, nullptr);
    if (fd < 0) return -1;
    int flags = ::fcntl(fd, F_GETFL, 0);
    if (flags >= 0) ::fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);
    return fd;
}

int genesis_control_dispatch(int client_fd, const genesis_config* cfg, genesis_node* node) {
    if (client_fd < 0 || !cfg) return -1;
    Req req;
    req.cfg = *cfg;
    if (!read_req(client_fd, &req)) {
        dprintf(client_fd, "ERR %d bad request\n", GENESIS_ERR_ARGS);
        ::close(client_fd);
        return 0;
    }
    if (req.via[0]) std::snprintf(req.cfg.routes, sizeof(req.cfg.routes), "%s", req.via);
    if (std::strcmp(req.command, "send") == 0) {
        if (!req.file[0] || !req.host[0] || req.port <= 0 || req.port > 65535) {
            dprintf(client_fd, "ERR %d send needs file, host, and port\n", GENESIS_ERR_ARGS);
            ::close(client_fd);
            return 0;
        }
        req.cfg.bind_port = 0;
        genesis_stats st{};
        int rc = genesis_send_file(&req.cfg, req.file, req.host, static_cast<uint16_t>(req.port), ctrl_progress, &client_fd,
                                   &st);
        if (rc == GENESIS_OK) {
            dprintf(client_fd, "OK sha256=%s rate=%llu pacing=%llu wire_tx=%llu\n", st.sha256_hex,
                    static_cast<unsigned long long>(st.rate_bps), static_cast<unsigned long long>(st.pacing_bps),
                    static_cast<unsigned long long>(st.bytes_wire_tx));
        } else {
            dprintf(client_fd, "ERR %d %s\n", rc, st.error[0] ? st.error : "send failed");
        }
        ::close(client_fd);
        return 0;
    }
    if (std::strcmp(req.command, "recv") == 0) {
        if (!req.output[0]) {
            dprintf(client_fd, "ERR %d recv needs output\n", GENESIS_ERR_ARGS);
            ::close(client_fd);
            return 0;
        }
        if (req.port > 0 && req.port != cfg->bind_port) {
            dprintf(client_fd, "ERR %d recv uses the daemon port %u\n", GENESIS_ERR_ARGS, cfg->bind_port);
            ::close(client_fd);
            return 0;
        }
        int rc = genesis::node_arm_recv(reinterpret_cast<genesis::Node*>(node), client_fd, req.output, &req.cfg);
        if (rc != GENESIS_OK) {
            dprintf(client_fd, "ERR %d daemon is busy or the output path is empty\n", rc);
            ::close(client_fd);
            return 0;
        }
        return 1;
    }
    dprintf(client_fd, "ERR %d unknown command\n", GENESIS_ERR_ARGS);
    ::close(client_fd);
    return 0;
}
