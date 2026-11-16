#include "genesis/client.hpp"

#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <unistd.h>

namespace {

volatile std::sig_atomic_t g_stop = 0;

void on_signal(int) { g_stop = 1; }

void usage() {
    std::fprintf(stderr,
                 "genesisd %s\n"
                 "  genesisd [-c FILE] [--daemon] [--chroot DIR] [--user NAME] [--pid FILE]\n"
                 "Foreground is the default so systemd (Type=simple) and OpenRC supervise-daemon\n"
                 "can own the process. --daemon double-forks for a sysv-style start.\n"
                 "-v logs transfer init, handshake flags, DHT nodes, and the end summary to stderr.\n"
                 "With --daemon those lines go to syslog (ident genesisd) instead.\n"
                 "--control PATH or --control HOST:PORT accepts send/recv from genesis --control.\n"
                 "export = NAME PATH [ro|rw] in the config publishes a directory for mount.genesis.\n",
                 genesis_version());
}

}  // namespace

int main(int argc, char** argv) {
    genesis::Config cfg;
    bool daemon = false;
    std::string chroot_dir;
    std::string user;
    std::string pid_file;
    std::string control;
    for (int i = 1; i < argc; ++i) {
        auto need = [&](const char* name) -> const char* {
            if (i + 1 >= argc) {
                std::fprintf(stderr, "missing value for %s\n", name);
                std::exit(2);
            }
            return argv[++i];
        };
        if (std::strcmp(argv[i], "-h") == 0 || std::strcmp(argv[i], "--help") == 0) {
            usage();
            return 0;
        } else if (std::strcmp(argv[i], "-c") == 0 || std::strcmp(argv[i], "--config") == 0) {
            if (cfg.load(need("--config")) != GENESIS_OK) {
                std::fprintf(stderr, "cannot load config\n");
                return 1;
            }
        } else if (std::strcmp(argv[i], "-v") == 0) {
            cfg.raw().verbose++;
        } else if (std::strcmp(argv[i], "-p") == 0 || std::strcmp(argv[i], "--port") == 0) {
            cfg.set("bind_port", need("--port"));
        } else if (std::strcmp(argv[i], "--daemon") == 0) {
            daemon = true;
        } else if (std::strcmp(argv[i], "--foreground") == 0) {
            daemon = false;
        } else if (std::strcmp(argv[i], "--chroot") == 0) {
            chroot_dir = need("--chroot");
        } else if (std::strcmp(argv[i], "--user") == 0) {
            user = need("--user");
        } else if (std::strcmp(argv[i], "--pid") == 0) {
            pid_file = need("--pid");
        } else if (std::strcmp(argv[i], "--recv-dir") == 0) {
            cfg.set("recv_dir", need("--recv-dir"));
        } else if (std::strcmp(argv[i], "--control") == 0) {
            control = need("--control");
        } else {
            std::fprintf(stderr, "unknown argument %s\n", argv[i]);
            return 2;
        }
    }
    if (!chroot_dir.empty()) std::snprintf(cfg.raw().chroot_dir, sizeof(cfg.raw().chroot_dir), "%s", chroot_dir.c_str());
    if (!user.empty()) std::snprintf(cfg.raw().drop_user, sizeof(cfg.raw().drop_user), "%s", user.c_str());
    if (!control.empty()) std::snprintf(cfg.raw().control, sizeof(cfg.raw().control), "%s", control.c_str());
    else if (cfg.raw().control[0]) control = cfg.raw().control;

    genesis::Node node(cfg);
    if (!node) {
        std::fprintf(stderr, "cannot bind %s:%u\n", cfg.raw().bind_host, cfg.raw().bind_port);
        return 1;
    }
    int ctrl = -1;
    if (!control.empty()) {
        char err[160];
        ctrl = genesis_control_listen(control.c_str(), err, sizeof(err));
        if (ctrl < 0) {
            std::fprintf(stderr, "control: %s\n", err);
            if (geteuid() != 0)
                std::fprintf(stderr, "control: not root, so a socket in /run or a chroot cannot be set up\n");
            return 1;
        }
        std::fprintf(stderr, "control listening on %s\n", control.c_str());
    }
    if (daemon) {
        if (cfg.raw().verbose > 0) genesis_log_syslog(1);
        char err[160];
        if (genesis_daemonize(pid_file.empty() ? cfg.raw().pid_file : pid_file.c_str(), err, sizeof(err)) != GENESIS_OK) {
            std::fprintf(stderr, "daemonize: %s\n", err);
            return 1;
        }
    }
    if (cfg.raw().chroot_dir[0] || cfg.raw().drop_user[0]) {
        char err[160];
        if (genesis_jail_apply(cfg.raw().chroot_dir, cfg.raw().drop_user, err, sizeof(err)) != GENESIS_OK) {
            std::fprintf(stderr, "jail: %s\n", err);
            return 1;
        }
    }
    std::signal(SIGTERM, on_signal);
    std::signal(SIGINT, on_signal);
    uint64_t reported = 0;
    while (!g_stop) {
        if (ctrl >= 0) {
            int client = genesis_control_take(ctrl);
            if (client >= 0) genesis_control_dispatch(client, &cfg.raw(), node.handle());
        }
        int rc = node.poll(ctrl >= 0 ? 50 : 500);
        if (rc != GENESIS_OK) break;
        genesis_stats st{};
        if (node.stats(&st) == GENESIS_OK && st.phase == 5 && st.bytes_payload && st.bytes_payload != reported) {
            std::fprintf(stderr, "transfer complete sha256=%s bytes=%llu\n", st.sha256_hex,
                         static_cast<unsigned long long>(st.bytes_payload));
            reported = st.bytes_payload;
        }
    }
    return 0;
}
