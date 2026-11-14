#include "genesis/client.hpp"
#include "vfs_codec.hpp"

#include <atomic>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <csignal>
#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

namespace {

void usage() {
    std::fprintf(stderr,
                 "genesis %s — UDP file transfer\n"
                 "  genesis send [opts] FILE HOST[:PORT]\n"
                 "  genesis send [opts] --ssh USER@HOST[:SSHPORT] FILE REMOTE_NAME\n"
                 "  genesis recv [opts] [-o FILE]\n"
                 "  genesis discover [--timeout MS]\n"
                 "  genesis stun\n"
                 "  genesis dht HOST[:PORT]\n"
                 "  genesis showmount [HOST[:PORT]]\n"
                 "  genesis tree HOST[:PORT]:/EXPORT[/PATH]\n"
                 "  genesis vfs-serve [--export NAME=PATH[,ro]] [--control PATH]\n"
                 "  genesis mount [mount.genesis options] SPEC MOUNTPOINT\n"
                 "  genesis version\n"
                 "Options:\n"
                 "  -c FILE          config file (key=value)\n"
                 "  -b HOST          bind address\n"
                 "  -p PORT          local UDP port (recv) or peer port (send, default 37420)\n"
                 "  --listen PORT    sender's local UDP port (default ephemeral)\n"
                 "  --profile auto|gbe|wifi|cellular\n"
                 "  --link auto|ethernet|wifi|cellular\n"
                 "  --fec auto|on|off    --nack auto|on|off\n"
                 "  --fec-k N --fec-r N --mss N --window N --jitter-ms N\n"
                 "  --via HOST:PORT      extra route, repeatable (striped, failover)\n"
                 "  --psk HEX --expect-pub HEX --timeout SEC\n"
                 "  --control PATH|HOST:PORT   ask a running genesisd instead of the library\n"
                 "  --remote-bin PATH   remote genesis binary for --ssh\n"
                 "  --ssh-port N\n"
                 "  -v               verbose (repeatable)\n"
                 "Progress is written to stderr as a bar, percent, and ETA.\n"
                 "FILE or -o - reads or writes standard input/output.\n",
                 genesis_version());
}

struct Opt {
    genesis::Config cfg;
    int verbose = 0;
    int peer_port = 37420;
    int ssh_port = 22;
    int discover_ms = 2000;
    int listen_port = -1;
    bool port_set = false;
    std::string control;
    std::string config_path;
    std::string remote_bin = "genesis";
    std::string output = "genesis.out";
};

bool take(int& i, int argc, char** argv, const char** out) {
    if (i + 1 >= argc) return false;
    *out = argv[++i];
    return true;
}

int apply_global(Opt& o, int& i, int argc, char** argv) {
    const char* a = argv[i];
    const char* v = nullptr;
    if (std::strcmp(a, "-v") == 0 || std::strcmp(a, "--verbose") == 0) {
        o.verbose++;
        o.cfg.raw().verbose = o.verbose;
        return 0;
    }
    if (std::strcmp(a, "-c") == 0 || std::strcmp(a, "--config") == 0) {
        if (!take(i, argc, argv, &v)) return -1;
        if (o.cfg.load(v) != GENESIS_OK) {
            std::fprintf(stderr, "cannot load config %s\n", v);
            return -1;
        }
        return 0;
    }
    if (std::strcmp(a, "-b") == 0 || std::strcmp(a, "--bind") == 0) {
        if (!take(i, argc, argv, &v)) return -1;
        return o.cfg.set("bind_host", v) == GENESIS_OK ? 0 : -1;
    }
    if (std::strcmp(a, "-p") == 0 || std::strcmp(a, "--port") == 0) {
        if (!take(i, argc, argv, &v)) return -1;
        o.peer_port = std::atoi(v);
        o.port_set = true;
        /* 0 is the ephemeral port used by recv --ssh-pipe. */
        if (o.peer_port == 0 && std::strcmp(v, "0") != 0) return -1;
        return o.peer_port >= 0 && o.peer_port <= 65535 ? 0 : -1;
    }
    if (std::strcmp(a, "--listen") == 0) {
        if (!take(i, argc, argv, &v)) return -1;
        o.listen_port = std::atoi(v);
        return o.cfg.set("bind_port", v) == GENESIS_OK ? 0 : -1;
    }
    if (std::strcmp(a, "--profile") == 0) {
        if (!take(i, argc, argv, &v)) return -1;
        return o.cfg.set("profile", v) == GENESIS_OK ? 0 : -1;
    }
    if (std::strcmp(a, "--link") == 0) {
        if (!take(i, argc, argv, &v)) return -1;
        return o.cfg.set("link", v) == GENESIS_OK ? 0 : -1;
    }
    if (std::strcmp(a, "--fec") == 0) {
        if (!take(i, argc, argv, &v)) return -1;
        return o.cfg.set("fec", v) == GENESIS_OK ? 0 : -1;
    }
    if (std::strcmp(a, "--nack") == 0) {
        if (!take(i, argc, argv, &v)) return -1;
        return o.cfg.set("nack", v) == GENESIS_OK ? 0 : -1;
    }
    if (std::strcmp(a, "--jitter-ms") == 0) {
        if (!take(i, argc, argv, &v)) return -1;
        return o.cfg.set("jitter_ms", v) == GENESIS_OK ? 0 : -1;
    }
    if (std::strcmp(a, "--control") == 0) {
        if (!take(i, argc, argv, &v)) return -1;
        o.control = v;
        return 0;
    }
    if (std::strcmp(a, "--via") == 0) {
        if (!take(i, argc, argv, &v)) return -1;
        std::string cur = o.cfg.raw().routes;
        if (!cur.empty()) cur.push_back(',');
        cur += v;
        return o.cfg.set("routes", cur) == GENESIS_OK ? 0 : -1;
    }
    if (std::strcmp(a, "--fec-k") == 0) {
        if (!take(i, argc, argv, &v)) return -1;
        return o.cfg.set("fec_k", v) == GENESIS_OK ? 0 : -1;
    }
    if (std::strcmp(a, "--fec-r") == 0) {
        if (!take(i, argc, argv, &v)) return -1;
        return o.cfg.set("fec_r", v) == GENESIS_OK ? 0 : -1;
    }
    if (std::strcmp(a, "--mss") == 0) {
        if (!take(i, argc, argv, &v)) return -1;
        return o.cfg.set("mss", v) == GENESIS_OK ? 0 : -1;
    }
    if (std::strcmp(a, "--window") == 0) {
        if (!take(i, argc, argv, &v)) return -1;
        return o.cfg.set("window", v) == GENESIS_OK ? 0 : -1;
    }
    if (std::strcmp(a, "--psk") == 0) {
        if (!take(i, argc, argv, &v)) return -1;
        return o.cfg.set("psk", v) == GENESIS_OK ? 0 : -1;
    }
    if (std::strcmp(a, "--expect-pub") == 0) {
        if (!take(i, argc, argv, &v)) return -1;
        return o.cfg.set("expect_pub_hex", v) == GENESIS_OK ? 0 : -1;
    }
    if (std::strcmp(a, "--timeout") == 0) {
        if (!take(i, argc, argv, &v)) return -1;
        return o.cfg.set("transfer_timeout_s", v) == GENESIS_OK ? 0 : -1;
    }
    if (std::strcmp(a, "--remote-bin") == 0) {
        if (!take(i, argc, argv, &v)) return -1;
        o.remote_bin = v;
        return 0;
    }
    if (std::strcmp(a, "--ssh-port") == 0) {
        if (!take(i, argc, argv, &v)) return -1;
        o.ssh_port = std::atoi(v);
        return 0;
    }
    if (std::strcmp(a, "--timeout-ms") == 0) {
        if (!take(i, argc, argv, &v)) return -1;
        o.discover_ms = std::atoi(v);
        return 0;
    }
    if (std::strcmp(a, "--export") == 0) {
        if (!take(i, argc, argv, &v)) return -1;
        return o.cfg.set("export", v) == GENESIS_OK ? 0 : -1;
    }
    return 1;
}

void human(char* dst, size_t cap, uint64_t bytes) {
    const char* u[] = {"B", "KiB", "MiB", "GiB", "TiB"};
    double v = static_cast<double>(bytes);
    int i = 0;
    while (v >= 1024.0 && i < 4) {
        v /= 1024.0;
        ++i;
    }
    std::snprintf(dst, cap, i ? "%.1f %s" : "%.0f %s", v, u[i]);
}

void on_progress(void*, uint64_t done, uint64_t total, uint64_t rate, uint64_t eta_ms) {
    const int width = 28;
    double pct = total ? (100.0 * static_cast<double>(done) / static_cast<double>(total)) : 0.0;
    int fill = total ? static_cast<int>((width * done) / total) : 0;
    if (fill > width) fill = width;
    char bar[40];
    for (int i = 0; i < width; ++i) bar[i] = i < fill ? '#' : '-';
    bar[width] = 0;
    char ds[32], ts[32], rs[32];
    human(ds, sizeof(ds), done);
    human(ts, sizeof(ts), total);
    human(rs, sizeof(rs), rate);
    char eta[32] = "unknown";
    if (eta_ms != ~uint64_t{0}) {
        uint64_t s = eta_ms / 1000;
        uint64_t h = s / 3600;
        uint64_t m = (s % 3600) / 60;
        uint64_t sec = s % 60;
        if (h)
            std::snprintf(eta, sizeof(eta), "%llu:%02llu:%02llu", static_cast<unsigned long long>(h),
                          static_cast<unsigned long long>(m), static_cast<unsigned long long>(sec));
        else
            std::snprintf(eta, sizeof(eta), "%llu:%02llu", static_cast<unsigned long long>(m),
                          static_cast<unsigned long long>(sec));
    }
    std::fprintf(stderr, "\r[%s] %5.1f%% %s / %s  %s/s  ETA %s   ", bar, pct, ds, ts, rs, eta);
    std::fflush(stderr);
}

bool shell_safe(const std::string& s) {
    if (s.empty() || s.size() > 200) return false;
    for (char c : s) {
        bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
                  c == '/' || c == '.' || c == '_' || c == '-' || c == '+';
        if (!ok) return false;
    }
    return true;
}

int ssh_send(Opt& o, const std::string& file, const std::string& spec, const std::string& remote_name) {
    auto at = spec.find('@');
    if (at == std::string::npos) {
        std::fprintf(stderr, "--ssh expects user@host\n");
        return 2;
    }
    std::string user = spec.substr(0, at);
    std::string host = spec.substr(at + 1);
    auto colon = host.rfind(':');
    if (colon != std::string::npos && host.find(':') == colon) {
        o.ssh_port = std::atoi(host.c_str() + colon + 1);
        host.resize(colon);
    }
    if (!shell_safe(user) || !shell_safe(host) || !shell_safe(remote_name) || !shell_safe(o.remote_bin)) {
        std::fprintf(stderr, "refusing ssh arguments with shell metacharacters\n");
        return 2;
    }
    int to_child[2], from_child[2];
    if (pipe(to_child) != 0 || pipe(from_child) != 0) return 1;
    pid_t pid = fork();
    if (pid < 0) return 1;
    if (pid == 0) {
        dup2(to_child[0], 0);
        dup2(from_child[1], 1);
        close(to_child[0]);
        close(to_child[1]);
        close(from_child[0]);
        close(from_child[1]);
        std::string port = std::to_string(o.ssh_port);
        std::string cmd = o.remote_bin + " recv --ssh-pipe -o " + remote_name + " -p 0";
        execlp("ssh", "ssh", "-o", "BatchMode=yes", "-p", port.c_str(), (user + "@" + host).c_str(), cmd.c_str(),
               static_cast<char*>(nullptr));
        _exit(127);
    }
    close(to_child[0]);
    close(from_child[1]);
    FILE* in = fdopen(from_child[0], "r");
    char line[128];
    if (!in || !std::fgets(line, sizeof(line), in)) {
        std::fprintf(stderr, "ssh control channel produced no ready line\n");
        close(to_child[1]);
        if (in) std::fclose(in);
        else close(from_child[0]);
        waitpid(pid, nullptr, 0);
        return 1;
    }
    unsigned port = 0;
    if (std::sscanf(line, "ready %u", &port) != 1 || port == 0 || port > 65535) {
        std::fprintf(stderr, "bad ready line: %s\n", line);
        close(to_child[1]);
        std::fclose(in);
        waitpid(pid, nullptr, 0);
        return 1;
    }
    genesis_stats stats{};
    int rc = genesis::send_file(o.cfg, file, host, static_cast<uint16_t>(port), on_progress, nullptr, &stats);
    std::fprintf(stderr, "\n");
    close(to_child[1]);
    std::fclose(in);
    int st = 0;
    waitpid(pid, &st, 0);
    if (rc != GENESIS_OK) {
        std::fprintf(stderr, "send failed (%d) %s\n", rc, stats.error);
        return 1;
    }
    std::fprintf(stderr, "ok sha256=%s rate=%llu B/s\n", stats.sha256_hex,
                 static_cast<unsigned long long>(stats.rate_bps));
    return 0;
}

const char* tri_name(int v) {
    if (v < 0) return "auto";
    return v ? "on" : "off";
}

const char* profile_name(int v) {
    if (v == GENESIS_PROFILE_GBE) return "gbe";
    if (v == GENESIS_PROFILE_CELLULAR) return "cellular";
    if (v == GENESIS_PROFILE_WIFI) return "wifi";
    return "auto";
}

const char* link_name(int v) {
    if (v == GENESIS_LINK_ETHERNET) return "ethernet";
    if (v == GENESIS_LINK_WIFI) return "wifi";
    if (v == GENESIS_LINK_CELLULAR) return "cellular";
    return "auto";
}

int control_connect(const std::string& spec) {
    if (spec.empty()) return -1;
    int fd = -1;
    if (spec.find('/') != std::string::npos || spec.compare(0, 5, "unix:") == 0) {
        std::string path = spec.compare(0, 5, "unix:") == 0 ? spec.substr(5) : spec;
        if (path.size() >= sizeof(sockaddr_un{}.sun_path)) return -1;
        fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
        if (fd < 0) return -1;
        sockaddr_un addr{};
        addr.sun_family = AF_UNIX;
        std::snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", path.c_str());
        if (::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
            ::close(fd);
            return -1;
        }
        return fd;
    }
    auto colon = spec.rfind(':');
    if (colon == std::string::npos || colon == 0) return -1;
    std::string host = spec.substr(0, colon);
    int port = std::atoi(spec.c_str() + colon + 1);
    if (port <= 0 || port > 65535) return -1;
    fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(static_cast<uint16_t>(port));
    if (::inet_pton(AF_INET, host.c_str(), &addr.sin_addr) != 1) {
        ::close(fd);
        return -1;
    }
    if (::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        ::close(fd);
        return -1;
    }
    return fd;
}

int control_call(const Opt& o, const char* command, const char* file, const char* host, int port, const char* output) {
    int fd = control_connect(o.control);
    if (fd < 0) {
        std::fprintf(stderr, "cannot connect to genesisd control %s\n", o.control.c_str());
        return 1;
    }
    FILE* fp = fdopen(fd, "w+");
    if (!fp) {
        ::close(fd);
        return 1;
    }
    const genesis_config& c = o.cfg.raw();
    std::fprintf(fp, "command=%s\n", command);
    if (file && file[0]) std::fprintf(fp, "file=%s\n", file);
    if (host && host[0]) std::fprintf(fp, "host=%s\n", host);
    if (output && output[0]) std::fprintf(fp, "output=%s\n", output);
    std::fprintf(fp, "port=%d\n", port);
    std::fprintf(fp, "fec=%s\nnack=%s\nprofile=%s\nlink=%s\n", tri_name(c.enable_fec), tri_name(c.enable_nack),
                 profile_name(c.profile), link_name(c.link_hint));
    std::fprintf(fp, "window=%d\nmss=%d\nfec_k=%d\nfec_r=%d\njitter_ms=%d\nverbose=%d\ntransfer_timeout_s=%d\n", c.window_packets,
                 c.plain_mss, c.fec_k, c.fec_r, c.jitter_ms, c.verbose, c.transfer_timeout_s);
    if (c.routes[0]) std::fprintf(fp, "via=%s\n", c.routes);
    if (c.bind_host[0]) std::fprintf(fp, "bind_host=%s\n", c.bind_host);
    std::fputc('\n', fp);
    std::fflush(fp);
    char line[512];
    while (std::fgets(line, sizeof(line), fp)) {
        unsigned long long done = 0, total = 0, rate = 0, eta = 0;
        if (std::sscanf(line, "P %llu %llu %llu %llu", &done, &total, &rate, &eta) == 4) {
            on_progress(nullptr, done, total, rate, eta);
            continue;
        }
        if (std::strncmp(line, "OK ", 3) == 0) {
            std::fprintf(stderr, "\n%s", line);
            std::fclose(fp);
            return 0;
        }
        if (std::strncmp(line, "ERR ", 4) == 0) {
            std::fprintf(stderr, "\n%s", line);
            std::fclose(fp);
            return 1;
        }
    }
    std::fprintf(stderr, "\ncontrol connection closed\n");
    std::fclose(fp);
    return 1;
}

volatile std::sig_atomic_t g_vfs_stop = 0;

void on_vfs_stop(int) { g_vfs_stop = 1; }

int exec_mount(int argc, char** argv) {
    char self[4096];
    ssize_t n = ::readlink("/proc/self/exe", self, sizeof(self) - 1);
    std::string bin = "mount.genesis";
    if (n > 0) {
        self[n] = '\0';
        std::string path(self, static_cast<size_t>(n));
        auto slash = path.find_last_of('/');
        if (slash != std::string::npos) {
            std::string cand = path.substr(0, slash + 1) + "mount.genesis";
            if (::access(cand.c_str(), X_OK) == 0) bin = cand;
        }
    }
    std::vector<char*> args;
    args.push_back(const_cast<char*>(bin.c_str()));
    for (int i = 2; i < argc; ++i) args.push_back(argv[i]);
    args.push_back(nullptr);
    if (bin.find('/') == std::string::npos) ::execvp(bin.c_str(), args.data());
    else ::execv(bin.c_str(), args.data());
    std::perror("mount.genesis");
    return 127;
}

int tree_walk(genesis_vfs* session, const std::string& path, int depth) {
    if (depth > 40) return 0;
    uint8_t data[48 * 1024];
    uint64_t cookie = 0;
    for (;;) {
        genesis_vfs_req req{};
        req.op = GENESIS_VFS_READDIR;
        req.path = path.c_str();
        req.offset = cookie;
        genesis_vfs_res res{};
        res.data = data;
        res.data_cap = sizeof(data);
        int rc = genesis_vfs_call(session, &req, &res, 8000);
        if (rc != GENESIS_OK) {
            std::fprintf(stderr, "readdir %s failed (%d)\n", path.c_str(), rc);
            return 1;
        }
        if (res.status) {
            std::fprintf(stderr, "readdir %s: %s\n", path.c_str(), std::strerror(res.status));
            return 1;
        }
        size_t io = 0;
        bool any = false;
        genesis::VfsDirEnt ent;
        while (genesis::vfs_dir_next(data, res.data_len, &io, &ent)) {
            any = true;
            cookie = ent.cookie;
            std::string child = path.empty() ? std::string(ent.name) : path + "/" + ent.name;
            std::printf("%s%s\n", child.c_str(), S_ISDIR(ent.mode) ? "/" : "");
            std::fflush(stdout);
            if (S_ISDIR(ent.mode) && tree_walk(session, child, depth + 1) != 0) return 1;
        }
        if (!any || res.data_len < 48 * 1024) break;
    }
    return 0;
}

}  // namespace

int main(int argc, char** argv) {
    if (argc < 2) {
        usage();
        return 2;
    }
    Opt opt;
    std::string cmd = argv[1];
    bool ssh = false;
    std::string ssh_spec;
    for (int i = 2; i < argc; ++i) {
        if (std::strcmp(argv[i], "-h") == 0 || std::strcmp(argv[i], "--help") == 0) {
            usage();
            return 0;
        }
        if (std::strcmp(argv[i], "--ssh") == 0) {
            const char* v = nullptr;
            if (!take(i, argc, argv, &v)) return 2;
            ssh = true;
            ssh_spec = v;
            continue;
        }
        if (std::strcmp(argv[i], "--ssh-pipe") == 0) {
            opt.cfg.raw().ssh_pipe = 1;
            continue;
        }
        if (std::strcmp(argv[i], "-o") == 0 || std::strcmp(argv[i], "--output") == 0) {
            const char* v = nullptr;
            if (!take(i, argc, argv, &v)) return 2;
            opt.output = v;
            continue;
        }
        int ar = apply_global(opt, i, argc, argv);
        if (ar < 0) return 2;
        if (ar == 1) {
            /* positional: leave for the command by rewinding via a stored list */
            argv[i][-0] = argv[i][0];
            /* mark by rotating: we'll rescan below */
        }
    }
    std::string pos[4];
    int np = 0;
    for (int i = 2; i < argc && np < 4; ++i) {
        if (argv[i][0] == '-') {
            if (std::strcmp(argv[i], "--ssh") == 0 || std::strcmp(argv[i], "-c") == 0 ||
                std::strcmp(argv[i], "--config") == 0 || std::strcmp(argv[i], "-b") == 0 ||
                std::strcmp(argv[i], "--bind") == 0 || std::strcmp(argv[i], "-p") == 0 ||
                std::strcmp(argv[i], "--port") == 0 || std::strcmp(argv[i], "--profile") == 0 ||
                std::strcmp(argv[i], "--fec-k") == 0 || std::strcmp(argv[i], "--fec-r") == 0 ||
                std::strcmp(argv[i], "--mss") == 0 || std::strcmp(argv[i], "--window") == 0 ||
                std::strcmp(argv[i], "--psk") == 0 || std::strcmp(argv[i], "--expect-pub") == 0 ||
                std::strcmp(argv[i], "--timeout") == 0 || std::strcmp(argv[i], "--remote-bin") == 0 ||
                std::strcmp(argv[i], "--ssh-port") == 0 || std::strcmp(argv[i], "--timeout-ms") == 0 ||
                std::strcmp(argv[i], "--listen") == 0 || std::strcmp(argv[i], "--link") == 0 ||
                std::strcmp(argv[i], "--fec") == 0 || std::strcmp(argv[i], "--nack") == 0 ||
                std::strcmp(argv[i], "--jitter-ms") == 0 || std::strcmp(argv[i], "--via") == 0 ||
                std::strcmp(argv[i], "--control") == 0 || std::strcmp(argv[i], "--export") == 0 ||
                std::strcmp(argv[i], "-o") == 0 || std::strcmp(argv[i], "--output") == 0) {
                ++i;
            }
            continue;
        }
        pos[np++] = argv[i];
    }
    if (cmd == "version" || cmd == "--version") {
        std::printf("%s\n", genesis_version());
        return 0;
    }
    if (cmd == "stun") {
        char host[64];
        uint16_t port = 0;
        int rc = genesis_stun_discover(&opt.cfg.raw(), host, sizeof(host), &port);
        if (rc != GENESIS_OK) {
            std::fprintf(stderr, "stun failed (%d)\n", rc);
            return 1;
        }
        std::printf("%s %u\n", host, port);
        return 0;
    }
    if (cmd == "dht") {
        if (np < 1) {
            usage();
            return 2;
        }
        std::string host = pos[0];
        int port = 37420;
        auto colon = host.rfind(':');
        if (colon != std::string::npos) {
            port = std::atoi(host.c_str() + colon + 1);
            host.resize(colon);
        }
        char out[2048];
        int rc = genesis_dht_query(&opt.cfg.raw(), host.c_str(), static_cast<uint16_t>(port), opt.discover_ms, out,
                                   sizeof(out));
        if (rc != GENESIS_OK) {
            std::fprintf(stderr, "dht failed (%d)\n", rc);
            return 1;
        }
        std::fputs(out, stdout);
        return 0;
    }
    if (cmd == "discover") {
        char line[256];
        int rc = genesis_discover_once(&opt.cfg.raw(), opt.discover_ms, line, sizeof(line));
        if (rc != GENESIS_OK) {
            std::fprintf(stderr, "no peers (%d)\n", rc);
            return 1;
        }
        std::printf("%s\n", line);
        return 0;
    }
    if (cmd == "recv") {
        if (opt.port_set) opt.cfg.raw().bind_port = static_cast<uint16_t>(opt.peer_port);
        if (opt.listen_port >= 0) opt.cfg.raw().bind_port = static_cast<uint16_t>(opt.listen_port);
        if (!opt.control.empty())
            return control_call(opt, "recv", nullptr, nullptr, opt.cfg.raw().bind_port, opt.output.c_str());
        genesis_stats stats{};
        int rc = genesis::recv_file(opt.cfg, opt.output, on_progress, nullptr, &stats);
        std::fprintf(stderr, "\n");
        if (rc != GENESIS_OK) {
            std::fprintf(stderr, "recv failed (%d) %s\n", rc, stats.error);
            return 1;
        }
        std::fprintf(stderr, "ok sha256=%s\n", stats.sha256_hex);
        return 0;
    }
    if (cmd == "send") {
        if (np < 2) {
            usage();
            return 2;
        }
        if (ssh && !opt.control.empty()) {
            std::fprintf(stderr, "--control and --ssh cannot be combined\n");
            return 2;
        }
        if (ssh) {
            std::string remote = np >= 3 ? pos[2] : pos[0].substr(pos[0].find_last_of('/') + 1);
            if (np == 2 && pos[1].find('@') == std::string::npos) {
                /* genesis send --ssh user@host FILE REMOTE  already in pos */
            }
            if (np >= 2 && ssh_spec.empty()) ssh_spec = pos[1];
            return ssh_send(opt, pos[0], ssh_spec, remote);
        }
        std::string host = pos[1];
        int port = opt.peer_port;
        auto c = host.rfind(':');
        if (c != std::string::npos && host.find(':') == c) {
            port = std::atoi(host.c_str() + c + 1);
            host.resize(c);
        }
        if (opt.listen_port >= 0) opt.cfg.raw().bind_port = static_cast<uint16_t>(opt.listen_port);
        else opt.cfg.raw().bind_port = 0;
        if (!opt.control.empty()) return control_call(opt, "send", pos[0].c_str(), host.c_str(), port, nullptr);
        genesis_stats stats{};
        int rc = genesis::send_file(opt.cfg, pos[0], host, static_cast<uint16_t>(port), on_progress, nullptr, &stats);
        std::fprintf(stderr, "\n");
        if (rc != GENESIS_OK) {
            std::fprintf(stderr, "send failed (%d) %s\n", rc, stats.error);
            return 1;
        }
        std::fprintf(stderr, "ok sha256=%s rate=%llu B/s pacing=%llu B/s wire_tx=%llu\n", stats.sha256_hex,
                     static_cast<unsigned long long>(stats.rate_bps),
                     static_cast<unsigned long long>(stats.pacing_bps),
                     static_cast<unsigned long long>(stats.bytes_wire_tx));
        return 0;
    }
    if (cmd == "showmount") {
        std::string host;
        int port = opt.peer_port;
        const char* hostp = nullptr;
        if (np >= 1) {
            host = pos[0];
            auto colon = host.rfind(':');
            if (colon != std::string::npos && host.find(':') == colon) {
                port = std::atoi(host.c_str() + colon + 1);
                host.resize(colon);
            }
            hostp = host.c_str();
        }
        char out[8192];
        int rc = genesis_showmount(&opt.cfg.raw(), hostp, static_cast<uint16_t>(port), opt.discover_ms, out, sizeof(out));
        if (rc != GENESIS_OK) {
            std::fprintf(stderr, "showmount failed (%d)\n", rc);
            return 1;
        }
        std::fputs(out, stdout);
        return 0;
    }
    if (cmd == "tree") {
        if (np < 1) {
            usage();
            return 2;
        }
        std::string spec = pos[0];
        auto sep = spec.find(":/");
        if (sep == std::string::npos) {
            usage();
            return 2;
        }
        std::string hp = spec.substr(0, sep);
        std::string rest = spec.substr(sep + 2);
        std::string exp = rest;
        std::string sub;
        auto slash = rest.find('/');
        if (slash != std::string::npos) {
            exp = rest.substr(0, slash);
            sub = rest.substr(slash + 1);
        }
        int port = opt.peer_port;
        auto colon = hp.rfind(':');
        if (colon != std::string::npos) {
            port = std::atoi(hp.c_str() + colon + 1);
            hp.resize(colon);
        }
        genesis_vfs* session = genesis_vfs_connect(&opt.cfg.raw(), hp.c_str(), static_cast<uint16_t>(port), exp.c_str(), 8000);
        if (!session) {
            std::fprintf(stderr, "tree: cannot reach %s:%d export %s\n", hp.c_str(), port, exp.c_str());
            return 1;
        }
        int rc = tree_walk(session, sub, 0);
        genesis_vfs_close(session);
        return rc;
    }
    if (cmd == "vfs-serve") {
        if (opt.port_set) opt.cfg.raw().bind_port = static_cast<uint16_t>(opt.peer_port);
        std::signal(SIGINT, on_vfs_stop);
        std::signal(SIGTERM, on_vfs_stop);
        genesis_vfs_server* server = genesis_vfs_server_start(&opt.cfg.raw());
        if (!server) {
            std::fprintf(stderr, "vfs-serve failed to bind\n");
            return 1;
        }
        if (opt.cfg.raw().ssh_pipe) {
            std::printf("ready %u\n", genesis_vfs_server_port(server));
            std::fflush(stdout);
        } else {
            std::fprintf(stderr, "vfs serving %d export(s) on port %u\n", opt.cfg.raw().export_count,
                         genesis_vfs_server_port(server));
        }
        while (!g_vfs_stop && genesis_vfs_server_running(server)) ::poll(nullptr, 0, 200);
        genesis_vfs_server_stop(server);
        return 0;
    }
    if (cmd == "mount") return exec_mount(argc, argv);
    usage();
    return 2;
}
