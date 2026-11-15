#include "endian.hpp"
#include "genesis/api.h"
#include "vfs_codec.hpp"

#include <fuse3/fuse.h>

#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include <fcntl.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef UTIME_NOW
#define UTIME_NOW ((1L << 30) - 1L)
#define UTIME_OMIT ((1L << 30) - 2L)
#endif

namespace {

genesis_vfs* g_vfs = nullptr;
int g_timeout_ms = 8000;
pid_t g_ssh = -1;

void usage() {
    std::fprintf(stderr,
                 "mount.genesis — mount a genesis export\n"
                 "  mount.genesis [options] HOST[:PORT]:/EXPORT MOUNTPOINT\n"
                 "  mount.genesis --control PATH EXPORT MOUNTPOINT\n"
                 "  mount.genesis --ssh USER@HOST --remote-export DIR EXPORT MOUNTPOINT\n"
                 "Options:\n"
                 "  -f                 stay in the foreground\n"
                 "  -o ro|rw,port=N,timeout=SEC,allow_other,...\n"
                 "  --control PATH     talk to a local genesisd instead of UDP\n"
                 "  --ssh USER@HOST    start a remote vfs-serve over SSH, then mount it\n"
                 "  --ssh-port N       default 22\n"
                 "  --remote-bin PATH  remote genesis binary\n"
                 "  --remote-export DIR  directory the remote export should serve\n"
                 "  --remote-ro        export that directory read-only\n");
}

bool shell_name(const std::string& s) {
    if (s.empty() || s.size() > 200) return false;
    for (char c : s) {
        bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '_' ||
                  c == '-' || c == '+' || c == '/';
        if (!ok) return false;
    }
    return true;
}

std::string quote_arg(const std::string& s) {
    std::string o = "'";
    for (char c : s) {
        if (c == '\'') o += "'\\''";
        else o += c;
    }
    o += "'";
    return o;
}

int rpc(const genesis_vfs_req& req, genesis_vfs_res* res) {
    int rc = genesis_vfs_call(g_vfs, &req, res, g_timeout_ms);
    if (rc != GENESIS_OK) return -EIO;
    if (res->status) return -res->status;
    return 0;
}

int vfs_getattr(const char* path, struct stat* st, struct fuse_file_info*) {
    genesis_vfs_req req{};
    req.op = GENESIS_VFS_STAT;
    req.path = path;
    genesis_vfs_res res{};
    int rc = rpc(req, &res);
    if (rc) return rc;
    std::memset(st, 0, sizeof(*st));
    st->st_mode = res.mode;
    st->st_nlink = res.nlink ? res.nlink : 1;
    st->st_size = static_cast<off_t>(res.size);
    st->st_uid = res.uid;
    st->st_gid = res.gid;
    st->st_mtim.tv_sec = static_cast<time_t>(res.mtime_ns / 1000000000ull);
    st->st_mtim.tv_nsec = static_cast<long>(res.mtime_ns % 1000000000ull);
    st->st_atim.tv_sec = static_cast<time_t>(res.atime_ns / 1000000000ull);
    st->st_atim.tv_nsec = static_cast<long>(res.atime_ns % 1000000000ull);
    st->st_ctim = st->st_mtim;
    st->st_blksize = 4096;
    st->st_blocks = static_cast<blkcnt_t>((res.size + 511) / 512);
    return 0;
}

int vfs_readdir(const char* path, void* buf, fuse_fill_dir_t filler, off_t off, struct fuse_file_info*,
                enum fuse_readdir_flags) {
    if (off == 0 && filler(buf, ".", nullptr, 1, static_cast<fuse_fill_dir_flags>(0))) return 0;
    if (off <= 1 && filler(buf, "..", nullptr, 2, static_cast<fuse_fill_dir_flags>(0))) return 0;
    uint64_t cookie = off <= 2 ? 0 : static_cast<uint64_t>(off) - 2;
    for (;;) {
        uint8_t data[48 * 1024];
        genesis_vfs_req req{};
        req.op = GENESIS_VFS_READDIR;
        req.path = path;
        req.offset = cookie;
        genesis_vfs_res res{};
        res.data = data;
        res.data_cap = sizeof(data);
        int rc = rpc(req, &res);
        if (rc) return rc;
        size_t io = 0;
        genesis::VfsDirEnt ent{};
        bool any = false;
        while (genesis::vfs_dir_next(data, res.data_len, &io, &ent)) {
            any = true;
            struct stat st {};
            st.st_mode = ent.mode;
            st.st_size = static_cast<off_t>(ent.size);
            if (filler(buf, ent.name, &st, static_cast<off_t>(ent.cookie + 2), static_cast<fuse_fill_dir_flags>(0))) return 0;
            cookie = ent.cookie;
        }
        if (!any || res.data_len < 32 * 1024) break;
    }
    return 0;
}

int vfs_read(const char* path, char* buf, size_t size, off_t off, struct fuse_file_info*) {
    if (size > 16384) size = 16384;
    genesis_vfs_req req{};
    req.op = GENESIS_VFS_READ;
    req.path = path;
    req.offset = static_cast<uint64_t>(off);
    req.size = size;
    genesis_vfs_res res{};
    res.data = reinterpret_cast<uint8_t*>(buf);
    res.data_cap = static_cast<uint32_t>(size);
    int rc = rpc(req, &res);
    if (rc) return rc;
    return static_cast<int>(res.data_len);
}

int vfs_write(const char* path, const char* buf, size_t size, off_t off, struct fuse_file_info*) {
    if (size > 16384) size = 16384;
    genesis_vfs_req req{};
    req.op = GENESIS_VFS_WRITE;
    req.path = path;
    req.offset = static_cast<uint64_t>(off);
    req.data = reinterpret_cast<const uint8_t*>(buf);
    req.data_len = static_cast<uint32_t>(size);
    genesis_vfs_res res{};
    int rc = rpc(req, &res);
    if (rc) return rc;
    return static_cast<int>(size);
}

int vfs_create(const char* path, mode_t mode, struct fuse_file_info* fi) {
    genesis_vfs_req req{};
    req.op = GENESIS_VFS_CREATE;
    req.path = path;
    req.mode = static_cast<uint32_t>(mode);
    req.flags = GENESIS_VFS_CREAT;
    if (fi && (fi->flags & O_EXCL)) req.flags |= GENESIS_VFS_EXCL;
    if (fi && (fi->flags & O_TRUNC)) req.flags |= GENESIS_VFS_TRUNC;
    genesis_vfs_res res{};
    return rpc(req, &res);
}

int vfs_open(const char* path, struct fuse_file_info* fi) {
    if (fi && (fi->flags & O_TRUNC)) {
        genesis_vfs_req req{};
        req.op = GENESIS_VFS_TRUNCATE;
        req.path = path;
        req.size = 0;
        genesis_vfs_res res{};
        return rpc(req, &res);
    }
    return 0;
}

int vfs_truncate(const char* path, off_t size, struct fuse_file_info*) {
    genesis_vfs_req req{};
    req.op = GENESIS_VFS_TRUNCATE;
    req.path = path;
    req.size = static_cast<uint64_t>(size);
    genesis_vfs_res res{};
    return rpc(req, &res);
}

int vfs_mkdir(const char* path, mode_t mode) {
    genesis_vfs_req req{};
    req.op = GENESIS_VFS_MKDIR;
    req.path = path;
    req.mode = static_cast<uint32_t>(mode);
    genesis_vfs_res res{};
    return rpc(req, &res);
}

int vfs_unlink(const char* path) {
    genesis_vfs_req req{};
    req.op = GENESIS_VFS_UNLINK;
    req.path = path;
    genesis_vfs_res res{};
    return rpc(req, &res);
}

int vfs_rmdir(const char* path) {
    genesis_vfs_req req{};
    req.op = GENESIS_VFS_RMDIR;
    req.path = path;
    genesis_vfs_res res{};
    return rpc(req, &res);
}

int vfs_rename(const char* from, const char* to, unsigned int flags) {
    genesis_vfs_req req{};
    req.op = GENESIS_VFS_RENAME;
    req.path = from;
    req.name = to;
    req.flags = flags;
    genesis_vfs_res res{};
    return rpc(req, &res);
}

int vfs_chmod(const char* path, mode_t mode, struct fuse_file_info*) {
    genesis_vfs_req req{};
    req.op = GENESIS_VFS_CHMOD;
    req.path = path;
    req.mode = static_cast<uint32_t>(mode);
    genesis_vfs_res res{};
    return rpc(req, &res);
}

int vfs_utimens(const char* path, const struct timespec tv[2], struct fuse_file_info*) {
    genesis_vfs_req req{};
    req.op = GENESIS_VFS_UTIMENS;
    req.path = path;
    auto one = [&](const timespec& t, uint32_t omit, uint32_t now, uint64_t* ns) {
        if (t.tv_nsec == UTIME_OMIT) req.flags |= omit;
        else if (t.tv_nsec == UTIME_NOW) req.flags |= now;
        else *ns = static_cast<uint64_t>(t.tv_sec) * 1000000000ull + static_cast<uint64_t>(t.tv_nsec);
    };
    one(tv[0], GENESIS_VFS_ATIME_OMIT, GENESIS_VFS_ATIME_NOW, &req.atime_ns);
    one(tv[1], GENESIS_VFS_MTIME_OMIT, GENESIS_VFS_MTIME_NOW, &req.mtime_ns);
    genesis_vfs_res res{};
    return rpc(req, &res);
}

int vfs_symlink(const char* target, const char* link) {
    genesis_vfs_req req{};
    req.op = GENESIS_VFS_SYMLINK;
    req.path = link;
    req.name = target;
    genesis_vfs_res res{};
    return rpc(req, &res);
}

int vfs_readlink(const char* path, char* buf, size_t cap) {
    genesis_vfs_req req{};
    req.op = GENESIS_VFS_READLINK;
    req.path = path;
    genesis_vfs_res res{};
    int rc = rpc(req, &res);
    if (rc) return rc;
    std::snprintf(buf, cap, "%s", res.name);
    return 0;
}

int vfs_link(const char* from, const char* to) {
    genesis_vfs_req req{};
    req.op = GENESIS_VFS_LINK;
    req.path = from;
    req.name = to;
    genesis_vfs_res res{};
    return rpc(req, &res);
}

int vfs_statfs(const char* path, struct statvfs* st) {
    std::memset(st, 0, sizeof(*st));
    st->f_bsize = 4096;
    st->f_frsize = 4096;
    st->f_namemax = 255;
    genesis_vfs_req req{};
    req.op = GENESIS_VFS_STATFS;
    req.path = path;
    uint8_t data[64];
    genesis_vfs_res res{};
    res.data = data;
    res.data_cap = sizeof(data);
    if (rpc(req, &res) != 0 || res.data_len < 56) return 0;
    uint64_t f[7];
    for (int i = 0; i < 7; ++i) f[i] = genesis::load_be64(data + i * 8);
    st->f_blocks = f[0];
    st->f_bfree = f[1];
    st->f_bavail = f[2];
    st->f_files = f[3];
    st->f_ffree = f[4];
    st->f_bsize = f[5] ? f[5] : 4096;
    st->f_frsize = st->f_bsize;
    st->f_namemax = f[6] ? f[6] : 255;
    return 0;
}

void* vfs_init(struct fuse_conn_info* conn, struct fuse_config* cfg) {
    (void)conn;
    cfg->attr_timeout = 0;
    cfg->entry_timeout = 0;
    cfg->negative_timeout = 0;
    cfg->kernel_cache = 0;
    cfg->set_uid = 1;
    cfg->uid = getuid();
    cfg->set_gid = 1;
    cfg->gid = getgid();
    return nullptr;
}

void vfs_destroy(void*) {
    if (g_vfs) genesis_vfs_close(g_vfs);
    g_vfs = nullptr;
    if (g_ssh > 0) {
        kill(g_ssh, SIGTERM);
        waitpid(g_ssh, nullptr, 0);
        g_ssh = -1;
    }
}

bool parse_remote(const std::string& spec, std::string& user, std::string& host, int& ssh_port) {
    auto at = spec.find('@');
    if (at == std::string::npos) return false;
    user = spec.substr(0, at);
    host = spec.substr(at + 1);
    auto colon = host.rfind(':');
    if (colon != std::string::npos && host.find(':') == colon) {
        ssh_port = std::atoi(host.c_str() + colon + 1);
        host.resize(colon);
    }
    return shell_name(user) && shell_name(host);
}

int start_ssh(const std::string& user, const std::string& host, int ssh_port, const std::string& remote_bin,
              const std::string& exp, const std::string& remote_path, bool remote_ro, uint16_t* udp_port) {
    if (!shell_name(exp) || remote_path.find('\n') != std::string::npos || remote_bin.find('\n') != std::string::npos)
        return -1;
    int from_child[2];
    if (pipe(from_child) != 0) return -1;
    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) {
        dup2(from_child[1], 1);
        ::close(from_child[0]);
        ::close(from_child[1]);
        signal(SIGHUP, SIG_IGN);
        std::string port = std::to_string(ssh_port);
        std::string cmd = quote_arg(remote_bin) + " vfs-serve --ssh-pipe -p 0 --export " + exp + "=" + quote_arg(remote_path);
        if (remote_ro) cmd += ",ro";
        execlp("ssh", "ssh", "-o", "BatchMode=yes", "-p", port.c_str(), (user + "@" + host).c_str(), cmd.c_str(),
               static_cast<char*>(nullptr));
        _exit(127);
    }
    ::close(from_child[1]);
    FILE* in = fdopen(from_child[0], "r");
    char line[128];
    if (!in || !std::fgets(line, sizeof(line), in)) {
        if (in) std::fclose(in);
        kill(pid, SIGTERM);
        waitpid(pid, nullptr, 0);
        return -1;
    }
    unsigned ready = 0;
    if (std::sscanf(line, "ready %u", &ready) != 1 || ready == 0 || ready > 65535) {
        std::fclose(in);
        kill(pid, SIGTERM);
        waitpid(pid, nullptr, 0);
        return -1;
    }
    /* Keep the pipe open so the remote sees a live SSH session. */
    g_ssh = pid;
    *udp_port = static_cast<uint16_t>(ready);
    return fileno(in);
}

}  // namespace

int main(int argc, char** argv) {
    bool foreground = false;
    bool remote_ro = false;
    int port = 37420;
    int ssh_port = 22;
    std::string control;
    std::string ssh;
    std::string remote_bin = "genesis";
    std::string remote_export;
    std::string extra_opts;
    std::vector<std::string> pos;
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        auto need = [&](const char* name) -> const char* {
            if (i + 1 >= argc) {
                std::fprintf(stderr, "missing value for %s\n", name);
                std::exit(2);
            }
            return argv[++i];
        };
        if (a == "-h" || a == "--help") {
            usage();
            return 0;
        } else if (a == "-f" || a == "-d") {
            foreground = true;
        } else if (a == "--control") {
            control = need("--control");
        } else if (a == "--ssh") {
            ssh = need("--ssh");
        } else if (a == "--ssh-port") {
            ssh_port = std::atoi(need("--ssh-port"));
        } else if (a == "--remote-bin") {
            remote_bin = need("--remote-bin");
        } else if (a == "--remote-export") {
            remote_export = need("--remote-export");
        } else if (a == "--remote-ro") {
            remote_ro = true;
        } else if (a == "-o" || a.rfind("-o", 0) == 0) {
            std::string opt = a == "-o" ? need("-o") : a.substr(2);
            std::string kept;
            size_t b = 0;
            while (b < opt.size()) {
                size_t c = opt.find(',', b);
                if (c == std::string::npos) c = opt.size();
                std::string tok = opt.substr(b, c - b);
                b = c + 1;
                if (tok.rfind("port=", 0) == 0) port = std::atoi(tok.c_str() + 5);
                else if (tok.rfind("timeout=", 0) == 0) g_timeout_ms = std::atoi(tok.c_str() + 8) * 1000;
                else if (!tok.empty()) {
                    if (!kept.empty()) kept += ",";
                    kept += tok;
                }
            }
            if (!kept.empty()) {
                if (!extra_opts.empty()) extra_opts += ",";
                extra_opts += kept;
            }
        } else if (a.rfind("-", 0) == 0) {
            std::fprintf(stderr, "unknown option %s\n", a.c_str());
            return 2;
        } else {
            pos.push_back(a);
        }
    }
    if (pos.size() != 2) {
        usage();
        return 2;
    }
    std::string spec = pos[0];
    std::string mountpoint = pos[1];
    std::string host;
    std::string exp = spec;
    if (control.empty()) {
        auto slash = spec.find('/');
        if (slash != std::string::npos) {
            std::string hp = spec.substr(0, slash);
            exp = spec.substr(slash + 1);
            auto sub = exp.find('/');
            if (sub != std::string::npos) exp.resize(sub);
            if (!hp.empty() && hp.back() == ':') hp.pop_back();
            auto colon = hp.rfind(':');
            if (colon != std::string::npos) {
                port = std::atoi(hp.c_str() + colon + 1);
                host = hp.substr(0, colon);
            } else {
                host = hp;
            }
        }
    }
    if (exp.empty()) {
        usage();
        return 2;
    }
    genesis_config cfg;
    genesis_config_init(&cfg);
    cfg.bind_port = 0;
    int ssh_pipe = -1;
    if (!ssh.empty()) {
        if (remote_export.empty()) {
            std::fprintf(stderr, "--ssh needs --remote-export DIR (the directory the remote peer will serve)\n");
            return 2;
        }
        std::string user, shost;
        if (!parse_remote(ssh, user, shost, ssh_port)) {
            std::fprintf(stderr, "--ssh expects user@host\n");
            return 2;
        }
        uint16_t ready = 0;
        ssh_pipe = start_ssh(user, shost, ssh_port, remote_bin, exp, remote_export, remote_ro, &ready);
        if (ssh_pipe < 0 || ready == 0) {
            std::fprintf(stderr, "ssh did not publish a ready port\n");
            return 1;
        }
        host = shost;
        port = ready;
    }
    if (!control.empty()) {
        g_vfs = genesis_vfs_connect_control(control.c_str(), exp.c_str(), g_timeout_ms);
    } else {
        if (host.empty() || port <= 0 || port > 65535) {
            usage();
            return 2;
        }
        g_vfs = genesis_vfs_connect(&cfg, host.c_str(), static_cast<uint16_t>(port), exp.c_str(), g_timeout_ms);
    }
    if (!g_vfs) {
        std::fprintf(stderr, "cannot open genesis export %s\n", exp.c_str());
        if (g_ssh > 0) {
            kill(g_ssh, SIGTERM);
            waitpid(g_ssh, nullptr, 0);
        }
        return 1;
    }
    (void)ssh_pipe;
    std::string opts = "fsname=genesis:" + spec;
    if (!extra_opts.empty()) opts += "," + extra_opts;
    std::string dash_o = "-o";
    std::vector<char*> av;
    av.push_back(argv[0]);
    if (foreground) av.push_back(const_cast<char*>("-f"));
    av.push_back(const_cast<char*>(dash_o.c_str()));
    av.push_back(const_cast<char*>(opts.c_str()));
    av.push_back(const_cast<char*>(mountpoint.c_str()));
    av.push_back(nullptr);
    fuse_operations ops{};
    ops.getattr = vfs_getattr;
    ops.readdir = vfs_readdir;
    ops.read = vfs_read;
    ops.write = vfs_write;
    ops.create = vfs_create;
    ops.open = vfs_open;
    ops.truncate = vfs_truncate;
    ops.mkdir = vfs_mkdir;
    ops.unlink = vfs_unlink;
    ops.rmdir = vfs_rmdir;
    ops.rename = vfs_rename;
    ops.chmod = vfs_chmod;
    ops.utimens = vfs_utimens;
    ops.symlink = vfs_symlink;
    ops.readlink = vfs_readlink;
    ops.link = vfs_link;
    ops.statfs = vfs_statfs;
    ops.init = vfs_init;
    ops.destroy = vfs_destroy;
    return fuse_main(static_cast<int>(av.size() - 1), av.data(), &ops, nullptr);
}
