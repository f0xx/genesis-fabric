#include "vfs_hub.hpp"

#include "crypto.hpp"
#include "discovery.hpp"
#include "endian.hpp"
#include "handshake.hpp"
#include "log.hpp"
#include "util.hpp"
#include "vfs_codec.hpp"
#include "wire.hpp"

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <arpa/inet.h>
#include <dirent.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <mutex>
#include <poll.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <string>
#include <thread>
#include <unistd.h>
#include <utility>
#include <vector>

extern "C" int renameat2(int olddirfd, const char* oldpath, int newdirfd, const char* newpath, unsigned int flags);

namespace genesis {
namespace {

constexpr size_t kChunk = 960;
constexpr int kMaxFrags = 128;
constexpr int kMaxConn = 8;
constexpr int kMaxCtrl = 8;

#ifndef UTIME_NOW
#define UTIME_NOW ((1L << 30) - 1L)
#define UTIME_OMIT ((1L << 30) - 2L)
#endif

struct Loc {
    int err = 0;
    int parent = -1;
    char leaf[256]{};
    bool root = false;
};

void loc_close(Loc& L) {
    if (L.parent >= 0) ::close(L.parent);
    L.parent = -1;
}

bool dotdot_component(const char* s) {
    for (const char* p = s; p && *p; ++p) {
        if (p[0] == '.' && p[1] == '.' && (p[2] == '/' || p[2] == '\0') && (p == s || p[-1] == '/')) return true;
    }
    return false;
}

Loc descend(int root, const char* rel) {
    Loc L;
    if (root < 0) {
        L.err = EBADF;
        return L;
    }
    L.parent = ::dup(root);
    if (L.parent < 0) {
        L.err = errno;
        return L;
    }
    if (!rel) rel = "";
    if (std::strchr(rel, '\\') || std::strchr(rel, '\n') || dotdot_component(rel)) {
        L.err = EPERM;
        loc_close(L);
        return L;
    }
    const char* p = rel;
    while (*p == '/') ++p;
    if (!*p) {
        L.root = true;
        return L;
    }
    if (std::strlen(p) > kVfsMaxPath) {
        L.err = ENAMETOOLONG;
        loc_close(L);
        return L;
    }
    while (*p) {
        while (*p == '/') ++p;
        if (!*p) break;
        const char* s = p;
        while (*p && *p != '/') ++p;
        size_t n = static_cast<size_t>(p - s);
        if (n == 0 || n > 255) {
            L.err = n ? ENAMETOOLONG : EINVAL;
            loc_close(L);
            return L;
        }
        char comp[256];
        std::memcpy(comp, s, n);
        comp[n] = '\0';
        if (std::strcmp(comp, ".") == 0) continue;
        if (std::strcmp(comp, "..") == 0) {
            L.err = EPERM;
            loc_close(L);
            return L;
        }
        const char* q = p;
        while (*q == '/') ++q;
        bool last = *q == '\0';
        if (!last) {
            int fd = ::openat(L.parent, comp, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
            if (fd < 0) {
                L.err = errno ? errno : EIO;
                loc_close(L);
                return L;
            }
            ::close(L.parent);
            L.parent = fd;
        } else {
            std::memcpy(L.leaf, comp, n + 1);
        }
    }
    if (!L.leaf[0]) L.root = true;
    return L;
}

void fill_times(VfsBlob& r, const struct stat& st) {
    r.mode = static_cast<uint32_t>(st.st_mode);
    r.nlink = static_cast<uint32_t>(st.st_nlink);
    r.uid = st.st_uid;
    r.gid = st.st_gid;
    r.size = static_cast<uint64_t>(st.st_size);
    r.mtime_ns = static_cast<uint64_t>(st.st_mtim.tv_sec) * 1000000000ull + static_cast<uint64_t>(st.st_mtim.tv_nsec);
    r.atime_ns = static_cast<uint64_t>(st.st_atim.tv_sec) * 1000000000ull + static_cast<uint64_t>(st.st_atim.tv_nsec);
}

bool mutating(uint8_t op) {
    switch (op) {
    case GENESIS_VFS_WRITE:
    case GENESIS_VFS_CREATE:
    case GENESIS_VFS_MKDIR:
    case GENESIS_VFS_UNLINK:
    case GENESIS_VFS_RMDIR:
    case GENESIS_VFS_RENAME:
    case GENESIS_VFS_CHMOD:
    case GENESIS_VFS_TRUNCATE:
    case GENESIS_VFS_SYMLINK:
    case GENESIS_VFS_UTIMENS:
    case GENESIS_VFS_LINK:
        return true;
    default:
        return false;
    }
}

ssize_t pread_all(int fd, uint8_t* buf, size_t n, uint64_t off) {
    size_t got = 0;
    while (got < n) {
        ssize_t k = ::pread(fd, buf + got, n - got, static_cast<off_t>(off + got));
        if (k == 0) break;
        if (k < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        got += static_cast<size_t>(k);
    }
    return static_cast<ssize_t>(got);
}

int pwrite_all(int fd, const uint8_t* buf, size_t n, uint64_t off) {
    size_t put = 0;
    while (put < n) {
        ssize_t k = ::pwrite(fd, buf + put, n - put, static_cast<off_t>(off + put));
        if (k < 0) {
            if (errno == EINTR) continue;
            return errno ? errno : EIO;
        }
        if (k == 0) return EIO;
        put += static_cast<size_t>(k);
    }
    return 0;
}

struct Export {
    char name[32]{};
    char path[256]{};
    uint8_t rw = 1;
    int fd = -1;
};

struct Assembly {
    uint32_t req = 0;
    uint16_t n = 0;
    uint16_t got = 0;
    std::vector<uint8_t> have;
    std::vector<std::vector<uint8_t>> parts;

    void clear() { *this = Assembly{}; }
    bool complete() const { return n > 0 && got == n; }

    bool add(uint16_t index, uint16_t count, const uint8_t* chunk, uint16_t len) {
        if (count == 0 || count > kMaxFrags || index >= count || len > kChunk) return false;
        if (n == 0) {
            n = count;
            have.assign(static_cast<size_t>((count + 7) / 8), 0);
            parts.assign(count, {});
        } else if (n != count) {
            return false;
        }
        size_t byte = index / 8;
        uint8_t bit = static_cast<uint8_t>(1u << (index % 8));
        if (have[byte] & bit) return true;
        have[byte] = static_cast<uint8_t>(have[byte] | bit);
        parts[index].assign(chunk, chunk + len);
        ++got;
        return true;
    }

    std::vector<uint8_t> join() const {
        std::vector<uint8_t> out;
        for (const auto& part : parts) out.insert(out.end(), part.begin(), part.end());
        return out;
    }
};

struct FragView {
    bool hole = false;
    uint8_t flags = 0;
    uint16_t index = 0;
    uint16_t count = 0;
    uint32_t req = 0;
    const uint8_t* chunk = nullptr;
    uint16_t chunk_len = 0;
    std::vector<uint8_t> bitmap;
};

bool parse_frag(const uint8_t* p, size_t n, FragView& f) {
    if (!p || n < 1) return false;
    if (p[0] == 5) {
        if (n < 10) return false;
        f.hole = true;
        f.flags = p[1];
        f.count = load_be16(p + 2);
        f.req = load_be32(p + 4);
        uint16_t bl = load_be16(p + 8);
        if (f.count == 0 || f.count > kMaxFrags || bl != (f.count + 7) / 8 || n < 10u + bl) return false;
        f.bitmap.assign(p + 10, p + 10 + bl);
        return true;
    }
    if (p[0] != 4 || n < 12) return false;
    f.hole = false;
    f.flags = p[1];
    f.index = load_be16(p + 2);
    f.count = load_be16(p + 4);
    f.req = load_be32(p + 6);
    f.chunk_len = load_be16(p + 10);
    if (f.count == 0 || f.count > kMaxFrags || f.index >= f.count || f.chunk_len > kChunk) return false;
    if (n < 12u + f.chunk_len) return false;
    f.chunk = p + 12;
    return true;
}

void nonce_of(uint8_t out[12], uint32_t conn, uint64_t seq) {
    store_be32(out, conn);
    store_be64(out + 4, seq);
}

bool seal_dg(std::vector<uint8_t>& out, uint32_t conn, uint64_t seq, const uint8_t key[32], const uint8_t* plain,
             size_t plen) {
    if (plen + 16 > 1400) return false;
    Header h;
    h.version = kProtoVersion;
    h.type = kVfs;
    h.flags = kFlagEncrypted;
    h.conn_id = conn;
    h.seq = seq;
    h.payload_len = static_cast<uint16_t>(plen + 16);
    out.assign(kHeaderBytes + h.payload_len, 0);
    if (!encode_header(out.data(), out.size(), h)) return false;
    uint8_t nonce[12];
    nonce_of(nonce, conn, seq);
    size_t clen = 0;
    if (!aead_encrypt(out.data() + kHeaderBytes, plen + 16, &clen, plain, plen, out.data(), kHeaderBytes, key, nonce))
        return false;
    return clen == plen + 16;
}

bool open_dg(const uint8_t* dg, const Header& h, const uint8_t key[32], std::vector<uint8_t>& plain) {
    if (!(h.flags & kFlagEncrypted) || h.ext_len != 0 || h.payload_len < 16) return false;
    uint8_t nonce[12];
    nonce_of(nonce, h.conn_id, h.seq);
    plain.assign(h.payload_len, 0);
    size_t plen = 0;
    if (!aead_decrypt(plain.data(), plain.size(), &plen, dg + kHeaderBytes, h.payload_len, dg, kHeaderBytes, key, nonce))
        return false;
    plain.resize(plen);
    return true;
}

bool older_req(uint32_t incoming, uint32_t newest) {
    return incoming != newest && static_cast<int32_t>(incoming - newest) < 0;
}

struct Conn {
    bool used = false;
    bool keyed = false;
    bool confirmed = false;
    uint32_t id = 0;
    uint32_t addr = 0;
    uint16_t port = 0;
    int export_index = -1;
    uint8_t tx[32]{};
    uint8_t rx[32]{};
    uint64_t tx_seq = 2;
    uint64_t last_us = 0;
    uint64_t hole_us = 0;
    std::vector<uint8_t> hello_dg;
    std::vector<uint8_t> confirm_dg;
    uint8_t transcript[32]{};
    uint32_t last_req = 0;
    bool have_last = false;
    std::vector<std::vector<uint8_t>> last_reply;
    Assembly in;
};

struct Ctrl {
    int fd = -1;
    int export_index = -1;
    bool dead = false;
    uint32_t need = 0;
    std::vector<uint8_t> in;
};

bool write_full(int fd, const uint8_t* p, size_t n) {
    size_t o = 0;
    while (o < n) {
        ssize_t k = ::write(fd, p + o, n - o);
        if (k < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        if (k == 0) return false;
        o += static_cast<size_t>(k);
    }
    return true;
}

bool write_frame(int fd, const uint8_t* p, size_t n) {
    if (n > 200000) return false;
    uint8_t b[4];
    store_be32(b, static_cast<uint32_t>(n));
    return write_full(fd, b, 4) && write_full(fd, p, n);
}

bool read_full_until(int fd, uint8_t* p, size_t n, uint64_t deadline_us) {
    size_t o = 0;
    while (o < n) {
        uint64_t now = monotonic_us();
        if (now >= deadline_us) return false;
        int ms = static_cast<int>((deadline_us - now) / 1000);
        if (ms < 1) ms = 1;
        pollfd pfd{};
        pfd.fd = fd;
        pfd.events = POLLIN;
        int pr = ::poll(&pfd, 1, ms);
        if (pr < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        if (pr == 0) continue;
        ssize_t k = ::read(fd, p + o, n - o);
        if (k < 0) {
            if (errno == EINTR || errno == EAGAIN) continue;
            return false;
        }
        if (k == 0) return false;
        o += static_cast<size_t>(k);
    }
    return true;
}

}  // namespace

struct VfsHub {
    Export ex[GENESIS_EXPORT_MAX];
    int ex_count = 0;
    uint8_t psk[32]{};
    bool have_psk = false;
    uint8_t expect_pub[32]{};
    bool have_expect = false;
    Conn conns[kMaxConn];
    Ctrl ctrl[kMaxCtrl];
    int ctrl_n = 0;
    std::atomic<int> lose_every{0};
    std::atomic<int> lose_count{0};

    int find_export(const char* name) const {
        if (!name || !name[0]) return -1;
        for (int i = 0; i < ex_count; ++i)
            if (std::strcmp(ex[i].name, name) == 0) return i;
        return -1;
    }

    int root_fd(int index) {
        if (index < 0 || index >= ex_count) return -1;
        if (ex[index].fd >= 0) return ex[index].fd;
        int fd = ::open(ex[index].path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (fd < 0) return -1;
        ex[index].fd = fd;
        return fd;
    }

    bool emit(UdpSocket& sock, const uint8_t* p, size_t n, uint32_t addr, uint16_t port) {
        int every = lose_every.load();
        if (every > 1) {
            int c = lose_count.fetch_add(1) + 1;
            if (c % every == 0) return true;
        }
        return sock.send_to(p, n, addr, port);
    }

    void list_shares(VfsBlob& resp) const {
        VfsShare shares[GENESIS_EXPORT_MAX];
        for (int i = 0; i < ex_count; ++i) {
            std::snprintf(shares[i].name, sizeof(shares[i].name), "%s", ex[i].name);
            std::snprintf(shares[i].path, sizeof(shares[i].path), "%s", ex[i].path);
            shares[i].rw = ex[i].rw;
        }
        vfs_shares_write(resp.data, shares, ex_count);
    }

    void dispatch(int export_index, const VfsBlob& req, VfsBlob& resp) {
        resp = VfsBlob{};
        resp.op = req.op;
        resp.req_id = req.req_id;
        resp.flags = req.flags;
        if (req.op == GENESIS_VFS_LIST) {
            list_shares(resp);
            return;
        }
        if (export_index < 0 || export_index >= ex_count) {
            resp.status = EPERM;
            return;
        }
        if (mutating(req.op) && !ex[export_index].rw) {
            resp.status = EROFS;
            return;
        }
        if (req.op == GENESIS_VFS_STATFS) {
            struct statvfs sv {};
            if (::statvfs(ex[export_index].path, &sv) != 0) {
                resp.status = errno ? errno : EIO;
                return;
            }
            uint64_t fields[7] = {static_cast<uint64_t>(sv.f_blocks), static_cast<uint64_t>(sv.f_bfree),
                                  static_cast<uint64_t>(sv.f_bavail), static_cast<uint64_t>(sv.f_files),
                                  static_cast<uint64_t>(sv.f_ffree),    static_cast<uint64_t>(sv.f_bsize),
                                  static_cast<uint64_t>(sv.f_namemax)};
            resp.data.resize(sizeof(fields));
            for (int i = 0; i < 7; ++i) store_be64(resp.data.data() + i * 8, fields[i]);
            return;
        }
        int root = root_fd(export_index);
        if (root < 0) {
            resp.status = errno ? errno : ENOENT;
            return;
        }
        Loc loc = descend(root, req.path.c_str());
        if (loc.err) {
            resp.status = loc.err;
            return;
        }
        struct Closer {
            Loc* l;
            ~Closer() { loc_close(*l); }
        } closer{&loc};

        auto need_leaf = [&]() -> bool {
            if (loc.root || !loc.leaf[0]) {
                resp.status = EINVAL;
                return false;
            }
            return true;
        };

        if (req.op == GENESIS_VFS_STAT) {
            struct stat st {};
            int rc = loc.root ? ::fstat(loc.parent, &st)
                              : ::fstatat(loc.parent, loc.leaf, &st, AT_SYMLINK_NOFOLLOW);
            if (rc != 0) resp.status = errno ? errno : EIO;
            else fill_times(resp, st);
            return;
        }
        if (req.op == GENESIS_VFS_READDIR) {
            int dfd = loc.root ? ::dup(loc.parent)
                               : ::openat(loc.parent, loc.leaf, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
            if (dfd < 0) {
                resp.status = errno ? errno : ENOTDIR;
                return;
            }
            DIR* dir = ::fdopendir(dfd);
            if (!dir) {
                resp.status = errno ? errno : EIO;
                ::close(dfd);
                return;
            }
            uint64_t index = 0;
            while (dirent* de = ::readdir(dir)) {
                if (std::strcmp(de->d_name, ".") == 0 || std::strcmp(de->d_name, "..") == 0) continue;
                if (index < req.offset) {
                    ++index;
                    continue;
                }
                struct stat st {};
                if (::fstatat(dfd, de->d_name, &st, AT_SYMLINK_NOFOLLOW) != 0) {
                    ++index;
                    continue;
                }
                VfsDirEnt ent{};
                std::snprintf(ent.name, sizeof(ent.name), "%s", de->d_name);
                ent.mode = static_cast<uint32_t>(st.st_mode);
                ent.size = static_cast<uint64_t>(st.st_size);
                ent.mtime_ns = static_cast<uint64_t>(st.st_mtim.tv_sec) * 1000000000ull +
                               static_cast<uint64_t>(st.st_mtim.tv_nsec);
                ent.cookie = index + 1;
                if (!vfs_dir_push(resp.data, ent, 48 * 1024)) break;
                ++index;
            }
            ::closedir(dir);
            return;
        }
        if (req.op == GENESIS_VFS_READLINK) {
            if (!need_leaf()) return;
            char buf[512];
            ssize_t n = ::readlinkat(loc.parent, loc.leaf, buf, sizeof(buf));
            if (n < 0) resp.status = errno ? errno : EIO;
            else if (static_cast<size_t>(n) >= sizeof(buf)) resp.status = ENAMETOOLONG;
            else resp.name.assign(buf, static_cast<size_t>(n));
            return;
        }
        if (req.op == GENESIS_VFS_MKDIR) {
            if (!need_leaf()) return;
            mode_t mode = req.mode ? static_cast<mode_t>(req.mode & 07777) : 0755;
            if (::mkdirat(loc.parent, loc.leaf, mode) != 0) resp.status = errno ? errno : EIO;
            return;
        }
        if (req.op == GENESIS_VFS_UNLINK) {
            if (!need_leaf()) return;
            if (::unlinkat(loc.parent, loc.leaf, 0) != 0) resp.status = errno ? errno : EIO;
            return;
        }
        if (req.op == GENESIS_VFS_RMDIR) {
            if (!need_leaf()) return;
            if (::unlinkat(loc.parent, loc.leaf, AT_REMOVEDIR) != 0) resp.status = errno ? errno : EIO;
            return;
        }
        if (req.op == GENESIS_VFS_CHMOD) {
            mode_t mode = static_cast<mode_t>(req.mode & 07777);
            if (loc.root) {
                if (::fchmod(loc.parent, mode) != 0) resp.status = errno ? errno : EIO;
                return;
            }
            struct stat st {};
            if (::fstatat(loc.parent, loc.leaf, &st, AT_SYMLINK_NOFOLLOW) != 0) {
                resp.status = errno ? errno : EIO;
                return;
            }
            if (S_ISLNK(st.st_mode)) {
                resp.status = EOPNOTSUPP;
                return;
            }
            /* fchmod on an O_PATH descriptor returns EBADF. The leaf was just
             * confirmed not to be a symlink; fchmodat follows that check. */
            if (::fchmodat(loc.parent, loc.leaf, mode, 0) != 0) resp.status = errno ? errno : EIO;
            return;
        }
        if (req.op == GENESIS_VFS_UTIMENS) {
            timespec tv[2];
            auto one = [&](uint64_t ns, uint32_t omit, uint32_t now, timespec* t) {
                if (req.flags & omit) {
                    t->tv_sec = 0;
                    t->tv_nsec = UTIME_OMIT;
                } else if (req.flags & now) {
                    t->tv_sec = 0;
                    t->tv_nsec = UTIME_NOW;
                } else {
                    t->tv_sec = static_cast<time_t>(ns / 1000000000ull);
                    t->tv_nsec = static_cast<long>(ns % 1000000000ull);
                }
            };
            one(req.atime_ns, GENESIS_VFS_ATIME_OMIT, GENESIS_VFS_ATIME_NOW, &tv[0]);
            one(req.mtime_ns, GENESIS_VFS_MTIME_OMIT, GENESIS_VFS_MTIME_NOW, &tv[1]);
            const char* leaf = loc.root ? "." : loc.leaf;
            int flags = loc.root ? 0 : AT_SYMLINK_NOFOLLOW;
            if (::utimensat(loc.parent, leaf, tv, flags) != 0) resp.status = errno ? errno : EIO;
            return;
        }
        if (req.op == GENESIS_VFS_SYMLINK) {
            if (!need_leaf()) return;
            if (req.name.empty() || req.name.size() > kVfsMaxPath || req.name[0] == '/' || dotdot_component(req.name.c_str()) ||
                req.name.find('\\') != std::string::npos || req.name.find('\n') != std::string::npos) {
                resp.status = EPERM;
                return;
            }
            if (::symlinkat(req.name.c_str(), loc.parent, loc.leaf) != 0) resp.status = errno ? errno : EIO;
            return;
        }
        if (req.op == GENESIS_VFS_RENAME || req.op == GENESIS_VFS_LINK) {
            if (!need_leaf()) return;
            Loc dest = descend(root, req.name.c_str());
            if (dest.err) {
                resp.status = dest.err;
                return;
            }
            struct DestClose {
                Loc* l;
                ~DestClose() { loc_close(*l); }
            } dc{&dest};
            if (dest.root || !dest.leaf[0]) {
                resp.status = EINVAL;
                return;
            }
            if (req.op == GENESIS_VFS_LINK) {
                if (::linkat(loc.parent, loc.leaf, dest.parent, dest.leaf, 0) != 0) resp.status = errno ? errno : EIO;
                return;
            }
            unsigned fl = 0;
            if (req.flags & GENESIS_VFS_NOREPLACE) fl |= RENAME_NOREPLACE;
            if (req.flags & GENESIS_VFS_EXCHANGE) fl |= RENAME_EXCHANGE;
            if (::renameat2(loc.parent, loc.leaf, dest.parent, dest.leaf, fl) != 0) resp.status = errno ? errno : EIO;
            return;
        }
        if (req.op == GENESIS_VFS_TRUNCATE) {
            if (!need_leaf()) return;
            int fd = ::openat(loc.parent, loc.leaf, O_WRONLY | O_NOFOLLOW | O_CLOEXEC);
            if (fd < 0) {
                resp.status = errno ? errno : EIO;
                return;
            }
            if (::ftruncate(fd, static_cast<off_t>(req.size)) != 0) resp.status = errno ? errno : EIO;
            ::close(fd);
            return;
        }
        if (req.op == GENESIS_VFS_READ || req.op == GENESIS_VFS_WRITE || req.op == GENESIS_VFS_CREATE) {
            if (!need_leaf()) return;
            if (req.op == GENESIS_VFS_READ) {
                int fd = ::openat(loc.parent, loc.leaf, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
                if (fd < 0) {
                    resp.status = errno ? errno : EIO;
                    return;
                }
                struct stat st {};
                if (::fstat(fd, &st) != 0) {
                    resp.status = errno ? errno : EIO;
                    ::close(fd);
                    return;
                }
                if (S_ISDIR(st.st_mode)) {
                    resp.status = EISDIR;
                    ::close(fd);
                    return;
                }
                fill_times(resp, st);
                uint32_t want = req.size > kVfsMaxData ? kVfsMaxData : static_cast<uint32_t>(req.size);
                resp.data.resize(want);
                ssize_t n = want ? pread_all(fd, resp.data.data(), want, req.offset) : 0;
                ::close(fd);
                if (n < 0) {
                    resp.status = errno ? errno : EIO;
                    resp.data.clear();
                    return;
                }
                resp.data.resize(static_cast<size_t>(n));
                return;
            }
            int flags = O_RDWR | O_NOFOLLOW | O_CLOEXEC;
            if (req.op == GENESIS_VFS_CREATE || (req.flags & GENESIS_VFS_CREAT)) flags |= O_CREAT;
            if (req.flags & GENESIS_VFS_EXCL) flags |= O_EXCL;
            if (req.flags & GENESIS_VFS_TRUNC) flags |= O_TRUNC;
            mode_t mode = req.mode ? static_cast<mode_t>(req.mode & 07777) : 0644;
            int fd = ::openat(loc.parent, loc.leaf, flags, mode);
            if (fd < 0) {
                resp.status = errno ? errno : EIO;
                return;
            }
            if (!req.data.empty()) {
                int wrc = pwrite_all(fd, req.data.data(), req.data.size(), req.offset);
                if (wrc != 0) resp.status = wrc;
            }
            struct stat st {};
            if (resp.status == 0 && ::fstat(fd, &st) == 0) fill_times(resp, st);
            ::close(fd);
            return;
        }
        resp.status = EINVAL;
    }

    void send_holes(UdpSocket& sock, Conn& c, uint32_t req, uint16_t count, const std::vector<uint8_t>& missing) {
        uint64_t now = monotonic_us();
        if (c.hole_us && now - c.hole_us < 15000) return;
        c.hole_us = now;
        uint8_t plain[16 + 32];
        if (missing.size() > 32) return;
        plain[0] = 5;
        plain[1] = 0;
        store_be16(plain + 2, count);
        store_be32(plain + 4, req);
        store_be16(plain + 8, static_cast<uint16_t>(missing.size()));
        std::memcpy(plain + 10, missing.data(), missing.size());
        std::vector<uint8_t> dg;
        if (!seal_dg(dg, c.id, c.tx_seq++, c.tx, plain, 10 + missing.size())) return;
        emit(sock, dg.data(), dg.size(), c.addr, c.port);
    }

    void send_reply(UdpSocket& sock, Conn& c, const VfsBlob& resp) {
        std::vector<uint8_t> sealed(128 * 1024);
        size_t n = vfs_seal(sealed.data(), sealed.size(), resp);
        if (!n) return;
        uint16_t frags = static_cast<uint16_t>((n + kChunk - 1) / kChunk);
        if (frags == 0 || frags > kMaxFrags) return;
        c.last_reply.clear();
        c.last_req = resp.req_id;
        c.have_last = true;
        for (uint16_t i = 0; i < frags; ++i) {
            uint16_t len = static_cast<uint16_t>(std::min(kChunk, n - static_cast<size_t>(i) * kChunk));
            uint8_t plain[12 + 1024];
            plain[0] = 4;
            plain[1] = 0x01;
            store_be16(plain + 2, i);
            store_be16(plain + 4, frags);
            store_be32(plain + 6, resp.req_id);
            store_be16(plain + 10, len);
            std::memcpy(plain + 12, sealed.data() + static_cast<size_t>(i) * kChunk, len);
            std::vector<uint8_t> dg;
            if (!seal_dg(dg, c.id, c.tx_seq++, c.tx, plain, 12 + len)) return;
            c.last_reply.push_back(std::move(dg));
        }
        for (const auto& dg : c.last_reply) {
            emit(sock, dg.data(), dg.size(), c.addr, c.port);
            if (c.last_reply.size() > 4) ::usleep(20000);
        }
    }

    void resend_some(UdpSocket& sock, Conn& c, const std::vector<uint8_t>& missing) {
        for (size_t i = 0; i < c.last_reply.size(); ++i) {
            size_t byte = i / 8;
            if (byte >= missing.size()) break;
            if (missing[byte] & (1u << (i % 8))) {
                emit(sock, c.last_reply[i].data(), c.last_reply[i].size(), c.addr, c.port);
                if (c.last_reply.size() > 4) ::usleep(20000);
            }
        }
    }

    void finish_request(UdpSocket& sock, Conn& c) {
        std::vector<uint8_t> raw = c.in.join();
        uint32_t req_id = c.in.req;
        c.in.clear();
        VfsBlob msg;
        VfsBlob resp;
        if (!vfs_open_blob(raw.data(), raw.size(), msg)) {
            resp.op = 0;
            resp.req_id = req_id;
            resp.status = EPROTO;
            send_reply(sock, c, resp);
            return;
        }
        msg.req_id = req_id;
        dispatch(c.export_index, msg, resp);
        resp.req_id = req_id;
        send_reply(sock, c, resp);
    }

    void on_request_frag(UdpSocket& sock, Conn& c, const FragView& frag) {
        if (c.have_last && frag.req == c.last_req) {
            for (const auto& dg : c.last_reply) {
            emit(sock, dg.data(), dg.size(), c.addr, c.port);
            if (c.last_reply.size() > 4) ::usleep(20000);
        }
            return;
        }
        if (c.in.n && frag.req == c.in.req) {
            c.in.req = frag.req;
            if (!c.in.add(frag.index, frag.count, frag.chunk, frag.chunk_len)) return;
            if (c.in.complete()) finish_request(sock, c);
            else {
                std::vector<uint8_t> miss((c.in.n + 7) / 8, 0);
                for (uint16_t i = 0; i < c.in.n; ++i)
                    if (!(c.in.have[i / 8] & (1u << (i % 8)))) miss[i / 8] = static_cast<uint8_t>(miss[i / 8] | (1u << (i % 8)));
                send_holes(sock, c, frag.req, c.in.n, miss);
            }
            return;
        }
        if (c.have_last && older_req(frag.req, c.last_req)) return;
        if (c.in.n && older_req(frag.req, c.in.req)) return;
        c.in.clear();
        c.in.req = frag.req;
        if (!c.in.add(frag.index, frag.count, frag.chunk, frag.chunk_len)) return;
        c.in.req = frag.req;
        if (c.in.complete()) finish_request(sock, c);
    }

    Conn* find_conn(uint32_t id, uint32_t addr, uint16_t port) {
        for (auto& c : conns)
            if (c.used && c.id == id && c.addr == addr && c.port == port) return &c;
        return nullptr;
    }

    Conn* alloc_conn(uint32_t id, uint32_t addr, uint16_t port) {
        Conn* slot = nullptr;
        for (auto& c : conns)
            if (!c.used) {
                slot = &c;
                break;
            }
        if (!slot) {
            slot = &conns[0];
            uint64_t oldest = slot->last_us;
            for (auto& c : conns)
                if (c.last_us <= oldest) {
                    oldest = c.last_us;
                    slot = &c;
                }
            if (slot->export_index >= 0) {
                /* keys are overwritten below */
            }
            secure_zero(slot->tx, sizeof(slot->tx));
            secure_zero(slot->rx, sizeof(slot->rx));
        }
        *slot = Conn{};
        slot->used = true;
        slot->id = id;
        slot->addr = addr;
        slot->port = port;
        slot->last_us = monotonic_us();
        return slot;
    }

    void reply_hello(UdpSocket& sock, uint32_t conn, uint32_t addr, uint16_t port, uint8_t status, const uint8_t* pub,
                     const uint8_t* nonce, std::vector<uint8_t>* saved) {
        uint8_t payload[64]{};
        payload[0] = 2;
        payload[1] = status;
        if (pub) std::memcpy(payload + 2, pub, 32);
        if (nonce) std::memcpy(payload + 34, nonce, 16);
        Header h;
        h.version = kProtoVersion;
        h.type = kVfs;
        h.conn_id = conn;
        h.payload_len = 50;
        std::vector<uint8_t> dg(kHeaderBytes + 50);
        encode_header(dg.data(), dg.size(), h);
        std::memcpy(dg.data() + kHeaderBytes, payload, 50);
        if (saved) *saved = dg;
        emit(sock, dg.data(), dg.size(), addr, port);
    }

    void accept_hello(UdpSocket& sock, const Header& h, const uint8_t* payload, size_t plen, uint32_t addr, uint16_t port) {
        if (plen < 50 || payload[0] != 1) return;
        uint8_t name_len = payload[49];
        if (50u + name_len != plen || name_len > 31) return;
        char name[32]{};
        std::memcpy(name, payload + 50, name_len);
        Conn* existing = find_conn(h.conn_id, addr, port);
        if (existing && existing->keyed) {
            if (!existing->hello_dg.empty())
                emit(sock, existing->hello_dg.data(), existing->hello_dg.size(), addr, port);
            if (!existing->confirm_dg.empty())
                emit(sock, existing->confirm_dg.data(), existing->confirm_dg.size(), addr, port);
            return;
        }
        int ix = name[0] ? find_export(name) : -1;
        if (name[0] && ix < 0) {
            reply_hello(sock, h.conn_id, addr, port, static_cast<uint8_t>(ENOENT > 255 ? 255 : ENOENT), nullptr, nullptr,
                        nullptr);
            return;
        }
        if (have_expect && !ct_equal(expect_pub, payload + 1, 32)) {
            reply_hello(sock, h.conn_id, addr, port, static_cast<uint8_t>(EACCES), nullptr, nullptr, nullptr);
            return;
        }
        Conn* c = existing ? existing : alloc_conn(h.conn_id, addr, port);
        c->export_index = ix;
        uint8_t sec[32], pub[32], shared[32];
        x25519_keypair(pub, sec);
        uint8_t my_nonce[16];
        random_bytes(my_nonce, 16);
        x25519(shared, sec, payload + 1);
        uint8_t i2r[32], r2i[32];
        derive_transport_keys(shared, psk, have_psk, payload + 33, my_nonce, i2r, r2i);
        std::memcpy(c->rx, i2r, 32);
        std::memcpy(c->tx, r2i, 32);
        secure_zero(sec, sizeof(sec));
        secure_zero(shared, sizeof(shared));
        secure_zero(i2r, sizeof(i2r));
        secure_zero(r2i, sizeof(r2i));
        c->keyed = true;
        c->confirmed = false;
        c->tx_seq = 2;
        reply_hello(sock, h.conn_id, addr, port, 0, pub, my_nonce, &c->hello_dg);
        uint8_t dig[32];
        Sha256 hash;
        hash.update(payload, plen);
        hash.update(c->hello_dg.data() + kHeaderBytes, 50);
        hash.final(dig);
        std::memcpy(c->transcript, dig, 32);
        uint8_t plain[33];
        plain[0] = 3;
        std::memcpy(plain + 1, dig, 32);
        seal_dg(c->confirm_dg, c->id, 1, c->tx, plain, 33);
        emit(sock, c->confirm_dg.data(), c->confirm_dg.size(), addr, port);
    }

    void on_udp(UdpSocket& sock, const uint8_t* data, size_t len, uint32_t addr, uint16_t port) {
        Header h;
        if (!decode_header(data, len, h) || h.type != kVfs || h.version != kProtoVersion || h.ext_len != 0) return;
        const uint8_t* payload = data + kHeaderBytes;
        if (!(h.flags & kFlagEncrypted)) {
            if (h.payload_len >= 1 && payload[0] == 1) accept_hello(sock, h, payload, h.payload_len, addr, port);
            return;
        }
        Conn* c = find_conn(h.conn_id, addr, port);
        if (!c || !c->keyed) return;
        c->last_us = monotonic_us();
        std::vector<uint8_t> plain;
        if (!open_dg(data, h, c->rx, plain) || plain.empty()) return;
        if (plain[0] == 3) {
            /* Decrypting with the server rx key already proves the client has the shared secret.
             * The digest must be the transcript both sides hashed, which is also what we sent. */
            if (plain.size() == 33 && ct_equal(plain.data() + 1, c->transcript, 32)) c->confirmed = true;
            return;
        }
        if (!c->confirmed) return;
        FragView frag;
        if (!parse_frag(plain.data(), plain.size(), frag)) return;
        if (frag.hole) {
            if ((frag.flags & 0x01) && frag.req == c->last_req) resend_some(sock, *c, frag.bitmap);
            return;
        }
        if (frag.flags & 0x01) return;
        on_request_frag(sock, *c, frag);
    }

    void on_control_frame(Ctrl& client, const uint8_t* p, size_t n) {
        VfsBlob msg;
        VfsBlob resp;
        if (!vfs_open_blob(p, n, msg)) {
            resp.status = EPROTO;
        } else {
            dispatch(client.export_index, msg, resp);
            resp.req_id = msg.req_id;
            resp.op = msg.op;
        }
        std::vector<uint8_t> sealed(128 * 1024);
        size_t sn = vfs_seal(sealed.data(), sealed.size(), resp);
        if (!sn) return;
        int flags = ::fcntl(client.fd, F_GETFL, 0);
        if (flags >= 0) ::fcntl(client.fd, F_SETFL, flags & ~O_NONBLOCK);
        if (!write_frame(client.fd, sealed.data(), sn)) client.dead = true;
        if (flags >= 0) ::fcntl(client.fd, F_SETFL, flags | O_NONBLOCK);
    }
};

namespace {

bool load_hex32(const char* hex, uint8_t out[32], bool* have) {
    *have = false;
    if (!hex || !hex[0]) return true;
    if (!from_hex(hex, out, 32)) return false;
    *have = true;
    return true;
}

void reap_ctrl(VfsHub* hub) {
    int w = 0;
    for (int i = 0; i < hub->ctrl_n; ++i) {
        if (hub->ctrl[i].dead) {
            if (hub->ctrl[i].fd >= 0) ::close(hub->ctrl[i].fd);
            continue;
        }
        if (w != i) hub->ctrl[w] = std::move(hub->ctrl[i]);
        ++w;
    }
    hub->ctrl_n = w;
}

}  // namespace

VfsHub* vfs_hub_create(const genesis_config* cfg) {
    if (!cfg) return nullptr;
    VfsHub* hub = new VfsHub();
    if (!load_hex32(cfg->psk_hex, hub->psk, &hub->have_psk) ||
        !load_hex32(cfg->expect_pub_hex, hub->expect_pub, &hub->have_expect)) {
        delete hub;
        return nullptr;
    }
    hub->ex_count = cfg->export_count;
    if (hub->ex_count > GENESIS_EXPORT_MAX) hub->ex_count = GENESIS_EXPORT_MAX;
    for (int i = 0; i < hub->ex_count; ++i) {
        std::snprintf(hub->ex[i].name, sizeof(hub->ex[i].name), "%s", cfg->export_name[i]);
        std::snprintf(hub->ex[i].path, sizeof(hub->ex[i].path), "%s", cfg->export_path[i]);
        hub->ex[i].rw = cfg->export_rw[i];
        hub->ex[i].fd = -1;
    }
    return hub;
}

void vfs_hub_destroy(VfsHub* hub) {
    if (!hub) return;
    for (int i = 0; i < hub->ex_count; ++i)
        if (hub->ex[i].fd >= 0) ::close(hub->ex[i].fd);
    for (int i = 0; i < hub->ctrl_n; ++i)
        if (hub->ctrl[i].fd >= 0) ::close(hub->ctrl[i].fd);
    for (auto& c : hub->conns) {
        secure_zero(c.tx, sizeof(c.tx));
        secure_zero(c.rx, sizeof(c.rx));
    }
    secure_zero(hub->psk, sizeof(hub->psk));
    delete hub;
}

bool vfs_is_packet(const uint8_t* data, size_t len) {
    Header h;
    return decode_header(data, len, h) && h.type == kVfs && h.version == kProtoVersion;
}

void vfs_hub_packet(VfsHub* hub, UdpSocket& sock, const uint8_t* data, size_t len, uint32_t addr, uint16_t port) {
    if (!hub) return;
    hub->on_udp(sock, data, len, addr, port);
}

int vfs_hub_fill_fds(VfsHub* hub, int* fds, int cap) {
    if (!hub || !fds || cap <= 0) return 0;
    reap_ctrl(hub);
    int n = hub->ctrl_n < cap ? hub->ctrl_n : cap;
    for (int i = 0; i < n; ++i) fds[i] = hub->ctrl[i].fd;
    return n;
}

void vfs_hub_on_fd(VfsHub* hub, int fd) {
    if (!hub) return;
    for (int i = 0; i < hub->ctrl_n; ++i) {
        Ctrl& client = hub->ctrl[i];
        if (client.fd != fd || client.dead) continue;
        uint8_t tmp[8192];
        ssize_t n = ::read(fd, tmp, sizeof(tmp));
        if (n == 0 || (n < 0 && errno != EINTR && errno != EAGAIN)) {
            client.dead = true;
            return;
        }
        if (n < 0) return;
        client.in.insert(client.in.end(), tmp, tmp + n);
        while (!client.dead) {
            if (client.need == 0) {
                if (client.in.size() < 4) return;
                client.need = load_be32(client.in.data());
                client.in.erase(client.in.begin(), client.in.begin() + 4);
                if (client.need == 0 || client.need > 200000) {
                    client.dead = true;
                    return;
                }
            }
            if (client.in.size() < client.need) return;
            hub->on_control_frame(client, client.in.data(), client.need);
            client.in.erase(client.in.begin(), client.in.begin() + client.need);
            client.need = 0;
        }
        return;
    }
}

int vfs_hub_attach(VfsHub* hub, int fd, const char* export_name) {
    if (!hub || fd < 0) return -1;
    reap_ctrl(hub);
    if (hub->ctrl_n >= kMaxCtrl) {
        dprintf(fd, "ERR %d too many vfs clients\n", GENESIS_ERR);
        ::close(fd);
        return -1;
    }
    int ix = -1;
    if (export_name && export_name[0]) {
        ix = hub->find_export(export_name);
        if (ix < 0) {
            dprintf(fd, "ERR %d unknown export\n", GENESIS_ERR_ARGS);
            ::close(fd);
            return -1;
        }
    }
    dprintf(fd, "OK\n");
    int flags = ::fcntl(fd, F_GETFL, 0);
    if (flags >= 0) ::fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    Ctrl& client = hub->ctrl[hub->ctrl_n++];
    client = Ctrl{};
    client.fd = fd;
    client.export_index = ix;
    return 0;
}

void vfs_hub_set_lose(VfsHub* hub, int every) {
    if (!hub) return;
    hub->lose_every.store(every > 1 ? every : 0);
}

}  // namespace genesis

struct genesis_vfs {
    std::mutex mu;
    bool control = false;
    int fd = -1;
    genesis::UdpSocket sock;
    uint32_t peer = 0;
    uint16_t peer_port = 0;
    uint32_t conn = 0;
    uint8_t secret[32]{};
    uint8_t pub[32]{};
    uint8_t nonce[16]{};
    uint8_t tx[32]{};
    uint8_t rx[32]{};
    uint8_t psk[32]{};
    bool have_psk = false;
    uint8_t expect_pub[32]{};
    bool have_expect = false;
    bool ready = false;
    bool saw_hello = false;
    int hello_status = 0;
    uint64_t tx_seq = 2;
    uint32_t next_req = 1;
    std::string export_name;
    std::vector<uint8_t> hello_dg;
    std::vector<uint8_t> hello_payload;
    std::vector<uint8_t> confirm_dg;
    std::vector<uint8_t> early;
    uint8_t transcript[32]{};
};

struct genesis_vfs_server {
    genesis::VfsHub* hub = nullptr;
    genesis::UdpSocket sock;
    genesis::UdpSocket disco;
    bool disco_on = false;
    int listen_fd = -1;
    std::atomic<int> stop{0};
    std::thread thr;
    bool ssh_pipe = false;
    char node_name[32]{};
    char exp_name[GENESIS_EXPORT_MAX][32]{};
    uint8_t exp_rw[GENESIS_EXPORT_MAX]{};
    int exp_count = 0;
    uint16_t port = 0;
    uint64_t last_beacon = 0;
};

namespace genesis {
namespace {

int clean_rel(const char* in, std::string& out) {
    out.clear();
    if (!in) return 0;
    while (*in == '/') ++in;
    if (std::strchr(in, '\\') || std::strchr(in, '\n') || dotdot_component(in)) return -1;
    out = in;
    while (out.size() > 1 && out.back() == '/') out.pop_back();
    return 0;
}

bool fill_blob(VfsBlob& b, const genesis_vfs_req* req) {
    b = VfsBlob{};
    if (!req) return false;
    b.op = static_cast<uint8_t>(req->op);
    b.flags = static_cast<uint8_t>(req->flags);
    b.mode = req->mode;
    b.offset = req->offset;
    b.size = req->size;
    b.mtime_ns = req->mtime_ns;
    b.atime_ns = req->atime_ns;
    if (clean_rel(req->path, b.path) != 0) return false;
    if (req->op == GENESIS_VFS_SYMLINK) {
        if (!req->name || !req->name[0] || req->name[0] == '/' || std::strchr(req->name, '\\') ||
            std::strchr(req->name, '\n') || dotdot_component(req->name))
            return false;
        b.name = req->name;
    } else if (req->op == GENESIS_VFS_RENAME || req->op == GENESIS_VFS_LINK) {
        if (clean_rel(req->name, b.name) != 0) return false;
    } else if (req->name) {
        b.name = req->name;
    }
    if (req->data && req->data_len) {
        if (req->data_len > kVfsMaxData) return false;
        b.data.assign(req->data, req->data + req->data_len);
    }
    return true;
}

void to_res(const VfsBlob& b, genesis_vfs_res* res) {
    res->status = b.status;
    res->mode = b.mode;
    res->nlink = b.nlink;
    res->uid = b.uid;
    res->gid = b.gid;
    res->size = b.size;
    res->mtime_ns = b.mtime_ns;
    res->atime_ns = b.atime_ns;
    std::snprintf(res->name, sizeof(res->name), "%s", b.name.c_str());
    res->data_len = static_cast<uint32_t>(b.data.size());
    if (res->data && res->data_cap && !b.data.empty()) {
        uint32_t n = res->data_len < res->data_cap ? res->data_len : res->data_cap;
        std::memcpy(res->data, b.data.data(), n);
        if (n < b.data.size() && res->status == 0) res->status = ERANGE;
    }
}

void take_server_hello(genesis_vfs* c, const uint8_t* payload, size_t plen) {
    if (plen < 50 || payload[0] != 2) return;
    c->hello_status = payload[1];
    if (c->hello_status != 0) return;
    if (c->have_expect && !ct_equal(c->expect_pub, payload + 2, 32)) {
        c->hello_status = EACCES;
        return;
    }
    if (c->saw_hello) return;
    uint8_t shared[32], i2r[32], r2i[32];
    x25519(shared, c->secret, payload + 2);
    derive_transport_keys(shared, c->psk, c->have_psk, c->nonce, payload + 34, i2r, r2i);
    std::memcpy(c->tx, i2r, 32);
    std::memcpy(c->rx, r2i, 32);
    secure_zero(shared, sizeof(shared));
    secure_zero(i2r, sizeof(i2r));
    secure_zero(r2i, sizeof(r2i));
    secure_zero(c->secret, sizeof(c->secret));
    Sha256 hash;
    hash.update(c->hello_payload.data(), c->hello_payload.size());
    hash.update(payload, 50);
    hash.final(c->transcript);
    uint8_t plain[33];
    plain[0] = 3;
    std::memcpy(plain + 1, c->transcript, 32);
    seal_dg(c->confirm_dg, c->conn, 1, c->tx, plain, sizeof(plain));
    c->tx_seq = 2;
    c->saw_hello = true;
    c->sock.send_to(c->confirm_dg.data(), c->confirm_dg.size(), c->peer, c->peer_port);
}

bool handle_udp(genesis_vfs* c, const uint8_t* data, size_t len, Assembly* resp, const std::vector<std::vector<uint8_t>>* req_dgs) {
    Header h;
    if (!decode_header(data, len, h) || h.type != kVfs || h.version != kProtoVersion || h.conn_id != c->conn) return false;
    const uint8_t* payload = data + kHeaderBytes;
    if (!(h.flags & kFlagEncrypted)) {
        if (h.payload_len >= 1 && payload[0] == 2) {
            bool had = c->saw_hello;
            take_server_hello(c, payload, h.payload_len);
            if (!had && c->saw_hello && !c->early.empty()) {
                std::vector<uint8_t> early = std::move(c->early);
                c->early.clear();
                return handle_udp(c, early.data(), early.size(), resp, req_dgs);
            }
        }
        return false;
    }
    if (!c->saw_hello) {
        c->early.assign(data, data + len);
        return false;
    }
    std::vector<uint8_t> plain;
    if (!open_dg(data, h, c->rx, plain) || plain.empty()) return false;
    if (plain[0] == 3) {
        if (plain.size() == 33 && ct_equal(plain.data() + 1, c->transcript, 32)) c->ready = true;
        return false;
    }
    if (!c->ready || !resp) return false;
    FragView frag;
    if (!parse_frag(plain.data(), plain.size(), frag)) return false;
    if (frag.hole) {
        if (!(frag.flags & 0x01) && req_dgs && frag.req == resp->req) {
            for (size_t i = 0; i < req_dgs->size(); ++i) {
                size_t byte = i / 8;
                if (byte < frag.bitmap.size() && (frag.bitmap[byte] & (1u << (i % 8))))
                    c->sock.send_to((*req_dgs)[i].data(), (*req_dgs)[i].size(), c->peer, c->peer_port);
            }
        }
        return false;
    }
    if (!(frag.flags & 0x01) || frag.req != resp->req) return false;
    if (!resp->add(frag.index, frag.count, frag.chunk, frag.chunk_len)) return false;
    resp->req = frag.req;
    return resp->complete();
}

void client_hole(genesis_vfs* c, const Assembly& box) {
    if (!box.n || box.n > kMaxFrags) return;
    std::vector<uint8_t> miss(static_cast<size_t>((box.n + 7) / 8), 0);
    for (uint16_t i = 0; i < box.n; ++i)
        if (i / 8 >= box.have.size() || !(box.have[i / 8] & (1u << (i % 8))))
            miss[i / 8] = static_cast<uint8_t>(miss[i / 8] | (1u << (i % 8)));
    uint8_t plain[48];
    plain[0] = 5;
    plain[1] = 0x01;
    store_be16(plain + 2, box.n);
    store_be32(plain + 4, box.req);
    store_be16(plain + 8, static_cast<uint16_t>(miss.size()));
    std::memcpy(plain + 10, miss.data(), miss.size());
    std::vector<uint8_t> dg;
    if (!seal_dg(dg, c->conn, c->tx_seq++, c->tx, plain, 10 + miss.size())) return;
    c->sock.send_to(dg.data(), dg.size(), c->peer, c->peer_port);
}

int handshake(genesis_vfs* c, int timeout_ms) {
    if (timeout_ms <= 0) timeout_ms = 8000;
    if (c->hello_dg.empty()) {
        x25519_keypair(c->pub, c->secret);
        random_bytes(c->nonce, 16);
        random_bytes(reinterpret_cast<uint8_t*>(&c->conn), sizeof(c->conn));
        if (c->conn == 0) c->conn = 1;
        uint8_t payload[96];
        payload[0] = 1;
        std::memcpy(payload + 1, c->pub, 32);
        std::memcpy(payload + 33, c->nonce, 16);
        size_t nl = c->export_name.size() > 31 ? 31 : c->export_name.size();
        payload[49] = static_cast<uint8_t>(nl);
        if (nl) std::memcpy(payload + 50, c->export_name.data(), nl);
        size_t plen = 50 + nl;
        c->hello_payload.assign(payload, payload + plen);
        Header h;
        h.version = kProtoVersion;
        h.type = kVfs;
        h.conn_id = c->conn;
        h.payload_len = static_cast<uint16_t>(plen);
        c->hello_dg.assign(kHeaderBytes + plen, 0);
        encode_header(c->hello_dg.data(), c->hello_dg.size(), h);
        std::memcpy(c->hello_dg.data() + kHeaderBytes, payload, plen);
    }
    uint64_t deadline = monotonic_us() + static_cast<uint64_t>(timeout_ms) * 1000ull;
    uint64_t last = 0;
    while (monotonic_us() < deadline && !c->ready && c->hello_status == 0) {
        uint64_t now = monotonic_us();
        if (now - last > 40000) {
            if (!c->saw_hello) c->sock.send_to(c->hello_dg.data(), c->hello_dg.size(), c->peer, c->peer_port);
            else if (!c->confirm_dg.empty())
                c->sock.send_to(c->confirm_dg.data(), c->confirm_dg.size(), c->peer, c->peer_port);
            last = now;
        }
        uint8_t buf[1600];
        uint32_t addr = 0;
        uint16_t port = 0;
        int n = c->sock.recv_from(buf, sizeof(buf), &addr, &port, 40);
        if (n > 0) handle_udp(c, buf, static_cast<size_t>(n), nullptr, nullptr);
    }
    if (c->hello_status) {
        logf(1, "vfs: peer refused export (%d)", c->hello_status);
        return GENESIS_ERR;
    }
    if (!c->ready) return GENESIS_ERR_TIMEOUT;
    return GENESIS_OK;
}

int udp_call(genesis_vfs* c, VfsBlob msg, VfsBlob& out, int timeout_ms) {
    if (!c->ready) return GENESIS_ERR;
    if (timeout_ms <= 0) timeout_ms = 8000;
    for (int i = 0; i < 32; ++i) {
        uint8_t junk[1600];
        uint32_t a = 0;
        uint16_t p = 0;
        if (c->sock.recv_from(junk, sizeof(junk), &a, &p, 0) <= 0) break;
    }
    msg.req_id = c->next_req++;
    std::vector<uint8_t> sealed(128 * 1024);
    size_t n = vfs_seal(sealed.data(), sealed.size(), msg);
    if (!n) return GENESIS_ERR;
    uint16_t frags = static_cast<uint16_t>((n + kChunk - 1) / kChunk);
    if (frags == 0 || frags > kMaxFrags) return GENESIS_ERR;
    std::vector<std::vector<uint8_t>> dgs;
    for (uint16_t i = 0; i < frags; ++i) {
        uint16_t len = static_cast<uint16_t>(std::min(kChunk, n - static_cast<size_t>(i) * kChunk));
        uint8_t plain[12 + 1024];
        plain[0] = 4;
        plain[1] = 0;
        store_be16(plain + 2, i);
        store_be16(plain + 4, frags);
        store_be32(plain + 6, msg.req_id);
        store_be16(plain + 10, len);
        std::memcpy(plain + 12, sealed.data() + static_cast<size_t>(i) * kChunk, len);
        std::vector<uint8_t> dg;
        if (!seal_dg(dg, c->conn, c->tx_seq++, c->tx, plain, 12 + len)) return GENESIS_ERR_CRYPTO;
        c->sock.send_to(dg.data(), dg.size(), c->peer, c->peer_port);
        dgs.push_back(std::move(dg));
        if (frags > 4) ::usleep(8000);
    }
    Assembly box;
    box.req = msg.req_id;
    uint64_t deadline = monotonic_us() + static_cast<uint64_t>(timeout_ms) * 1000ull;
    uint64_t last_tx = monotonic_us();
    uint64_t hole_us = 0;
    int backoff = 800;
    while (monotonic_us() < deadline) {
        uint64_t now = monotonic_us();
        int left = static_cast<int>((deadline - now) / 1000);
        if (left < 1) left = 1;
        int slice = left < 40 ? left : 40;
        uint8_t buf[1600];
        uint32_t addr = 0;
        uint16_t port = 0;
        int got = c->sock.recv_from(buf, sizeof(buf), &addr, &port, slice);
        bool progressed = false;
        if (got > 0) {
            progressed = handle_udp(c, buf, static_cast<size_t>(got), &box, &dgs);
            if (box.got) last_tx = monotonic_us();
            if (progressed && box.complete()) {
                std::vector<uint8_t> raw = box.join();
                if (!vfs_open_blob(raw.data(), raw.size(), out)) return GENESIS_ERR_PROTO;
                return GENESIS_OK;
            }
        }
        now = monotonic_us();
        if (box.got && !box.complete() && now - hole_us > 15000) {
            client_hole(c, box);
            hole_us = now;
        }
        if (now - last_tx >= static_cast<uint64_t>(backoff) * 1000ull) {
            for (const auto& dg : dgs) c->sock.send_to(dg.data(), dg.size(), c->peer, c->peer_port);
            last_tx = now;
            if (backoff < 200) backoff *= 2;
        }
    }
    return GENESIS_ERR_TIMEOUT;
}

int dial_control(const char* spec) {
    if (!spec || !spec[0]) return -1;
    if (std::strchr(spec, '/') || std::strncmp(spec, "unix:", 5) == 0) {
        const char* path = std::strncmp(spec, "unix:", 5) == 0 ? spec + 5 : spec;
        if (std::strlen(path) >= sizeof(sockaddr_un{}.sun_path)) return -1;
        int fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
        if (fd < 0) return -1;
        sockaddr_un addr{};
        addr.sun_family = AF_UNIX;
        std::snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", path);
        if (::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
            ::close(fd);
            return -1;
        }
        return fd;
    }
    const char* colon = std::strrchr(spec, ':');
    if (!colon || colon == spec) return -1;
    char host[128];
    size_t hn = static_cast<size_t>(colon - spec);
    if (hn >= sizeof(host)) return -1;
    std::memcpy(host, spec, hn);
    host[hn] = '\0';
    int port = std::atoi(colon + 1);
    if (port <= 0 || port > 65535) return -1;
    int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(static_cast<uint16_t>(port));
    if (::inet_pton(AF_INET, host, &addr.sin_addr) != 1 ||
        ::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        ::close(fd);
        return -1;
    }
    return fd;
}

bool read_line(int fd, char* buf, size_t cap, uint64_t deadline) {
    size_t n = 0;
    while (n + 1 < cap) {
        uint8_t c = 0;
        if (!read_full_until(fd, &c, 1, deadline)) return false;
        buf[n++] = static_cast<char>(c);
        if (c == '\n') {
            buf[n] = '\0';
            return true;
        }
    }
    return false;
}

int control_call(genesis_vfs* c, const VfsBlob& msg, VfsBlob& out, int timeout_ms) {
    if (timeout_ms <= 0) timeout_ms = 8000;
    std::vector<uint8_t> sealed(128 * 1024);
    size_t n = vfs_seal(sealed.data(), sealed.size(), msg);
    if (!n) return GENESIS_ERR;
    uint64_t deadline = monotonic_us() + static_cast<uint64_t>(timeout_ms) * 1000ull;
    if (!write_frame(c->fd, sealed.data(), n)) return GENESIS_ERR_NET;
    uint8_t lenb[4];
    if (!read_full_until(c->fd, lenb, 4, deadline)) return GENESIS_ERR_TIMEOUT;
    uint32_t len = load_be32(lenb);
    if (len == 0 || len > sealed.size()) return GENESIS_ERR_PROTO;
    if (!read_full_until(c->fd, sealed.data(), len, deadline)) return GENESIS_ERR_TIMEOUT;
    if (!vfs_open_blob(sealed.data(), len, out)) return GENESIS_ERR_PROTO;
    return GENESIS_OK;
}

bool read_attach_header(int fd, char* exp, size_t cap) {
    std::string buf;
    uint64_t deadline = monotonic_us() + 2000000ull;
    while (buf.size() < 2 || buf[buf.size() - 2] != '\n' || buf.back() != '\n') {
        if (buf.size() > 4000) return false;
        uint8_t c = 0;
        if (!read_full_until(fd, &c, 1, deadline)) return false;
        buf.push_back(static_cast<char>(c));
    }
    exp[0] = '\0';
    bool cmd = false;
    size_t i = 0;
    while (i < buf.size()) {
        size_t e = buf.find('\n', i);
        if (e == std::string::npos) break;
        std::string line = buf.substr(i, e - i);
        i = e + 1;
        auto eq = line.find('=');
        if (eq == std::string::npos) continue;
        std::string key = line.substr(0, eq);
        std::string val = line.substr(eq + 1);
        if (key == "command" && val == "vfs") cmd = true;
        if (key == "export" && val.size() < cap) std::snprintf(exp, cap, "%s", val.c_str());
    }
    return cmd;
}

void server_loop(genesis_vfs_server* s) {
    while (!s->stop.load()) {
        if (s->ssh_pipe) {
            pollfd hp{};
            hp.fd = 0;
            hp.events = POLLIN;
            if (::poll(&hp, 1, 0) > 0) {
                if (hp.revents & (POLLHUP | POLLERR | POLLNVAL)) {
                    s->stop.store(1);
                    break;
                }
                if (hp.revents & POLLIN) {
                    char b[64];
                    ssize_t n = ::read(0, b, sizeof(b));
                    if (n == 0) {
                        s->stop.store(1);
                        break;
                    }
                }
            }
        }
        uint64_t now = monotonic_us();
        if (s->disco_on && now - s->last_beacon > 2000000ull) {
            Beacon b;
            b.port = s->port;
            b.features = kFeatVfs | kFeatDiscovery | kFeatFile;
            std::snprintf(b.name, sizeof(b.name), "%s", s->node_name);
            uint8_t pkt[512];
            size_t len = beacon_encode(pkt, sizeof(pkt), b);
            if (s->exp_count)
                len = beacon_append_exports(pkt, sizeof(pkt), len, s->exp_name, s->exp_rw, s->exp_count);
            if (len) s->disco.send_to(pkt, len, kDiscoveryGroup, kDiscoveryPort);
            s->last_beacon = now;
        }
        pollfd pf[10];
        int nfd = 0;
        pf[nfd].fd = s->sock.fd();
        pf[nfd].events = POLLIN;
        pf[nfd].revents = 0;
        int udp_slot = nfd++;
        int listen_slot = -1;
        if (s->listen_fd >= 0) {
            pf[nfd].fd = s->listen_fd;
            pf[nfd].events = POLLIN;
            pf[nfd].revents = 0;
            listen_slot = nfd++;
        }
        int extra_fds[8];
        int extra = vfs_hub_fill_fds(s->hub, extra_fds, 8);
        int extra_base = nfd;
        for (int i = 0; i < extra && nfd < 10; ++i) {
            pf[nfd].fd = extra_fds[i];
            pf[nfd].events = POLLIN;
            pf[nfd].revents = 0;
            ++nfd;
        }
        int pr = ::poll(pf, static_cast<nfds_t>(nfd), 50);
        if (pr < 0 && errno == EINTR) continue;
        if (pr > 0 && listen_slot >= 0 && (pf[listen_slot].revents & POLLIN)) {
            int cfd = ::accept(s->listen_fd, nullptr, nullptr);
            if (cfd >= 0) {
                char exp[32];
                if (!read_attach_header(cfd, exp, sizeof(exp))) ::close(cfd);
                else vfs_hub_attach(s->hub, cfd, exp);
            }
        }
        if (pr > 0) {
            for (int i = 0; i < extra && extra_base + i < nfd; ++i)
                if (pf[extra_base + i].revents & (POLLIN | POLLHUP | POLLERR)) vfs_hub_on_fd(s->hub, extra_fds[i]);
        }
        if (pr > 0 && (pf[udp_slot].revents & (POLLIN | POLLERR))) {
            uint8_t buf[1600];
            uint32_t addr = 0;
            uint16_t port = 0;
            int n = s->sock.recv_from(buf, sizeof(buf), &addr, &port, 0);
            if (n > 0) vfs_hub_packet(s->hub, s->sock, buf, static_cast<size_t>(n), addr, port);
        }
    }
}

int load_client_keys(genesis_vfs* c, const genesis_config* cfg) {
    c->have_psk = false;
    c->have_expect = false;
    if (!cfg) return 0;
    if (cfg->psk_hex[0] && !from_hex(cfg->psk_hex, c->psk, 32)) return -1;
    if (cfg->psk_hex[0]) c->have_psk = true;
    if (cfg->expect_pub_hex[0] && !from_hex(cfg->expect_pub_hex, c->expect_pub, 32)) return -1;
    if (cfg->expect_pub_hex[0]) c->have_expect = true;
    return 0;
}

}  // namespace
}  // namespace genesis

extern "C" genesis_vfs* genesis_vfs_connect(const genesis_config* cfg, const char* host, uint16_t port,
                                            const char* export_name, int timeout_ms) {
    if (!cfg || !host || !host[0] || port == 0) return nullptr;
    auto* c = new genesis_vfs();
    if (genesis::load_client_keys(c, cfg) != 0) {
        delete c;
        return nullptr;
    }
    if (export_name) c->export_name = export_name;
    if (!genesis::ipv4_resolve(host, &c->peer)) {
        delete c;
        return nullptr;
    }
    c->peer_port = port;
    if (!c->sock.open(cfg->bind_host[0] ? cfg->bind_host : "0.0.0.0", 0, cfg->socket_buffer > 0 ? cfg->socket_buffer : 1 << 20,
                      false)) {
        delete c;
        return nullptr;
    }
    int rc;
    {
        std::lock_guard<std::mutex> lock(c->mu);
        rc = genesis::handshake(c, timeout_ms);
    }
    if (rc != GENESIS_OK) {
        delete c;
        return nullptr;
    }
    return c;
}

extern "C" genesis_vfs* genesis_vfs_connect_control(const char* spec, const char* export_name, int timeout_ms) {
    int fd = genesis::dial_control(spec);
    if (fd < 0) return nullptr;
    std::string exp = export_name ? export_name : "";
    if (exp.find('\n') != std::string::npos) {
        ::close(fd);
        return nullptr;
    }
    dprintf(fd, "command=vfs\nexport=%s\n\n", exp.c_str());
    char line[128];
    uint64_t deadline = genesis::monotonic_us() + static_cast<uint64_t>(timeout_ms > 0 ? timeout_ms : 8000) * 1000ull;
    if (!genesis::read_line(fd, line, sizeof(line), deadline) || std::strncmp(line, "OK", 2) != 0) {
        ::close(fd);
        return nullptr;
    }
    auto* c = new genesis_vfs();
    c->control = true;
    c->fd = fd;
    c->ready = true;
    c->export_name = exp;
    return c;
}

extern "C" void genesis_vfs_close(genesis_vfs* session) {
    if (!session) return;
    {
        std::lock_guard<std::mutex> lock(session->mu);
        if (session->fd >= 0) ::close(session->fd);
        session->fd = -1;
        genesis::secure_zero(session->secret, sizeof(session->secret));
        genesis::secure_zero(session->tx, sizeof(session->tx));
        genesis::secure_zero(session->rx, sizeof(session->rx));
        genesis::secure_zero(session->psk, sizeof(session->psk));
        session->sock.close();
    }
    delete session;
}

extern "C" int genesis_vfs_call(genesis_vfs* session, const genesis_vfs_req* req, genesis_vfs_res* res, int timeout_ms) {
    if (!session || !req || !res) return GENESIS_ERR_ARGS;
    std::lock_guard<std::mutex> lock(session->mu);
    genesis::VfsBlob msg;
    genesis::VfsBlob out;
    if (!genesis::fill_blob(msg, req)) return GENESIS_ERR_JAIL;
    int rc = session->control ? genesis::control_call(session, msg, out, timeout_ms)
                              : genesis::udp_call(session, msg, out, timeout_ms);
    if (rc != GENESIS_OK) return rc;
    genesis::to_res(out, res);
    return GENESIS_OK;
}

extern "C" genesis_vfs_server* genesis_vfs_server_start(const genesis_config* cfg) {
    if (!cfg) return nullptr;
    auto* s = new genesis_vfs_server();
    s->hub = genesis::vfs_hub_create(cfg);
    if (!s->hub) {
        delete s;
        return nullptr;
    }
    const char* host = cfg->bind_host[0] ? cfg->bind_host : "0.0.0.0";
    if (!s->sock.open(host, cfg->bind_port, cfg->socket_buffer > 0 ? cfg->socket_buffer : 1 << 20, false)) {
        genesis::vfs_hub_destroy(s->hub);
        delete s;
        return nullptr;
    }
    s->port = s->sock.local_port();
    s->ssh_pipe = cfg->ssh_pipe != 0;
    std::snprintf(s->node_name, sizeof(s->node_name), "%s", cfg->node_name);
    s->exp_count = cfg->export_count;
    if (s->exp_count > GENESIS_EXPORT_MAX) s->exp_count = GENESIS_EXPORT_MAX;
    for (int i = 0; i < s->exp_count; ++i) {
        std::snprintf(s->exp_name[i], sizeof(s->exp_name[i]), "%s", cfg->export_name[i]);
        s->exp_rw[i] = cfg->export_rw[i];
    }
    if (cfg->control[0]) {
        char err[160];
        s->listen_fd = genesis_control_listen(cfg->control, err, sizeof(err));
        if (s->listen_fd < 0) genesis::logf(1, "vfs control: %s", err);
    }
    if (cfg->enable_discovery) {
        if (s->disco.open("0.0.0.0", genesis::kDiscoveryPort, 1 << 20, false) && s->disco.join_multicast(genesis::kDiscoveryGroup))
            s->disco_on = true;
    }
    s->thr = std::thread(genesis::server_loop, s);
    return s;
}

extern "C" uint16_t genesis_vfs_server_port(const genesis_vfs_server* server) {
    return server ? server->port : 0;
}

extern "C" int genesis_vfs_server_running(const genesis_vfs_server* server) {
    return server && server->stop.load() == 0;
}

extern "C" void genesis_vfs_server_stop(genesis_vfs_server* server) {
    if (!server) return;
    server->stop.store(1);
    if (server->thr.joinable()) server->thr.join();
    if (server->listen_fd >= 0) ::close(server->listen_fd);
    genesis::vfs_hub_destroy(server->hub);
    delete server;
}

extern "C" void genesis_vfs_server_lose(genesis_vfs_server* server, int every) {
    if (!server) return;
    genesis::vfs_hub_set_lose(server->hub, every);
}

extern "C" int genesis_showmount(const genesis_config* cfg, const char* host, uint16_t port, int timeout_ms, char* out,
                                 size_t out_cap) {
    if (!cfg || !out || out_cap < 8) return GENESIS_ERR_ARGS;
    out[0] = '\0';
    if (timeout_ms <= 0) timeout_ms = 2000;
    if (!host || !host[0]) {
        genesis::UdpSocket disco;
        if (!disco.open("0.0.0.0", genesis::kDiscoveryPort, 1 << 20, false) || !disco.join_multicast(genesis::kDiscoveryGroup))
            return GENESIS_ERR_NET;
        uint64_t deadline = genesis::monotonic_us() + static_cast<uint64_t>(timeout_ms) * 1000ull;
        size_t used = 0;
        bool any = false;
        while (genesis::monotonic_us() < deadline) {
            uint64_t now = genesis::monotonic_us();
            int left = static_cast<int>((deadline - now) / 1000);
            if (left < 1) break;
            uint8_t buf[512];
            uint32_t addr = 0;
            uint16_t sport = 0;
            int n = disco.recv_from(buf, sizeof(buf), &addr, &sport, left > 200 ? 200 : left);
            if (n <= 0) continue;
            genesis::Beacon b;
            if (!genesis::beacon_decode(buf, static_cast<size_t>(n), b)) continue;
            char names[8][32];
            uint8_t rw[8];
            int count = genesis::beacon_read_exports(buf, static_cast<size_t>(n), names, rw, 8);
            if (count <= 0 && (b.features & genesis::kFeatVfs) == 0) continue;
            char ip[32];
            if (!genesis::ipv4_format(addr, ip, sizeof(ip))) continue;
            char line[256];
            int lw = std::snprintf(line, sizeof(line), "%s:%u %s", ip, b.port, b.name);
            for (int i = 0; i < count && lw > 0 && lw < static_cast<int>(sizeof(line)); ++i)
                lw += std::snprintf(line + lw, sizeof(line) - static_cast<size_t>(lw), "%s%s", i ? "," : " ", names[i]);
            if (lw < 0) continue;
            if (std::strstr(out, line)) continue;
            if (used + static_cast<size_t>(lw) + 2 >= out_cap) break;
            used += static_cast<size_t>(std::snprintf(out + used, out_cap - used, "%s\n", line));
            any = true;
        }
        return any ? GENESIS_OK : GENESIS_ERR_TIMEOUT;
    }
    if (port == 0) port = 37420;
    genesis_vfs* session = genesis_vfs_connect(cfg, host, port, "", timeout_ms);
    if (!session) return GENESIS_ERR_NET;
    genesis_vfs_req req{};
    req.op = GENESIS_VFS_LIST;
    uint8_t data[4096];
    genesis_vfs_res res{};
    res.data = data;
    res.data_cap = sizeof(data);
    int rc = genesis_vfs_call(session, &req, &res, timeout_ms);
    genesis_vfs_close(session);
    if (rc != GENESIS_OK) return rc;
    if (res.status) return GENESIS_ERR;
    std::vector<genesis::VfsShare> shares;
    if (!genesis::vfs_shares_read(data, res.data_len, shares)) return GENESIS_ERR_PROTO;
    size_t used = 0;
    for (const auto& s : shares) {
        int lw = std::snprintf(out + used, out_cap - used, "%s %s %s\n", s.name, s.rw ? "rw" : "ro", s.path);
        if (lw < 0 || static_cast<size_t>(lw) >= out_cap - used) break;
        used += static_cast<size_t>(lw);
    }
    return GENESIS_OK;
}
