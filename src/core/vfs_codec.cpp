#include "vfs_codec.hpp"

#include "endian.hpp"

#include <cstring>

namespace genesis {
namespace {

constexpr size_t kFixed = 68;
constexpr int kHash = 4096;
constexpr int kMaxChain = 32;
constexpr size_t kSealCap = kFixed + 511 + 511 + 65536 + 8;

size_t hash3(const uint8_t* s) {
    return static_cast<size_t>((s[0] * 31u + s[1] * 13u + s[2]) & (kHash - 1));
}

}  // namespace

size_t vfs_compress(uint8_t* dst, size_t cap, const uint8_t* src, size_t n) {
    if (!dst || !src || n == 0 || n > 256 * 1024) return 0;
    std::vector<int> head(kHash, -1);
    std::vector<int> prev(n, -1);
    auto note = [&](size_t p) {
        if (p + 2 >= n) return;
        size_t h = hash3(src + p);
        prev[p] = head[h];
        head[h] = static_cast<int>(p);
    };
    size_t o = 0;
    size_t i = 0;
    while (i < n) {
        if (o >= cap) return 0;
        size_t ctrl_at = o++;
        uint8_t ctrl = 0;
        for (int bit = 0; bit < 8 && i < n; ++bit) {
            size_t best_len = 0;
            size_t best_off = 0;
            if (i + 2 < n) {
                int chain = head[hash3(src + i)];
                int steps = 0;
                while (chain >= 0 && steps < kMaxChain) {
                    size_t off = i - static_cast<size_t>(chain);
                    if (off >= 1 && off <= 4095) {
                        size_t len = 0;
                        size_t base = static_cast<size_t>(chain);
                        while (len < 18 && i + len < n && src[base + len] == src[i + len]) ++len;
                        if (len > best_len) {
                            best_len = len;
                            best_off = off;
                        }
                    }
                    chain = prev[static_cast<size_t>(chain)];
                    ++steps;
                }
            }
            if (best_len >= 3) {
                if (o + 2 > cap) return 0;
                ctrl = static_cast<uint8_t>(ctrl | (1u << bit));
                uint32_t off = static_cast<uint32_t>(best_off);
                dst[o++] = static_cast<uint8_t>((best_len - 3) | ((off >> 8) << 4));
                dst[o++] = static_cast<uint8_t>(off & 0xff);
                for (size_t k = 0; k < best_len; ++k) note(i + k);
                i += best_len;
            } else {
                if (o + 1 > cap) return 0;
                note(i);
                dst[o++] = src[i++];
            }
        }
        dst[ctrl_at] = ctrl;
    }
    return o;
}

size_t vfs_decompress(uint8_t* dst, size_t cap, const uint8_t* src, size_t n) {
    if (!dst || !src || n == 0) return 0;
    size_t i = 0;
    size_t o = 0;
    while (i < n) {
        uint8_t ctrl = src[i++];
        for (int bit = 0; bit < 8; ++bit) {
            if (i >= n) {
                if ((ctrl & (0xffu << bit)) != 0) return 0;
                return o;
            }
            if (ctrl & (1u << bit)) {
                if (i + 2 > n) return 0;
                uint8_t b0 = src[i++];
                uint8_t b1 = src[i++];
                unsigned len = static_cast<unsigned>(b0 & 0x0f) + 3u;
                unsigned off = (static_cast<unsigned>(b0 & 0xf0) << 4) | b1;
                if (off == 0 || off > o || o + len > cap) return 0;
                for (unsigned k = 0; k < len; ++k) dst[o + k] = dst[o - off + k];
                o += len;
            } else {
                if (o >= cap) return 0;
                dst[o++] = src[i++];
            }
        }
    }
    return o;
}

size_t vfs_encode(uint8_t* dst, size_t cap, const VfsBlob& m) {
    if (!dst) return 0;
    if (m.path.size() > kVfsMaxPath || m.name.size() > kVfsMaxPath || m.data.size() > kVfsMaxData) return 0;
    size_t need = kFixed + m.path.size() + m.name.size() + m.data.size();
    if (need > cap) return 0;
    std::memset(dst, 0, kFixed);
    dst[0] = m.op;
    dst[1] = m.flags;
    store_be32(dst + 4, static_cast<uint32_t>(m.status));
    store_be32(dst + 8, m.req_id);
    store_be64(dst + 12, m.offset);
    store_be64(dst + 20, m.size);
    store_be32(dst + 28, m.mode);
    store_be32(dst + 32, m.nlink);
    store_be32(dst + 36, m.uid);
    store_be32(dst + 40, m.gid);
    store_be64(dst + 44, m.mtime_ns);
    store_be64(dst + 52, m.atime_ns);
    store_be16(dst + 60, static_cast<uint16_t>(m.path.size()));
    store_be16(dst + 62, static_cast<uint16_t>(m.name.size()));
    store_be32(dst + 64, static_cast<uint32_t>(m.data.size()));
    size_t o = kFixed;
    if (!m.path.empty()) {
        std::memcpy(dst + o, m.path.data(), m.path.size());
        o += m.path.size();
    }
    if (!m.name.empty()) {
        std::memcpy(dst + o, m.name.data(), m.name.size());
        o += m.name.size();
    }
    if (!m.data.empty()) {
        std::memcpy(dst + o, m.data.data(), m.data.size());
        o += m.data.size();
    }
    return o;
}

bool vfs_decode(const uint8_t* src, size_t n, VfsBlob& m) {
    m = VfsBlob{};
    if (!src || n < kFixed) return false;
    m.op = src[0];
    m.flags = src[1];
    m.status = static_cast<int32_t>(load_be32(src + 4));
    m.req_id = load_be32(src + 8);
    m.offset = load_be64(src + 12);
    m.size = load_be64(src + 20);
    m.mode = load_be32(src + 28);
    m.nlink = load_be32(src + 32);
    m.uid = load_be32(src + 36);
    m.gid = load_be32(src + 40);
    m.mtime_ns = load_be64(src + 44);
    m.atime_ns = load_be64(src + 52);
    uint16_t path_len = load_be16(src + 60);
    uint16_t name_len = load_be16(src + 62);
    uint32_t data_len = load_be32(src + 64);
    if (path_len > kVfsMaxPath || name_len > kVfsMaxPath || data_len > kVfsMaxData) return false;
    size_t need = kFixed + static_cast<size_t>(path_len) + name_len + data_len;
    if (n < need) return false;
    size_t o = kFixed;
    m.path.assign(reinterpret_cast<const char*>(src + o), path_len);
    o += path_len;
    m.name.assign(reinterpret_cast<const char*>(src + o), name_len);
    o += name_len;
    m.data.assign(src + o, src + o + data_len);
    return true;
}

size_t vfs_seal(uint8_t* dst, size_t cap, const VfsBlob& m) {
    if (!dst || cap < 2) return 0;
    std::vector<uint8_t> raw(kSealCap);
    size_t n = vfs_encode(raw.data(), raw.size(), m);
    if (!n) return 0;
    std::vector<uint8_t> comp(n);
    size_t c = 0;
    if (n >= 96) c = vfs_compress(comp.data(), comp.size(), raw.data(), n);
    if (c >= 1 && c + 1 < n && c + 1 <= cap) {
        dst[0] = 0xA1;
        std::memcpy(dst + 1, comp.data(), c);
        return c + 1;
    }
    if (n + 1 > cap) return 0;
    dst[0] = 0xA0;
    std::memcpy(dst + 1, raw.data(), n);
    return n + 1;
}

bool vfs_open_blob(const uint8_t* src, size_t n, VfsBlob& m) {
    if (!src || n < 2) return false;
    if (src[0] == 0xA0) return vfs_decode(src + 1, n - 1, m);
    if (src[0] != 0xA1) return false;
    std::vector<uint8_t> raw(kSealCap);
    size_t got = vfs_decompress(raw.data(), raw.size(), src + 1, n - 1);
    if (!got) return false;
    return vfs_decode(raw.data(), got, m);
}

bool vfs_dir_next(const uint8_t* p, size_t n, size_t* io, VfsDirEnt* e) {
    if (!p || !io || !e || *io >= n) return false;
    size_t o = *io;
    if (o + 2 > n) return false;
    uint16_t namelen = load_be16(p + o);
    o += 2;
    if (namelen == 0 || namelen > 255 || o + namelen + 4 + 8 + 8 + 8 > n) return false;
    *e = VfsDirEnt{};
    std::memcpy(e->name, p + o, namelen);
    o += namelen;
    e->mode = load_be32(p + o);
    o += 4;
    e->size = load_be64(p + o);
    o += 8;
    e->mtime_ns = load_be64(p + o);
    o += 8;
    e->cookie = load_be64(p + o);
    o += 8;
    *io = o;
    return true;
}

bool vfs_dir_push(std::vector<uint8_t>& out, const VfsDirEnt& e, size_t limit) {
    size_t namelen = 0;
    while (e.name[namelen] && namelen < 255) ++namelen;
    if (namelen == 0 || e.name[namelen] != '\0') return false;
    size_t add = 2 + namelen + 4 + 8 + 8 + 8;
    if (out.size() + add > limit) return false;
    uint8_t b[8];
    store_be16(b, static_cast<uint16_t>(namelen));
    out.insert(out.end(), b, b + 2);
    out.insert(out.end(), reinterpret_cast<const uint8_t*>(e.name), reinterpret_cast<const uint8_t*>(e.name) + namelen);
    store_be32(b, e.mode);
    out.insert(out.end(), b, b + 4);
    store_be64(b, e.size);
    out.insert(out.end(), b, b + 8);
    store_be64(b, e.mtime_ns);
    out.insert(out.end(), b, b + 8);
    store_be64(b, e.cookie);
    out.insert(out.end(), b, b + 8);
    return true;
}

void vfs_shares_write(std::vector<uint8_t>& out, const VfsShare* items, int count) {
    out.clear();
    if (!items || count < 0) count = 0;
    if (count > 255) count = 255;
    out.push_back(static_cast<uint8_t>(count));
    for (int i = 0; i < count; ++i) {
        size_t nl = 0;
        while (items[i].name[nl] && nl < 31) ++nl;
        size_t pl = 0;
        while (items[i].path[pl] && pl < 255) ++pl;
        out.push_back(static_cast<uint8_t>(nl));
        out.insert(out.end(), reinterpret_cast<const uint8_t*>(items[i].name),
                   reinterpret_cast<const uint8_t*>(items[i].name) + nl);
        out.push_back(items[i].rw ? 1 : 0);
        uint8_t b[2];
        store_be16(b, static_cast<uint16_t>(pl));
        out.insert(out.end(), b, b + 2);
        out.insert(out.end(), reinterpret_cast<const uint8_t*>(items[i].path),
                   reinterpret_cast<const uint8_t*>(items[i].path) + pl);
    }
}

bool vfs_shares_read(const uint8_t* p, size_t n, std::vector<VfsShare>& out) {
    out.clear();
    if (!p || n < 1) return false;
    size_t o = 0;
    int count = p[o++];
    for (int i = 0; i < count; ++i) {
        if (o >= n) return false;
        uint8_t nl = p[o++];
        if (nl > 31 || o + nl + 1 + 2 > n) return false;
        VfsShare s{};
        std::memcpy(s.name, p + o, nl);
        o += nl;
        s.rw = p[o++] ? 1 : 0;
        uint16_t pl = load_be16(p + o);
        o += 2;
        if (pl > 255 || o + pl > n) return false;
        std::memcpy(s.path, p + o, pl);
        o += pl;
        out.push_back(s);
    }
    return o == n;
}

}  // namespace genesis
