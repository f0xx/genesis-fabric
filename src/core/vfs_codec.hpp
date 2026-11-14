#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace genesis {

/* Logical VFS message. Compression and UDP fragmentation sit outside this. */
struct VfsBlob {
    uint8_t op = 0;
    uint8_t flags = 0;
    int32_t status = 0;
    uint32_t req_id = 0;
    uint64_t offset = 0;
    uint64_t size = 0;
    uint32_t mode = 0;
    uint32_t nlink = 0;
    uint32_t uid = 0;
    uint32_t gid = 0;
    uint64_t mtime_ns = 0;
    uint64_t atime_ns = 0;
    std::string path;
    std::string name;
    std::vector<uint8_t> data;
};

constexpr uint32_t kVfsMaxData = 65536;
constexpr size_t kVfsMaxPath = 511;

/* LZSS, 4 KiB window, matches of 3..18 bytes. Returns 0 when the output does not fit. */
size_t vfs_compress(uint8_t* dst, size_t cap, const uint8_t* src, size_t n);
size_t vfs_decompress(uint8_t* dst, size_t cap, const uint8_t* src, size_t n);

size_t vfs_encode(uint8_t* dst, size_t cap, const VfsBlob& m);
bool vfs_decode(const uint8_t* src, size_t n, VfsBlob& m);

/* Leading 0xA0 is raw. 0xA1 is vfs_compress of the encoded message. */
size_t vfs_seal(uint8_t* dst, size_t cap, const VfsBlob& m);
bool vfs_open_blob(const uint8_t* src, size_t n, VfsBlob& m);

struct VfsDirEnt {
    char name[256]{};
    uint32_t mode = 0;
    uint64_t size = 0;
    uint64_t mtime_ns = 0;
    uint64_t cookie = 0;
};

bool vfs_dir_next(const uint8_t* p, size_t n, size_t* io, VfsDirEnt* e);
/* False when the entry would pass limit. An entry that does not fit is not appended. */
bool vfs_dir_push(std::vector<uint8_t>& out, const VfsDirEnt& e, size_t limit);

struct VfsShare {
    char name[32]{};
    char path[256]{};
    uint8_t rw = 0;
};

void vfs_shares_write(std::vector<uint8_t>& out, const VfsShare* items, int count);
bool vfs_shares_read(const uint8_t* p, size_t n, std::vector<VfsShare>& out);

}  // namespace genesis
