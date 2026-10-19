#include "crypto.hpp"

#include <cerrno>
#include <cstdio>
#include <cstring>

#if defined(__linux__)
#include <sys/random.h>
#endif
#include <fcntl.h>
#include <unistd.h>

namespace genesis {

bool random_bytes(uint8_t* dst, size_t n) {
    size_t off = 0;
    while (off < n) {
#if defined(__linux__)
        ssize_t r = getrandom(dst + off, n - off, 0);
        if (r < 0) {
            if (errno == EINTR) continue;
            break;
        }
        off += static_cast<size_t>(r);
#else
        break;
#endif
    }
    if (off == n) return true;
    int fd = ::open("/dev/urandom", O_RDONLY);
    if (fd < 0) return false;
    while (off < n) {
        ssize_t r = ::read(fd, dst + off, n - off);
        if (r < 0) {
            if (errno == EINTR) continue;
            ::close(fd);
            return false;
        }
        if (r == 0) {
            ::close(fd);
            return false;
        }
        off += static_cast<size_t>(r);
    }
    ::close(fd);
    return true;
}

}  // namespace genesis
