#include "crypto.hpp"
#include "random_stub.hpp"

namespace genesis {

namespace {
int (*g_hook)(uint8_t*, size_t) = nullptr;
}

void embedded_set_random(int (*hook)(uint8_t*, size_t)) { g_hook = hook; }

bool random_bytes(uint8_t* dst, size_t n) {
    if (!g_hook) return false;
    return g_hook(dst, n) == 0;
}

}  // namespace genesis
