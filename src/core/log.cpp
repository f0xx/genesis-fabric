#include "log.hpp"

#include <cstdarg>
#include <cstdio>

#ifndef GENESIS_EMBEDDED
#include <syslog.h>
#endif

namespace genesis {
namespace {
int g_verbose = 0;
int g_syslog = 0;
}

void log_set_verbose(int verbose) { g_verbose = verbose; }
int log_verbose() { return g_verbose; }

void log_use_syslog(int on) {
    g_syslog = on ? 1 : 0;
#ifndef GENESIS_EMBEDDED
    if (g_syslog) openlog("genesisd", LOG_PID | LOG_NDELAY, LOG_DAEMON);
#endif
}

void logf(int level, const char* fmt, ...) {
    if (level > g_verbose) return;
    char buf[640];
    va_list ap;
    va_start(ap, fmt);
    std::vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
#ifndef GENESIS_EMBEDDED
    if (g_syslog) {
        syslog(LOG_INFO, "%s", buf);
        return;
    }
#endif
    std::fprintf(stderr, "\ngenesis: %s\n", buf);
}

}  // namespace genesis
