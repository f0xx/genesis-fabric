#pragma once

namespace genesis {

void log_set_verbose(int verbose);
int log_verbose();
/* When on, logf writes to syslog (ident genesisd, facility daemon) instead of stderr.
 * Opened immediately so the socket survives a later chroot. */
void log_use_syslog(int on);
void logf(int level, const char* fmt, ...);

}  // namespace genesis
