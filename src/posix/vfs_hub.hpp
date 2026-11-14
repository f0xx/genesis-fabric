#pragma once

/*
 * VFS hub owned by a daemon node or by genesis_vfs_server.
 * File transfers never enter here: the poll loop demuxes frame type kVfs first.
 */

#include "genesis/api.h"
#include "udp.hpp"

#include <cstddef>
#include <cstdint>

namespace genesis {

struct VfsHub;

VfsHub* vfs_hub_create(const genesis_config* cfg);
void vfs_hub_destroy(VfsHub* hub);
bool vfs_is_packet(const uint8_t* data, size_t len);
void vfs_hub_packet(VfsHub* hub, UdpSocket& sock, const uint8_t* data, size_t len, uint32_t addr, uint16_t port);
int vfs_hub_fill_fds(VfsHub* hub, int* fds, int cap);
void vfs_hub_on_fd(VfsHub* hub, int fd);
/* Writes OK or ERR. On success the hub owns fd. export_name may be empty. */
int vfs_hub_attach(VfsHub* hub, int fd, const char* export_name);
void vfs_hub_set_lose(VfsHub* hub, int every);

}  // namespace genesis
