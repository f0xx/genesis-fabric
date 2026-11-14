#pragma once

#include "genesis/api.h"

namespace genesis {

struct Node;

int run_send(const genesis_config* cfg, const char* path, const char* host, uint16_t port,
             genesis_progress_fn progress, void* user, genesis_stats* stats);
int run_recv(const genesis_config* cfg, const char* path, genesis_progress_fn progress, void* user,
             genesis_stats* stats);

Node* node_create(const genesis_config* cfg);
int node_poll(Node* node, int timeout_ms);
void node_stop(Node* node);
void node_destroy(Node* node);
int node_stats(const Node* node, genesis_stats* stats);
uint16_t node_port(const Node* node);
/* One incoming file is written to path and progress/result lines go to client_fd. */
int node_arm_recv(Node* node, int client_fd, const char* path, const genesis_config* cfg);
/* Keep client_fd and serve VFS frames on it. export_name may be empty (list only). */
int node_vfs_attach(Node* node, int client_fd, const char* export_name);

}  // namespace genesis
