/*
 * Genesis Codes public C ABI.
 * Thin C++20 clients (genesis, genesisd) link libgenesis_core.so and only
 * talk through this header. The protocol engine stays inside the shared core.
 */
#ifndef GENESIS_API_H
#define GENESIS_API_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define GENESIS_VERSION_MAJOR 1
#define GENESIS_VERSION_MINOR 1
#define GENESIS_VERSION_PATCH 0

#define GENESIS_PROTO_VERSION 1
#define GENESIS_HANDSHAKE_VERSION 1

enum {
    GENESIS_PROFILE_AUTO = 0,
    GENESIS_PROFILE_GBE = 1,
    GENESIS_PROFILE_CELLULAR = 2,
    GENESIS_PROFILE_WIFI = 3
};

/* Link class used to pick FEC, NACK, and the initial pace.
 * Ethernet is preferred over wifi, and wifi over cellular, when a guess is required. */
enum {
    GENESIS_LINK_UNKNOWN = 0,
    GENESIS_LINK_ETHERNET = 1,
    GENESIS_LINK_WIFI = 2,
    GENESIS_LINK_CELLULAR = 3
};

enum {
    GENESIS_TRUST_ANY = 0,
    GENESIS_TRUST_TOFU = 1,
    GENESIS_TRUST_PSK = 2
};

enum {
    GENESIS_OK = 0,
    GENESIS_ERR = -1,
    GENESIS_ERR_ARGS = -2,
    GENESIS_ERR_IO = -3,
    GENESIS_ERR_NET = -4,
    GENESIS_ERR_CRYPTO = -5,
    GENESIS_ERR_PROTO = -6,
    GENESIS_ERR_TIMEOUT = -7,
    GENESIS_ERR_JAIL = -8
};

typedef struct genesis_config {
    char bind_host[64];
    uint16_t bind_port;
    char node_name[32];
    char stun_host[128];
    uint16_t stun_port;
    char turn_host[128];
    uint16_t turn_port;
    char turn_username[64];
    char turn_password[64];
    int profile;
    int fec_k;
    int fec_r;
    int plain_mss;
    int window_packets;
    int enable_fec;          /* -1 auto, 0 off, 1 on. Advertised as feature bit 0. */
    int enable_mesh;
    int enable_discovery;
    int enable_io_uring; /* -1 auto, 0 off, 1 on */
    int pinned_core;     /* -1 none */
    int socket_buffer;
    char psk_hex[80];
    char expect_pub_hex[80];
    char cookie_hex[40];
    char recv_dir[256];
    char chroot_dir[256];
    char drop_user[32];
    char pid_file[256];
    char tofu_path[256];
    int trust;
    int verbose;
    int punch_ms;
    int transfer_timeout_s;
    int ssh_pipe; /* receiver prints "ready <port>" on stdout before the transfer */
    int enable_nack; /* -1 auto, 0 off, 1 on. Advertised as feature bit 9. */
    int enable_dht;  /* 1 answers GDHT find/ping on the transfer socket */
    int jitter_ms;   /* 0 = hold derived from measured jitter and the link class */
    int link_hint;   /* GENESIS_LINK_*. 0 detects from the default route, then RTT. */
    char routes[512]; /* extra host:port paths, comma-separated. Striped with the primary. */
    char control[256]; /* empty: this process uses the library. Otherwise a socket path or host:port. */
} genesis_config;

typedef struct genesis_stats {
    uint64_t bytes_payload;
    uint64_t bytes_wire_tx;
    uint64_t bytes_wire_rx;
    uint64_t packets_tx;
    uint64_t packets_rx;
    uint64_t retx;
    uint64_t fec_recovered;
    uint64_t losses;
    uint64_t pacing_bps;
    uint64_t rate_bps;
    uint64_t min_rtt_us;
    uint64_t file_size;
    int profile;
    int phase;
    int io_uring;
    char sha256_hex[65];
    char error[160];
    uint64_t jitter_us;
    uint64_t nacks_sent;       /* missing sequences named in outgoing NACKs */
    int link_kind;
    int fec_enabled;
    int nack_enabled;
    int routes_alive;
    int dht_peers;
    uint64_t fec_tx_packets;
    uint64_t fec_rx_packets;
    uint64_t nack_tx_packets;
    uint64_t nack_rx_packets;
    uint64_t fec_tx_bytes;
    uint64_t nack_tx_bytes;
    uint64_t elapsed_us;
} genesis_stats;

/* Progress callback. Called on the transfer thread, never from a signal handler.
 * done/total are payload bytes. rate_bps is an exponential average of recent
 * samples (about a 2 second time constant), not a single 100 ms window.
 * eta_ms is UINT64_MAX when the rate is zero. The callback must not re-enter
 * genesis and must not block. */
typedef void (*genesis_progress_fn)(void* user, uint64_t done, uint64_t total,
                                    uint64_t rate_bps, uint64_t eta_ms);

/* Opaque daemon. One thread owns it: create, poll, destroy. */
typedef struct genesis_node genesis_node;

/* "major.minor.patch". Never NULL. The caller does not free it. */
const char* genesis_version(void);

/* Reset cfg to defaults. cfg must be non-NULL. */
void genesis_config_init(genesis_config* cfg);

/* Read key=value lines. '#' comments are ignored. cfg must already be initialized.
 * Returns GENESIS_OK, ERR_ARGS, or ERR_IO. An unknown key fails the load. */
int genesis_config_load(genesis_config* cfg, const char* path);

/* Set one key. enable_fec and enable_nack accept auto, on, off, 1, and 0.
 * Returns GENESIS_OK or GENESIS_ERR_ARGS. */
int genesis_config_set(genesis_config* cfg, const char* key, const char* value);

/* Lexical jail check. root may be empty (only rejects NUL and empty).
 * resolved receives the joined path when non-NULL. Returns GENESIS_OK when the
 * relative path stays inside root, otherwise GENESIS_ERR_ARGS or GENESIS_ERR_JAIL.
 * Does not touch the filesystem. */
int genesis_path_is_safe(const char* root, const char* relative,
                         char* resolved, size_t resolved_cap);

/*
 * Apply chroot + privilege drop. Sockets must already be open.
 * The user is resolved with getpwnam/initgroups before chroot, because the
 * jail does not contain /etc/passwd. setgid and setuid run after chroot.
 * Returns GENESIS_OK, or GENESIS_ERR_JAIL. Non-root callers get a clear error
 * rather than a false sense of isolation. err may be NULL.
 */
int genesis_jail_apply(const char* chroot_dir, const char* user,
                       char* err, size_t err_cap);

/* Send later log lines to syslog instead of stderr. Call before daemonize and before chroot.
 * on=0 keeps stderr. No effect on the embedded build. */
void genesis_log_syslog(int on);

/* Double-fork daemonize. Foreground supervisors (systemd, OpenRC supervise) must not call this.
 * pid_file may be NULL. Returns GENESIS_OK in the grandchild, GENESIS_ERR if fork fails,
 * or GENESIS_ERR_IO if the pid file cannot be written. The parent processes exit. */
int genesis_daemonize(const char* pid_file, char* err, size_t err_cap);

/* Send local_path to peer_host:peer_port. path "-" reads stdin as a stream (size 0 until FIN).
 * progress and stats may be NULL. Blocks until done, failure, or transfer_timeout_s (0 = no limit).
 * Not re-entrant. Returns GENESIS_OK or a GENESIS_ERR_* code. */
int genesis_send_file(const genesis_config* cfg, const char* local_path,
                      const char* peer_host, uint16_t peer_port,
                      genesis_progress_fn progress, void* user,
                      genesis_stats* stats);

/* Receive one file. output_path "-" writes stdout. Same timeout and return rules as send. */
int genesis_recv_file(const genesis_config* cfg, const char* output_path,
                      genesis_progress_fn progress, void* user,
                      genesis_stats* stats);

/* STUN binding on a new UDP socket. mapped_host receives dotted IPv4.
 * Uses cfg->stun_host and stun_port. Returns GENESIS_OK or GENESIS_ERR_NET. */
int genesis_stun_discover(const genesis_config* cfg,
                          char* mapped_host, size_t host_cap, uint16_t* mapped_port);

/* Wait up to timeout_ms for one discovery beacon. peer_line receives "a.b.c.d port name".
 * Returns GENESIS_OK, GENESIS_ERR_TIMEOUT, or GENESIS_ERR_ARGS. Does not send a file. */
int genesis_discover_once(const genesis_config* cfg, int timeout_ms,
                          char* peer_line, size_t line_cap);

/* Bind the daemon socket. Returns NULL if the bind fails. */
genesis_node* genesis_node_create(const genesis_config* cfg);

/* Drive discovery, DHT, and one receive. timeout_ms is the poll wait.
 * Returns GENESIS_OK or GENESIS_ERR_ARGS. */
int genesis_node_poll(genesis_node* node, int timeout_ms);

/* Ask poll to return. Safe from another thread. Does not free the node. */
void genesis_node_request_stop(genesis_node* node);

/* Close sockets and free the node. NULL is ignored. */
void genesis_node_destroy(genesis_node* node);

/* Copy the last finished session. Returns GENESIS_OK or GENESIS_ERR_ARGS. */
int genesis_node_stats(const genesis_node* node, genesis_stats* stats);

/*
 * Ask host:port for the Kademlia nodes closest to this process.
 * out receives lines of "near|far <32-hex-id> a.b.c.d:port rtt_us=N\n".
 * timeout_ms is the whole query. Returns GENESIS_OK when a GDHT reply arrives.
 * The peer must be running genesisd or a transfer that has DHT enabled.
 */
int genesis_dht_query(const genesis_config* cfg, const char* host, uint16_t port, int timeout_ms, char* out,
                      size_t out_cap);

/*
 * Classify the host's default route. Writes the interface name when ifname is
 * non-NULL. Returns GENESIS_LINK_ETHERNET, WIFI, CELLULAR, or UNKNOWN.
 * Does not open a socket and does not change routing.
 */
int genesis_detect_link(char* ifname, size_t ifname_cap);

/* Listen for CLI control connections. spec is a filesystem path, "unix:path", or "host:port".
 * Returns a non-blocking listen fd, or -1. err may be NULL. */
int genesis_control_listen(const char* spec, char* err, size_t err_cap);
/* Accept one client, or -1 if none is waiting. The returned fd is blocking. */
int genesis_control_take(int listen_fd);
/* Read one send/recv request. send runs here and closes client_fd (returns 0).
 * recv arms the daemon and keeps client_fd open (returns 1). Errors return 0 after closing. */
int genesis_control_dispatch(int client_fd, const genesis_config* cfg, genesis_node* node);

#ifdef __cplusplus
}
#endif

#endif
