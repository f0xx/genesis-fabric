# Genesis Fabric

UDP file transfer for a LAN, a routed path, or a punched NAT mapping. The protocol engine is `libgenesis_core.so`. `genesis` and `genesisd` are thin C++20 programs that talk to it through `include/genesis/api.h`.

The data plane is UDP. Congestion control is a user-space BBRv3-style pacer. It does not change the kernel congestion control, and it does not open router ports.

## Genesis Fabric vs. The Alternatives

Genesis Fabric occupies a unique sweet spot. It provides the low-overhead tunnel capability of a VPN, the real-time flexibility of WebRTC, and the robust bulk transport capabilities of QUIC—all tightly integrated into a single userspace engine.

| Feature / Axis | Genesis Fabric | WireGuard | QUIC (HTTP/3) | WebRTC (Data) | KCP |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Primary Design Target** | Secure, adaptive file sync, VFS mounts, and TUN/TAP over lossy networks. | High-performance kernel-space IP-to-IP tunneling. | Stream-multiplexed web traffic over TLS 1.3. | Real-time browser media and arbitrary P2P channels. | Low-latency ARQ layer over arbitrary UDP sockets. |
| **Congestion Control** | Userspace BBRv3-style pacer (does not touch kernel). | None (handled by inner TCP/QUIC flows). | Pluggable (New Reno/CUBIC/BBR) built into transport. | Delay-sensitive (GCC/BWE) focused on frame timing. | Aggressive window-less ARQ (trades bandwidth for latency). |
| **Loss Recovery** | Hybrid **FEC (Reed-Solomon)** + explicit **NACK** + adaptive RTO backup. | None (relies entirely on inner protocol layers). | Pure ACK/SACK tracking with precise range acknowledgments. | Configurable RTX (NACK) and media-specific FEC. | Selective retransmission (SACK) with fast-recovery overrides. |
| **NAT Traversal** | Built-in **rendezvous introducer** with direct punch & automatic relay backup. | Endpoint roaming via keepalives; requires one public IP to start. | Connection migration only (client-to-server IP changes). | Comprehensive ICE workflow (STUN/TURN candidate pair checks). | None (must be handled externally by application). |
| **Cryptographic Stack** | Auditable userspace X25519, HKDF-SHA256, and ChaCha20-Poly1305. | Noise_IKpsk2, ChaCha20-Poly1305 (formal cryptographic proof). | Standard TLS 1.3 record layer and handshake protocol. | DTLS-SRTP for secure media and signaling fingerprint verification. | None (plain text out of the box; needs an external layer). |
| **Application Ecosystem** | In-tree **FUSE client (`mount.genesis`)**, encrypted VFS, and TUN/TAP routing. | Virtual network interface layout; highly integrated into OS kernels. | Stream API deeply coupled with HTTP/3 ecosystem. | Rich browser APIs designed primarily for multimedia pipelines. | Pure buffer-in, callback-out minimal C API abstraction. |
| **Mesh / Topology** | Encrypted peer gossip sequence & 16x8 XOR-distance DHT. | Static cryptokey routing table configuration per peer. | No mesh capabilities (strict point-to-point architecture). | Ad-hoc top-level application mesh or centralized SFU hubs. | No mesh capabilities (point-to-point link only). |

## Key Features

* **Hybrid Error Correction (FEC + NACK):** Maximizes goodput over lossy connections using systematic Reed-Solomon erasure coding combined with explicit negative acknowledgments. It acts as a resilient alternative to TCP over UDP.
* **Userspace BBRv3 Pacing:** Integrates a custom BBR-style congestion control engine inside the application plane. It adapts dynamically to wire conditions without altering kernel sysctl parameters or requiring root privileges for the networking stack.
* **Zero-Configuration NAT Traversal:** Leverages a lightweight `GNAT` rendezvous plane to perform automatic peer-to-peer hole punching. It falls back to an integrated, authenticated relay mode if both peers sit behind symmetric NAT boundaries.
* **Cryptographic Fabric:** Secures all control and data lines with modern, reviewable primitives including X25519 key exchange, HKDF-SHA256, and ChaCha20-Poly1305 authenticated encryption.
* **Decentralized Mesh & Discovery:** Employs an encrypted gossip protocol alongside a 16-bucket XOR-distance Distributed Hash Table (DHT) to maintain cluster topology, accelerate routing, and handle node discovery dynamically.
* **Production-Grade Isolation:** Features a strict, fail-closed chroot jail mechanism (`genesisd`) that safely drops process capabilities to an unprivileged user immediately after binding the network socket.
* **Embedded-Ready Architecture:** Isolates the core state engine (`libgenesis_core.so`) completely from POSIX socket and filesystem abstractions. The static bare-metal target relies on an abstract clock and a custom TRNG entropy hook, making it ideal for Zephyr and ESP-IDF environments.
* **Rich Application Tooling:** Ships out of the box with a high-performance network file transfer utility, an encrypted VFS layer with an active FUSE client (`mount.genesis`), an interactive Web UI helper, and ad-hoc IP-over-UDP tunnel creation via native TUN/TAP integration.

## Build

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
ctest --test-dir build --output-on-failure
```

Sanitizers are one at a time:

```sh
cmake -S . -B build-asan -DGENESIS_SANITIZER=address
cmake -S . -B build-tsan -DGENESIS_SANITIZER=thread -DGENESIS_IO_URING=OFF
```

`-march=native` is off unless `-DGENESIS_NATIVE_ARCH=ON`, so a binary built here can be copied to another machine of the same ABI. CMake 3.16 is the minimum, which covers the Alpine image used in CI.

`liburing` is optional. The data path uses `sendto` / `recvfrom`. A `sendmmsg` helper is in the socket class for bursts. io_uring is initialized when the library is present so the stats flag can report it; UDP reads are not issued with `readv`.

## Install

`cmake --install` places `genesis`, `genesisd`, the shared library, `genesis/api.h`, a systemd unit, an OpenRC script, and `genesis.conf.example`. The unit files are not enabled.

## Use

```sh
genesis recv -o /tmp/out.bin -p 37420
genesis send -p 37420 ./file.bin 192.0.2.20
```

Progress (bar, percent, rate, ETA) is written to stderr. A config file is `-c path` with `key = value` lines. An interrupted receive continues from the last flushed chunk when the destination and its `.genesis` sidecar are still there. `--control PATH` or `--control HOST:PORT` sends that same `send` or `recv` to a running `genesisd` instead of calling the library. `export` lines publish directories, and `mount.genesis` mounts one over the same protocol. The operator manual is `docs/user-guide.md`. See also `config/genesis.conf.example`, `docs/USAGE.md`, and `docs/VFS.md`.

## Layout

| Path | Role |
| --- | --- |
| `src/core` | Wire format, handshake, FEC, BBR, crypto, STUN, mesh. No sockets. |
| `src/posix` | UDP, session, config jail, daemonize |
| `src/embedded` | Entropy hook for a socket-free static library |
| `apps/cli`, `apps/daemon` | Thin clients |
| `apps/mount` | `mount.genesis`, the FUSE client |
| `tests/test_main.cpp` | Vectors, FEC, engine, jail, VFS, SPSC ring |
| `packaging` | systemd and OpenRC, not installed into the running system by the build |
| `docker` | Alpine image that builds and runs `ctest` |

## Further reading

- `docs/ARCHITECTURE.md`
- `docs/PROTOCOL.md`
- `docs/SECURITY.md`
- `docs/CHROOT_AUDIT.md`
- `docs/EMBEDDED.md`
- `docs/USAGE.md`
- `docs/VFS.md`
- `docs/NAT.md`
- `docs/COMPARISON.md`
