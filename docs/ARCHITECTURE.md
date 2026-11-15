# Architecture

`libgenesis_core.so` owns the protocol. The CLI and the daemon include `genesis/client.hpp` and never include the engine, the cipher, or the socket class.

The core is single-threaded. `Engine::start`, `tick`, `on_datagram`, and `pop` are the whole data plane. A POSIX session binds one UDP socket, pops a burst of datagrams, and reads with `poll`. Addresses inside the engine are host-order IPv4 integers. The socket layer converts with `htonl` / `ntohl`.

## Pieces

- Wire header, 48 bytes, big-endian, magic `GCX1`, version 1. Unknown versions are rejected.
- Handshake version 1. X25519, then HKDF-SHA256, then ChaCha20-Poly1305. The AEAD nonce is the sequence number. Sequence 1 is the key confirmation and is not a reliable data sequence. Data starts at 2.
- Reed-Solomon over GF(2^8), systematic, erasure-only. Parity row 0 is the XOR of the data shards. The receiver learns the sender's chunk size from the first block, so a gigabit profile and a cellular profile can still exchange a file.
- User-space BBR. Startup gain 2.77 on a gigabit profile and 2.0 on cellular. One spurious timeout does not end startup. A loss of more than 16 segments does. ProbeBW cycles cruise, refill, up, and down. ProbeRTT runs for 200 ms.
- Mesh table. The metric is `rtt_us * 1000 / bw_kbps`. Gossip is a monotonic sequence plus the table. A direct observation is kept when a gossip advertisement is worse.
- Discovery beacon magic `GDIS` on 239.255.42.19:37421. This is not SSDP and it does not map a port on the router. A trailer after the name lists filesystem exports. Older decoders ignore it.
- VFS, frame type 14, is a sibling of the file engine on the same UDP socket. One handshake, then filesystem RPCs. `mount.genesis` is the FUSE client. The daemon and `genesis vfs-serve` are the servers. See `docs/VFS.md`.
- NAT rendezvous uses a separate `GNAT` header on the same UDP socket. A world-reachable introducer exchanges reflexive addresses, the peers punch, and the introducer relays when the punch gets no answer. `genesis tun` carries IP or Ethernet over that path. See `docs/NAT.md`.
- STUN Binding request, XOR-MAPPED-ADDRESS, MESSAGE-INTEGRITY (HMAC-SHA1), fingerprint. TURN Allocate is constructed. A full long-term TURN client is not finished.
- SPSC ring for a streaming handoff. One producer, one consumer, power-of-two capacity.

## Profiles

`auto` starts on the gigabit gains and can move to the cellular gains when the RTT stays high. `gbe` / `LOCAL_LAN_10G` uses a larger FEC group and a 1336-byte plaintext. `cellular` / `CELLULAR_5G` uses more parity and a smaller plaintext. The initial pacer is 80 Mbit/s or 5 Mbit/s. Startup will not adopt a one-packet sample as the bottleneck.

## What is not in the library

Kernel BBR is not switched on. QUIC is not used. UPnP IGD is not used. There is no userspace TCP.

## Embedded

`genesis_core_embedded` is a static library of the same protocol objects plus `src/embedded/random_stub.cpp`. The port supplies entropy and drives `Engine` from its own NIC driver. See `docs/EMBEDDED.md`.
