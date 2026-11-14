# Security

The sample that shipped with the design notes is not this protocol. These choices replace it:

- ChaCha20-Poly1305, X25519, HMAC, and HKDF, checked against the RFC test vectors. Not an LCG, and not XOR with a counter.
- Explicit big-endian load and store. Structs are not written to the socket.
- The NACK body is a list of sequence numbers. An empty handler is not enough.
- FEC recovers a missing shard and then the reorder buffer delivers in order. A parity block is not written to the file.
- The daemon double-forks only when `--daemon` is passed. systemd and OpenRC supervise a foreground process. `daemon(0, 0)` is not used.
- Gossip has a monotonic sequence and is encrypted with the session key. There is no plaintext group token.
- There is no UPnP IGD call. Mapping a port would change the router, which this deployment is not allowed to do.
- io_uring is not used to `readv` a UDP socket.

## Identity

`trust = any` accepts any peer key. `expect_pub_hex` pins the peer X25519 public key and the handshake fails closed on a mismatch. `psk` is mixed into HKDF. `trust = tofu` is stored in the config and is not a finished pin-on-first-use store. Do not treat it as authentication.

Handshake version and header version are both checked. A newer peer is rejected rather than parsed with the version-1 layout.

A filesystem export uses that same handshake. The server opens paths with `O_NOFOLLOW` and refuses `..` and an absolute symlink target. A read-only export rejects changes. The control-socket form of the same calls is local and mode `0600`; it is not a network listener unless the operator points `--control` at `host:port`.

Peer updates cannot rewind the sequence. Unknown TLVs are ignored, so a new feature does not break an older peer, and an older peer does not apply a TLV it does not know.

## NAT

The control plane for a host you can SSH to is SSH. `genesis send --ssh user@host --ssh-port 222` asks the remote `genesis recv --ssh-pipe` for its UDP port on a stdout line, then sends. The remote command is built only from characters that are safe to pass through a shell. STUN discovers the mapped address from the same socket the transfer will use. TURN Allocate can be encoded. A relayed transfer is not the default path.

## Randomness

POSIX uses `getrandom` and then `/dev/urandom`. The embedded static library has no entropy until the port installs a hook. A handshake without entropy fails.
