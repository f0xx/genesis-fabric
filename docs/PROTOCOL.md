# Protocol

Header, 48 bytes, all multi-byte fields big-endian:

| Offset | Field |
| --- | --- |
| 0 | magic `GCX1` (`0x47435831`) |
| 4 | version (1) |
| 5 | type |
| 6 | flags (bit 0 = encrypted) |
| 8 | connection id |
| 12 | sequence |
| 20 | cumulative ack |
| 28 | selective-ack bitmap, 64 bits after the cumulative ack |
| 36 | timestamp, microseconds |
| 44 | payload length |
| 46 | extension length |

Types: Hello 1, HelloAck 2, KeyConfirm 3, Data 4, Fec 5, Ack 6, Nack 7, Fin 8, FinAck 9, Gossip 10, Ping 11, Pong 12, PeerUpdate 13.

A version other than 1 is rejected. Extensions are skipped by length, so a later minor header can grow without a new magic.

## Handshake

Hello carries handshake version, profile, feature bits, an X25519 public key, a nonce, a node id, the UDP port, the node name, the file name, the file size, and address candidates. Handshake versions other than 1 are rejected.

Both sides HKDF-SHA256 the X25519 shared secret. An optional pre-shared key is appended to the input keying material. The salt is the initiator nonce concatenated with the responder nonce. The info string is `genesis-hs-v1`. The first 32 bytes are initiator-to-responder, the next 32 are the reverse. The sender uses the first key to transmit. The receiver swaps.

The transcript is SHA-256 over the raw Hello and HelloAck. Key confirmation is AEAD with sequence 1 and that transcript as plaintext. A confirm that does not match is a hard failure. Cached handshake datagrams are retransmitted unchanged, because the timestamp is inside the transcript.

Feature bits in the hello, masked together by both peers:

| Bit | Name | Meaning |
| --- | --- | --- |
| 0 | FEC | systematic Reed-Solomon parity |
| 1 | BBR | user-space pacer |
| 5 | cellular | peer believes the path is cellular |
| 6 | gigabit | peer believes the path is ethernet |
| 9 | NACK | receiver may name missing sequences |
| 10 | wifi | peer believes the path is wifi |
| 11 | DHT | GDHT queries are answered |
| 12 | jitter | receiver holds out-of-order data before treating a gap as loss |
| 13 | resume | a partial file with the same name and size continues at a chunk boundary |

A bit the peer does not set is turned off locally. FEC and NACK therefore only run when both sides agree.

The hello body may end with two trailing TLVs that an older peer ignores. Type 1 is a big-endian uint16, the sender's chunk size. Type 2 is a big-endian uint64, the byte offset the receiver already has. The offset is honored only when both peers set the resume bit, the destination sidecar names the same file and size, and the offset is a multiple of the chunk. The sender hashes the prefix it skips. The receiver hashes the bytes already on disk. The FIN digest is still the whole file.

## Jitter and NACK

Out-of-order data is held until the next sequence arrives or the hold expires. The hold is `max(2 * jitter, floor)` where the floor is 2 ms on ethernet, 8 ms on wifi, and 40 ms on cellular, unless `jitter_ms` is set. In-order data is written immediately. A NACK listing up to eight missing sequences is sent only after the hold, and only when the NACK bit was negotiated. Cellular paths leave NACK and FEC off: delay is not treated as loss, and the retransmission timeout is at least the hold.

## Routes

`--via host:port` (config `routes`) stripes groups across the primary peer and the extra paths. A path that fails four sends is abandoned for that block and the block moves to a live path. The transfer fails only when every path has given up.

## DHT

Magic `GDHT`, version 1. Ping, find-node, and nodes replies carry a 16-byte id, IPv4 address, port, and RTT. The table is 16 buckets of 8 nodes, keyed by XOR distance. A node is near when its RTT is under 30 ms or it shares a long id prefix; otherwise it is far. `genesis dht host` prints one line per returned node.

## Peer updates

After the keys exist, a peer update is AEAD. The body is a sequence number and a list of TLVs.

| Type | Meaning |
| --- | --- |
| 1 | candidate: kind, 4-byte address, port |
| 2 | feature bitset, uint32 |
| 3 | profile, one byte |

A sequence that is not strictly greater than the last applied update is dropped. An unknown TLV is skipped. That is the versioning rule for features added later.

## Data and FEC

Data plaintext starts with a big-endian offset, a group id, the shard index, k, r, a pad byte, and the byte count, then the file bytes. The receiver sets its reorder stride from the first block (offset 0). A block that does not sit on that stride is not acknowledged, so it is retransmitted rather than acknowledged into a hole.

FEC plaintext carries the group id, the base sequence, k, r, the parity index, and one parity block. Recovery fills missing data shards and acknowledges those data sequences. Parity uses its own nonce space at and above 2^63, so a lost parity packet does not open a hole in the cumulative ack. Each parity datagram is sent twice and is not retransmitted after that.

FIN carries the file size, the SHA-256, and the name. The receiver finishes only when every byte is in place and the hash matches, then it sends FinAck.

## Reliability

Cumulative ack plus a 64-bit selective bitmap in the header, covering the 64 sequence numbers immediately after the cumulative ack. An Ack datagram also carries 32 bytes of plaintext: four big-endian bitmaps covering the following 256 sequence numbers, which is enough for the whole send window. A retransmission of a sequence the receiver already accepted refreshes the cumulative ack, and the receiver emits an ack at least every 50 ms during a transfer.

The retransmission timeout starts at `max(3 * min_rtt, 20 ms)`, doubles on each resend, and is capped at 1 s. The oldest due sequence is sent first. A sequence is failed after 48 sends.

## Mesh and discovery

Gossip plaintext is a monotonic sequence, a timestamp, and node records (id, next hop, metric, rtt, bandwidth). Replays are rejected. The session AEAD key protects it. There is no plaintext network token.

Discovery beacons are not part of the file connection. Magic `GDIS`, version 1, port, features, 16-byte id, name. Group `239.255.42.19`, port `37421`.
