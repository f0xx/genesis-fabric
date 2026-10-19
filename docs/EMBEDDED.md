# Embedded

The protocol objects do not include POSIX sockets. `genesis_core_embedded` is that set plus one entropy stub.

```text
src/embedded/random_stub.cpp
```

Call `genesis::embedded_set_random` with a function that fills a buffer from the platform TRNG before any handshake. If the hook is missing, `random_bytes` fails and the handshake cannot start.

Drive the engine from the NIC driver:

1. Build an `EngineOpts` and an `Engine` (sender or receiver).
2. On each received datagram, `on_datagram(bytes, len, from, now_us)`.
3. On a timer, `tick(now_us)` and `pop` every datagram into the driver's transmit queue.
4. File bytes come from the `IoRead` / `IoWrite` callbacks. Those can be a flash reader. They do not have to be `FILE`.

`now_us` is a monotonic microsecond clock. The pacer and the retransmission timeout are wrong if this jumps backwards.

## Ports

- Zephyr: a UDP socket or a raw net_pkt feeder in `ports/zephyr`. Link `genesis_core_embedded` and set the entropy hook from the CSRNG driver.
- ESP-IDF: same static library. Entropy from `esp_fill_random`. The Wi-Fi event loop calls `tick`.
- Bare metal: no libc FILE. The read callback pulls from a memory window. Endian helpers are ordinary shifts, so they do not need a libc.

The POSIX session, jail, and daemon are not linked into this library. A port that needs them is a hosted port, not a bare-metal one.

## Limits that matter on a small core

X25519 is a schoolbook Montgomery ladder. It runs once per handshake, not per packet. ChaCha20-Poly1305 runs per packet. FEC workspace is sized for k ≤ 16 and r ≤ 4 in the engine. The default plaintext is 1200 bytes so a cellular radio that cannot carry a 1500-byte datagram still has room for the header and the tag.
