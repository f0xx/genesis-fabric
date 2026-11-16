# Live transfers

Measured on 19 Oct 2026 with a release build and no sanitizer. Checksums are SHA-256. Goodput is `genesis_stats.rate_bps` from the sender summary. Wire sent counts datagrams the kernel accepted, including FEC and retransmission.

The hosts below are roles, not names. "Laptop" is a Wi-Fi station. "LAN peer" is another station on that same subnet. "Routed peer" is a host one hop further away, reached over a slower path. A musl build of the unit tests passed on a fourth host; a bulk UDP transfer was not attempted there.

A raw UDP blast of 1200-byte datagrams from the laptop to the LAN peer delivered about 1.0 MB/s (8.4 MB offered, 8.4 MB received). That is the ceiling observed for laptop-to-LAN sends. Loopback and the reverse direction are faster. Wi-Fi transfers used `--window 48` so the sender does not overrun that path. The default window is fine on loopback.

| Path | Payload | Goodput | Wire sent | Result |
| --- | --- | --- | --- | --- |
| Loopback | 32 MiB | 16.0 MB/s | 40.4 MB | hash match |
| Loopback via a 10% drop proxy | 32 MiB | 17.4 MB/s | 48.9 MB | hash match |
| Laptop to LAN peer, window 48 | 32 MiB | 0.42 MB/s | 85.9 MB | hash match |
| LAN peer to laptop, window 48 | 32 MiB | 4.1 MB/s | 45.0 MB | hash match |
| Routed peer to laptop, window 48 | 8 MiB | 0.90 MB/s | 16.5 MB | hash match |
| Routed peer to laptop, window 48 | 308.2 MiB | 0.95 MB/s | 627 MB | hash match |
| Laptop to routed peer, cellular profile, window 32 | 308.2 MiB | 0.60 MB/s | 695 MB | hash match |

The 308.2 MiB object is one media file (323,178,446 bytes). The same SHA-256 was checked on the source and on both copies. The hash is omitted here.

The return path used `--profile cellular` because an automatic-profile attempt at the full window climbed to about 2.6 MB/s and then stopped making progress. The cellular profile keeps the initial pace near 5 Mbit/s and uses two parity shards. An unprivileged process cannot `chroot`; the jail helper fails closed, so that copy sat in a scratch directory rather than a root jail.
