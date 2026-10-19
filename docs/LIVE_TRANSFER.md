# Live transfers

Measured on 19 Oct 2026 with the release build (`build-rel/genesis`, no sanitizer). Sources under the torrent directory were not deleted. Checksums are SHA-256.

The laptop is `192.168.4.110` on `wlan0`. `huge` is `192.168.4.100` on the same subnet. `euphoria` is `192.168.200.244`, reached through `192.168.4.120`, SSH on port 222. `artc0` is Alpine with musl, reached through a jump host; unit tests pass there, and a bulk UDP transfer was not attempted.

A raw UDP blast of 1200-byte datagrams from the laptop to `huge` delivered about 1.0 MB/s (8.4 MB offered, 8.4 MB received). That is the ceiling for laptop-to-LAN sends. Loopback and the reverse direction are faster. WiFi transfers used `--window 48` so the sender does not overrun that path. The default window is fine on loopback.

| Path | Payload | Goodput | Wire sent | Result |
| --- | --- | --- | --- | --- |
| Loopback | 32 MiB | 16.0 MB/s | 40.4 MB | match `9f263aec…` |
| Loopback via a 10% drop proxy | 32 MiB | 17.4 MB/s | 48.9 MB | match `9f263aec…` |
| Laptop to huge, window 48 | 32 MiB | 0.42 MB/s | 85.9 MB | match `9f263aec…` |
| Huge to laptop, window 48 | 32 MiB | 4.1 MB/s | 45.0 MB | match `9f263aec…` |
| Euphoria to laptop, window 48 | 8 MiB | 0.90 MB/s | 16.5 MB | match `2daeb1f3…` |
| Euphoria to laptop, window 48 | 308.2 MiB | 0.95 MB/s | 627 MB | match `b66b906b…` |
| Laptop to euphoria `tmp/`, cellular profile, window 32 | 308.2 MiB | 0.60 MB/s | 695 MB | match `b66b906b…` |

The 308.2 MiB object is `foxx/The_World_in_HDR_in_4K_HDR10.mkv` (323,178,446 bytes) from `/mnt/lvmd0/lvmd0p0/torrents/downloads/` on euphoria. It landed on the laptop at `/home/foxx/tmp/genesis_codes_ai_assessment/The_World_in_HDR.mkv` and was sent back to `/home/foxx/repos/My Projects/genesis_codes_ai_assessment/tmp/The_World_in_HDR.mkv` on euphoria. The hash on all three copies is `b66b906b5739f92170468c49412bba30557cb69eea363975b07a0d8951cf7e3c`.

Goodput is `genesis_stats.rate_bps` from the sender summary line. The progress bar on stderr shows a recent rate, which moves around that average. Wire sent counts datagrams the kernel accepted, including FEC and retransmission, so it is larger than the file on a lossy path.

The return path used `--profile cellular` because an automatic-profile attempt at the full window climbed to about 2.6 MB/s and then stopped making progress. The cellular profile keeps the initial pace near 5 Mbit/s and uses two parity shards. An unprivileged process cannot `chroot`; the jail helper fails closed, so the copy sits in the project `tmp/` directory rather than a root jail.
