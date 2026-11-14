# Filesystem exports

A genesis node can publish directories and a client can mount one. The file-transfer engine is unchanged. Filesystem calls are a separate request/response channel on the same UDP socket, frame type 14. This daemon demuxes that type before it would open a file session. A daemon from before this version can open an empty file session for the datagram and then ignore the type, so an export has to be served by this version. File transfers do not set the VFS feature bit and do not send type 14, so a mount-capable node still sends files to an older peer.

`mount.genesis` is the FUSE helper. `genesis mount` runs the helper that sits next to the `genesis` binary. `genesisd` serves the exports in its config. `genesis vfs-serve` is the same server without the file-transfer loop, including the SSH bootstrap.

## Publish

```
export = photos /home/foxx/photos rw
export = pub /srv/pub ro
```

The same line is accepted as `photos=/home/foxx/photos,rw`. The name is at most 31 characters from `[A-Za-z0-9._+-]`. A path component `..` is rejected. Eight exports is the maximum. The default mode is read-write. A read-only export returns `EROFS` for anything that would change the tree.

```sh
genesisd -c /etc/genesis/genesis.conf
genesis vfs-serve -b 0.0.0.0 -p 37420 --export "photos=/home/foxx/photos"
```

## Find and mount

```sh
genesis showmount
genesis showmount 192.168.4.100:37420
mount.genesis 192.168.4.100:37420:/photos /mnt/photos
genesis mount -f 192.168.4.100:37420:/photos /mnt/photos
genesis tree 192.168.4.100:37420:/photos
```

`showmount` with no host listens for discovery beacons. A host asks that node for its table. Lines from a node are `name rw|ro path`. Beacon lines are `ip:port name export,export`.

Discovery beacons grew a trailer after the version-1 name: `0xE1`, a count, then each name and a read-write flag. A decoder that stops at the name still accepts the beacon.

The mount talks to a local daemon control socket when you would rather not open a second UDP handshake:

```sh
mount.genesis --control /run/genesis/genesis.sock photos /mnt/photos
```

The control command is `command=vfs` and `export=name`. The daemon keeps that connection and exchanges the same sealed messages it would send over UDP. The socket mode is `0600`. There is no second cipher on that socket.

## SSH

SSH only starts the remote listener. The bytes go over UDP, the same way `genesis send --ssh` does.

```sh
mount.genesis --ssh user@host --remote-bin ~/bin/genesis \
  --remote-export /home/user/photos photos /mnt/photos
```

The remote command is `genesis vfs-serve --ssh-pipe -p 0 --export photos='path'`. It prints `ready PORT` and exits when the SSH session closes. The export name and the SSH user and host are restricted to a shell-safe set. The directory is single-quoted.

## What a mount can do

list, stat, read, write, create, mkdir, unlink, rmdir, rename (including `RENAME_NOREPLACE` and `RENAME_EXCHANGE`), chmod, truncate, symlink, readlink, utimens, link, statfs.

Copy, move, and delete from a shell are those operations. One call moves at most 64 KiB. The kernel splits a larger read or write.

The server does not follow symlinks. `O_NOFOLLOW` is used for every open, and a path component that is a symlink returns `ELOOP`. The FUSE kernel resolves a symlink by calling readlink and looking the target up again. A symlink target that is absolute or contains `..` is rejected. chmod of a symlink returns `EOPNOTSUPP`.

Attribute and entry caches are zero. The export is presented as owned by the user who mounted it. The daemon's credentials still perform the system calls.

## On the wire

One handshake per mount, then small RPCs. The handshake is the file-transfer construction: X25519, optional PSK, HKDF-SHA256 with info `genesis-hs-v1`, ChaCha20-Poly1305. The client transmit key is initiator-to-responder. The nonce is the connection id and the sequence. The confirmation plaintext is a subtype byte and the SHA-256 of the two hello payloads. Sequence 1 is that confirmation. Data sequences start at 2. A retransmit sends the same datagram again, so the nonce does not change.

The logical message is then sealed. `0xA0` is raw. `0xA1` is LZSS (4 KiB window, matches of 3 to 18 bytes) and is used only when the message is at least 96 bytes and the compressed form is smaller. Both UDP and the control socket use that seal.

UDP carries the sealed bytes in 960-byte fragments, at most 128 of them, under the path MTU. The client has one call in flight. A missing fragment is reported, and the whole request is sent again with a backoff from 40 ms to 200 ms. A repeated request id returns the cached reply and does not run the operation twice. `genesis_vfs_server_lose` drops a fraction of outgoing datagrams for tests.

A peer that does not know the export answers the hello with `ENOENT` and does not keep keys. A pinned `expect_pub` that does not match answers `EACCES`.
