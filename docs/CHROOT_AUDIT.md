# Chroot audit

`genesis_jail_apply` and `genesis_path_is_safe` are the whole jail. Nothing in this tree edits a system unit, a sysctl, or a firewall.

## Order

1. Bind the UDP socket first. A chroot that happens before `bind` cannot reach `/dev` or the network namespace setup the process still needs, and the socket is already a file descriptor so it survives the chroot.
2. Optional `--daemon` double-fork. The pid file is written after the second fork. Use an absolute pid path. The function also `chdir("/")`, so a relative chroot path would be wrong. The daemon resolves the chroot from the config before this, and the path must be absolute.
3. Look up the drop user and call `initgroups` while `/etc/passwd` and `/etc/group` are still visible. Copy uid and gid out of the `passwd` buffer before the next NSS call.
4. `chdir` to the jail, `chroot`, `chdir("/")`.
5. `setgid`, `setuid`. Then `setuid(0)` must fail. If it succeeds, the process aborts. The credentials were not actually dropped.

## Fail closed

- A caller that is not root gets `GENESIS_ERR_JAIL` and the text `jail requires root`. The process does not pretend to be isolated.
- The chroot path must be absolute and must not contain `..`.
- An unknown user is an error. A failed `setuid` is an error.
- `genesis_path_is_safe` rejects an absolute relative-path, a backslash, a newline, an empty name, and any `..` component. The joined path has to stay under the root. A relative `recv_dir` is allowed only as a lexical prefix with the same `..` rule. This is not a substitute for `open` with `O_NOFOLLOW` on every file the daemon creates. The daemon opens the joined path after this check. A symlink inside the jail can still point at a file the user can write. The drop to an unprivileged user is what bounds that.

## What the jail does not do

- It does not install seccomp.
- It does not hide `/proc`. After `chroot`, `/proc` is absent unless the jail itself contains a mount, which this program does not create.
- It does not change the router.
- TOFU state is a config path. It is not written by the jail helper.

## Daemon supervisors

The systemd unit is `Type=simple` and starts `genesisd --foreground`. The OpenRC script uses `supervise-daemon` the same way. `--daemon` exists for a sysv double-fork and is not the path either supervisor should use. Neither file is enabled by the build.
