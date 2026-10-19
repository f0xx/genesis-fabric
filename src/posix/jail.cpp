#include "genesis/api.h"

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <sys/stat.h>
#include <unistd.h>

namespace {

bool has_dotdot(const char* s) {
    const char* p = s;
    while (*p) {
        if (p[0] == '.' && p[1] == '.' && (p[2] == '/' || p[2] == '\0') && (p == s || p[-1] == '/')) return true;
        ++p;
    }
    return false;
}

}  // namespace

int genesis_path_is_safe(const char* root, const char* relative, char* resolved, size_t resolved_cap) {
    if (!relative || !resolved || resolved_cap == 0) return GENESIS_ERR_ARGS;
    if (std::strchr(relative, '\0') != relative + std::strlen(relative)) return GENESIS_ERR_JAIL;
    if (relative[0] == '/' || relative[0] == '\\') return GENESIS_ERR_JAIL;
    if (std::strchr(relative, '\\') || std::strchr(relative, '\n')) return GENESIS_ERR_JAIL;
    if (has_dotdot(relative)) return GENESIS_ERR_JAIL;
    if (relative[0] == '\0') return GENESIS_ERR_JAIL;
    if (!root || !root[0]) {
        if (std::snprintf(resolved, resolved_cap, "%s", relative) >= static_cast<int>(resolved_cap))
            return GENESIS_ERR_JAIL;
        return GENESIS_OK;
    }
    /* Absolute roots are required for a real chroot. A relative recv_dir is only a
     * lexical prefix: ".." is still rejected, so the joined path cannot climb out. */
    if (has_dotdot(root)) return GENESIS_ERR_JAIL;
    int n = std::snprintf(resolved, resolved_cap, "%s/%s", root, relative);
    if (n < 0 || static_cast<size_t>(n) >= resolved_cap) return GENESIS_ERR_JAIL;
    return GENESIS_OK;
}

int genesis_jail_apply(const char* chroot_dir, const char* user, char* err, size_t err_cap) {
    auto seterr = [&](const char* m) {
        if (err && err_cap) std::snprintf(err, err_cap, "%s", m);
    };
    if ((!chroot_dir || !chroot_dir[0]) && (!user || !user[0])) return GENESIS_OK;
    if (geteuid() != 0) {
        seterr("jail requires root; refusing to pretend the process is isolated");
        return GENESIS_ERR_JAIL;
    }
    /* Resolve the account before chroot. getpwnam and initgroups read
     * /etc/passwd and /etc/group, which are outside the jail. */
    uid_t uid = 0;
    gid_t gid = 0;
    bool drop = user && user[0];
    if (drop) {
        struct passwd* pw = getpwnam(user);
        if (!pw) {
            seterr("unknown drop user");
            return GENESIS_ERR_JAIL;
        }
        uid = pw->pw_uid;
        gid = pw->pw_gid;
        if (initgroups(user, gid) != 0) {
            seterr(std::strerror(errno));
            return GENESIS_ERR_JAIL;
        }
    }
    if (chroot_dir && chroot_dir[0]) {
        if (chroot_dir[0] != '/' || has_dotdot(chroot_dir)) {
            seterr("chroot path must be absolute and must not contain ..");
            return GENESIS_ERR_JAIL;
        }
        if (chdir(chroot_dir) != 0) {
            seterr(std::strerror(errno));
            return GENESIS_ERR_JAIL;
        }
        if (chroot(chroot_dir) != 0) {
            seterr(std::strerror(errno));
            return GENESIS_ERR_JAIL;
        }
        if (chdir("/") != 0) {
            seterr("chdir / after chroot failed");
            return GENESIS_ERR_JAIL;
        }
    }
    if (drop) {
        if (setgid(gid) != 0 || setuid(uid) != 0) {
            seterr(std::strerror(errno));
            return GENESIS_ERR_JAIL;
        }
        if (setuid(0) == 0) {
            seterr("dropped uid can still setuid(0)");
            return GENESIS_ERR_JAIL;
        }
        errno = 0;
    }
    return GENESIS_OK;
}

int genesis_daemonize(const char* pid_file, char* err, size_t err_cap) {
    auto seterr = [&](const char* m) {
        if (err && err_cap) std::snprintf(err, err_cap, "%s", m);
    };
    pid_t pid = fork();
    if (pid < 0) {
        seterr(std::strerror(errno));
        return GENESIS_ERR;
    }
    if (pid > 0) _exit(0);
    if (setsid() < 0) _exit(1);
    pid = fork();
    if (pid < 0) _exit(1);
    if (pid > 0) _exit(0);
    umask(027);
    if (chdir("/") != 0) {
        /* not fatal before an optional chroot; the caller may chroot next */
    }
    int fd = open("/dev/null", O_RDWR);
    if (fd >= 0) {
        dup2(fd, 0);
        dup2(fd, 1);
        dup2(fd, 2);
        if (fd > 2) close(fd);
    }
    if (pid_file && pid_file[0]) {
        FILE* f = std::fopen(pid_file, "w");
        if (!f) {
            seterr("cannot write pid file");
            return GENESIS_ERR_IO;
        }
        std::fprintf(f, "%ld\n", static_cast<long>(getpid()));
        std::fclose(f);
    }
    return GENESIS_OK;
}
