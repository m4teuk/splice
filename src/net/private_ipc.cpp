#include "net/private_ipc.h"

#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>

namespace spl::net {

namespace {
const char* const kSuspicious =
    "\n  Someone on this machine may be trying to intercept spl's control socket."
    "\n  Refusing to start. Ask an admin to remove it, or set SPL_RUNTIME_DIR to a"
    "\n  private directory.";
}  // namespace

bool ensure_private_dir(const std::string& path, std::string* err) {
    if (::mkdir(path.c_str(), 0700) != 0 && errno != EEXIST) {
        if (err) *err = "cannot create " + path + ": " + std::strerror(errno);
        return false;
    }
    // lstat, not stat: a symlink must be seen as a symlink, never followed.
    struct stat st {};
    if (::lstat(path.c_str(), &st) != 0) {
        if (err) *err = "cannot inspect " + path + ": " + std::strerror(errno);
        return false;
    }
    if (S_ISLNK(st.st_mode)) {
        if (err) *err = path + " is a symlink, not a directory." + kSuspicious;
        return false;
    }
    if (!S_ISDIR(st.st_mode)) {
        if (err) *err = path + " exists but is not a directory." + kSuspicious;
        return false;
    }
    if (st.st_uid != ::getuid()) {
        if (err)
            *err = path + " is owned by another user (uid " + std::to_string(st.st_uid) +
                   "), not you." + kSuspicious;
        return false;
    }
    // Ours but too open (e.g. created by hand): nothing to lose by tightening.
    // Once it's ours and 0700 it stays that way: in a sticky dir like /tmp no
    // other user can remove or rename it.
    if ((st.st_mode & 077) != 0 && ::chmod(path.c_str(), 0700) != 0) {
        if (err) *err = "cannot restrict permissions of " + path + ": " + std::strerror(errno);
        return false;
    }
    return true;
}

std::optional<uid_t> socket_peer_uid(int fd) {
#if defined(SO_PEERCRED)
    struct ucred cred {};
    socklen_t len = sizeof(cred);
    if (::getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cred, &len) != 0) return std::nullopt;
    return cred.uid;
#else
    uid_t uid = 0;
    gid_t gid = 0;
    if (::getpeereid(fd, &uid, &gid) != 0) return std::nullopt;
    return uid;
#endif
}

}  // namespace spl::net
