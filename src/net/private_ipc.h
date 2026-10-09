// Safety checks for the daemon's local control socket.
//
// The socket lives in a per-user directory that may sit in a shared place
// (/tmp). Another local user could pre-create that directory (or a symlink) to
// intercept the socket, so we only ever use a directory that is really ours,
// and both ends of a connection also check the other end's uid with the kernel.
#pragma once

#include <sys/types.h>

#include <optional>
#include <string>

namespace spl::net {

// Ensures `path` is a private directory: creates it 0700 if missing; otherwise
// it must be a real directory (not a symlink) owned by us. If it's ours but
// group/other have access, tightens it to 0700. Returns false with a
// user-facing explanation in *err when the directory can't be trusted.
bool ensure_private_dir(const std::string& path, std::string* err);

// The uid of the process at the other end of a connected unix socket, as
// reported by the kernel (SO_PEERCRED / getpeereid); nullopt if unavailable.
std::optional<uid_t> socket_peer_uid(int fd);

}  // namespace spl::net
