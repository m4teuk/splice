// On-disk store of paired connections, one file per peer under the config dir
// ($SPL_CONFIG_DIR, else $XDG_CONFIG_HOME/spl, else ~/.config/spl). Files hold
// the peer's WG public key and this side's private key, so they are mode 0600.
#pragma once

#include <optional>
#include <string>
#include <vector>

#include "proto/pairing.h"  // Uid, WgKey, Ip6

namespace spl::peer {

struct ConnRecord {
    std::string name;             // local friendly name for the peer
    proto::Uid uid{};             // this side's uid (low bit = side)
    bool side = false;            // false = leader, true = follower
    proto::Ip6 ula_base{};        // negotiated /prefix ULA network (host bits 0)
    uint8_t ula_prefix = 64;
    proto::WgKey own_priv{};      // this side's fresh X25519 private key
    proto::WgKey own_pub{};       // this side's X25519 public key
    proto::WgKey peer_pub{};      // peer's X25519 public key
    int64_t created_unix = 0;
};

// A persistent named pipe registration (daemon-owned types only; PIPE
// registrations live and die with their owning process). One file per pipe
// under <config>/pipes/<peer>/<name>: first line the type, then one arg per
// line (args may contain spaces).
struct PipeRecord {
    std::string peer;
    std::string name;
    std::string type;
    std::vector<std::string> args;
};

class Store {
 public:
    static std::optional<Store> open(std::string* err);

    bool save(const ConnRecord& r, std::string* err);
    std::optional<ConnRecord> load(const std::string& name);
    std::vector<ConnRecord> load_all();

    std::vector<std::string> list();  // connection names, sorted
    bool exists(const std::string& name);
    bool rename(const std::string& from, const std::string& to, std::string* err);
    bool remove(const std::string& name);  // true if a record was removed

    // Persistent pipe registrations.
    bool save_pipe(const PipeRecord& r, std::string* err);
    std::optional<PipeRecord> load_pipe(const std::string& peer, const std::string& name);
    std::vector<PipeRecord> list_pipes(const std::string& peer);  // sorted by name
    bool remove_pipe(const std::string& peer, const std::string& name);
    void wipe_pipes();  // all pipes for all peers (reset)

    const std::string& dir() const { return dir_; }

 private:
    explicit Store(std::string dir) : dir_(std::move(dir)) {}
    std::string dir_;
};

}  // namespace spl::peer
