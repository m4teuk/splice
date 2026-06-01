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

class Store {
 public:
    static std::optional<Store> open(std::string* err);

    bool save(const ConnRecord& r, std::string* err);
    std::optional<ConnRecord> load(const std::string& name);
    std::vector<ConnRecord> load_all();

    const std::string& dir() const { return dir_; }

 private:
    explicit Store(std::string dir) : dir_(std::move(dir)) {}
    std::string dir_;
};

}  // namespace spl::peer
