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
    // Address hints (`spl peer add-address`): hosts where this peer may be found
    // — "host", "host:port" or "[v6]:port"; the port defaults to the LAN
    // discovery port. Only ever *extra* places to ask; never authoritative.
    std::vector<std::string> addresses;
    // Per-peer settings (`spl peer set`). All on by default; a missing line = on.
    bool use_relay = true;         // register with / send through the relay for this peer
    bool lan_discovery = true;     // broadcast on local networks to find this peer
    bool remember_address = true;  // save the last addresses that worked and try them first
    // The port this peer listens on for LAN discovery; 0 = the default. Told to
    // us at pairing, or set with `spl peer set <peer> lan-port`.
    uint16_t lan_port = 0;
};

// The settings by their CLI names, in display order.
struct PeerSetting {
    const char* name;
    bool ConnRecord::* field;
};
inline constexpr PeerSetting kPeerSettings[] = {
    {"relay", &ConnRecord::use_relay},
    {"lan-discovery", &ConnRecord::lan_discovery},
    {"remember-address", &ConnRecord::remember_address},
};
// "relay on · lan-discovery on · remember-address on"
std::string settings_summary(const ConnRecord& r);

// An address a direct path to the peer last worked at ("ip:port" / "[v6]:port"),
// remembered by the daemon in <config>/<name>.seen — newest first.
struct SeenAddress {
    std::string addr;
    int64_t when_unix = 0;
};

// Splits an address hint into host and port (0 = unspecified). False if malformed.
bool parse_address_hint(const std::string& hint, std::string* host, uint16_t* port);

// A persistent named pipe registration (daemon-owned types only; PIPE
// registrations live and die with their owning process). One file per pipe
// under <config>/pipes/<peer>/<name>: line 1 the type, line 2 the LIMIT (0 =
// unlimited), then one arg per line (args may contain spaces).
struct PipeRecord {
    std::string peer;
    std::string name;
    std::string type;
    uint32_t limit = 0;
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

    // Remembered addresses (written by the daemon; the CLI only removes entries).
    std::vector<SeenAddress> load_seen(const std::string& name);
    bool save_seen(const std::string& name, const std::vector<SeenAddress>& seen);

    // The LAN port the peer itself last told the daemon it listens on (0 = it
    // hasn't). Written by the daemon in <config>/<name>.lanport; it takes
    // precedence over the record's lan_port, which the CLI owns. save(…, 0) forgets.
    uint16_t load_learned_port(const std::string& name);
    bool save_learned_port(const std::string& name, uint16_t port);

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
