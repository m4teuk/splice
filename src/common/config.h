// Config dir resolution and an optional INI config file.
//
//   $SPL_CONFIG_DIR, else $XDG_CONFIG_HOME/spl, else ~/.config/spl
//
// config file (`<dir>/config`):
//   [server]
//   addr = ::
//   port = 7777
//   [peer]
//   addr = relay.example
//   port = 7777
#pragma once

#include <cstdint>
#include <string>

namespace spl {

std::string config_dir();   // the resolved config directory
std::string config_path();  // <config_dir>/config

struct HostPort {
    std::string addr;
    uint16_t port = 0;  // 0 == unset
};

// Full relay-server settings (the [server] section). 0/empty == unset.
struct ServerConfig {
    std::string addr;  // bind address
    uint16_t port = 0;
    double per_ip_rate = 0, per_ip_burst = 0;
    double global_rate = 0, global_burst = 0;
    std::string cert, key;  // TLS cert/key (empty => ephemeral self-signed)
};

struct Config {
    ServerConfig server;  // [server]: relay server settings
    HostPort peer;        // [peer]: default rendezvous/relay server for peer commands
};

// Loads the config file; a missing file yields an all-unset Config.
Config load_config();

// True if a config file already exists at config_path().
bool config_exists();

// Writes the [server] section (with client-setup comments) to config_path(),
// creating the config dir and overwriting any existing file. False + *err on error.
bool write_server_config(const ServerConfig& s, std::string* err);

}  // namespace spl
