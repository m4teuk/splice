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

struct Config {
    HostPort server;  // default bind for `spl server`
    HostPort peer;    // default rendezvous/relay server for peer commands
};

// Loads the config file; a missing file yields an all-unset Config.
Config load_config();

}  // namespace spl
