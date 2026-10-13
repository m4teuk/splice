// The one place the CLI command set is declared. main.cpp routes on it and the
// completion engine offers it, so the two can't drift apart.
//
//   managed = handled by peer_cmd_main (daemon / pipe plumbing)
//   alias   = dispatchable but hidden from completion
//
// Managing paired peers lives under one group, `spl peer <sub>` (kPeerSubcommands);
// the top level is about the daemon, pipes and data.
#pragma once

#include <string_view>

namespace spl::peer {

struct CommandDef {
    std::string_view name;
    bool managed;
    bool alias;
};

inline constexpr CommandDef kCommands[] = {
    {"server", false, false}, {"pair", false, false},     {"serve", false, false},
    {"get", false, false},    {"send", false, false},     {"inbox", false, false},
    {"chat", false, false},   {"revshell", false, false}, {"shell", false, false},
    {"update", false, false}, {"status", true, false},    {"ping", true, false},
    {"config", true, false},  {"start", true, false},     {"stop", true, false},
    {"reset", true, false},   {"reload", true, false},    {"register", true, false},
    {"unregister", true, false}, {"open", true, false},   {"close", true, false},
    {"ls", true, false},      {"peer", false, false},
};

struct PeerSubDef {
    std::string_view name;
    bool alias;
};
inline constexpr PeerSubDef kPeerSubcommands[] = {
    {"ls", false},          {"show", false},           {"rename", false},
    {"remove", false},      {"add-address", false},    {"remove-address", false},
    {"list", true},         {"rm", true},
};

inline bool is_managed_command(std::string_view name) {
    for (const auto& c : kCommands)
        if (c.managed && c.name == name) return true;
    return false;
}

}  // namespace spl::peer
