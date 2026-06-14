// The one place the CLI command set is declared. main.cpp routes on it and the
// completion engine offers it, so the two can't drift apart.
//
//   managed = handled by peer_cmd_main (daemon / pipe / connection management)
//   alias   = dispatchable but hidden from completion (e.g. `list`, `rm`)
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
    {"chat", false, false},   {"update", false, false},   {"status", true, false},
    {"ping", true, false},
    {"config", true, false},  {"start", true, false},     {"stop", true, false},
    {"reset", true, false},   {"register", true, false},
    {"unregister", true, false}, {"open", true, false},   {"close", true, false},
    {"ls", true, false},      {"rename", true, false},    {"remove", true, false},
    {"add", true, false},     {"list", true, true},       {"rm", true, true},
};

inline bool is_managed_command(std::string_view name) {
    for (const auto& c : kCommands)
        if (c.managed && c.name == name) return true;
    return false;
}

}  // namespace spl::peer
