// The CLI's help text, in one table: `spl --help` (the overview), `spl help
// <command>` / `spl <command> --help` (one page), and the short usage a command
// prints when it's called wrong all come from it, so they can't drift apart.
#pragma once

#include <optional>
#include <string>

namespace spl::peer {

// The overview of every command, grouped. Goes to stdout (or stderr for an error).
void print_overview(bool to_stderr = false);

// The full page for `topic` ("get", "peer", "peer set", …) on stdout. False if
// there is no such page.
bool print_help(const std::string& topic);

// If argv asks for help (`-h`/`--help` among the command's own words), the topic
// it asks about. Never consumes anything a command would treat as data: scanning
// stops at `--`, and at the TYPE word of `register`/`open` (the args after it
// belong to the pipe).
std::optional<std::string> help_request(int argc, char** argv);

// A command was called wrong: "<cmd>: <why>" (when given), its usage lines, and
// where to read more — on stderr. Returns 2, the exit code for misuse.
int usage_error(const std::string& topic, const std::string& why = "");

}  // namespace spl::peer
