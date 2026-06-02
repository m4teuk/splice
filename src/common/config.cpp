#include "common/config.h"

#include <cstdlib>
#include <fstream>
#include <string>

namespace spl {

std::string config_dir() {
    if (const char* d = std::getenv("SPL_CONFIG_DIR")) return d;
    if (const char* x = std::getenv("XDG_CONFIG_HOME")) return std::string(x) + "/spl";
    if (const char* h = std::getenv("HOME")) return std::string(h) + "/.config/spl";
    return "./.spl";
}

std::string config_path() { return config_dir() + "/config"; }

namespace {
std::string trim(const std::string& s) {
    const char* ws = " \t\r\n";
    size_t a = s.find_first_not_of(ws);
    if (a == std::string::npos) return "";
    size_t b = s.find_last_not_of(ws);
    return s.substr(a, b - a + 1);
}
}  // namespace

Config load_config() {
    Config c;
    std::ifstream f(config_path());
    if (!f) return c;

    std::string line, section;
    while (std::getline(f, line)) {
        std::string t = trim(line);
        if (t.empty() || t[0] == '#' || t[0] == ';') continue;
        if (t[0] == '[') {
            auto end = t.find(']');
            if (end != std::string::npos) section = trim(t.substr(1, end - 1));
            continue;
        }
        auto eq = t.find('=');
        if (eq == std::string::npos) continue;
        std::string key = trim(t.substr(0, eq));
        std::string val = trim(t.substr(eq + 1));

        HostPort* tgt = section == "server" ? &c.server : section == "peer" ? &c.peer : nullptr;
        if (!tgt) continue;
        if (key == "addr")
            tgt->addr = val;
        else if (key == "port")
            tgt->port = static_cast<uint16_t>(std::atoi(val.c_str()));
    }
    return c;
}

}  // namespace spl
