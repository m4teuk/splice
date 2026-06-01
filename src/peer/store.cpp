#include "peer/store.h"

#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <cctype>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <map>
#include <sstream>

#include "common/base64.h"

namespace spl::peer {

namespace {

std::string resolve_dir() {
    if (const char* d = std::getenv("SPL_CONFIG_DIR")) return d;
    if (const char* x = std::getenv("XDG_CONFIG_HOME")) return std::string(x) + "/spl";
    if (const char* h = std::getenv("HOME")) return std::string(h) + "/.config/spl";
    return "./.spl";
}

bool mkdirs(const std::string& path) {
    for (size_t i = 1; i <= path.size(); ++i) {
        if (i == path.size() || path[i] == '/') {
            std::string cur = path.substr(0, i);
            if (cur.empty() || cur == ".") continue;
            if (::mkdir(cur.c_str(), 0700) != 0 && errno != EEXIST) return false;
        }
    }
    return true;
}

std::string sanitize(const std::string& name) {
    std::string s;
    for (char c : name) {
        if (std::isalnum(static_cast<unsigned char>(c)) || c == '-' || c == '_' || c == '.')
            s += c;
        else
            s += '_';
    }
    return s.empty() ? "conn" : s;
}

template <size_t N>
bool getb64(const std::string& v, std::array<uint8_t, N>& out) {
    auto d = base64_decode(v);
    if (!d || d->size() != N) return false;
    std::copy(d->begin(), d->end(), out.begin());
    return true;
}

std::optional<ConnRecord> parse_file(const std::string& path) {
    std::ifstream f(path);
    if (!f) return std::nullopt;
    std::map<std::string, std::string> kv;
    std::string line;
    while (std::getline(f, line)) {
        auto pos = line.find(": ");
        if (pos == std::string::npos) continue;
        kv[line.substr(0, pos)] = line.substr(pos + 2);
    }
    ConnRecord r;
    auto it = kv.find("name");
    if (it == kv.end()) return std::nullopt;
    r.name = it->second;
    if (!getb64(kv["uid"], r.uid)) return std::nullopt;
    if (!getb64(kv["ula_base"], r.ula_base)) return std::nullopt;
    if (!getb64(kv["own_priv"], r.own_priv)) return std::nullopt;
    if (!getb64(kv["own_pub"], r.own_pub)) return std::nullopt;
    if (!getb64(kv["peer_pub"], r.peer_pub)) return std::nullopt;
    r.side = kv["side"] == "1";
    r.ula_prefix = static_cast<uint8_t>(std::atoi(kv["ula_prefix"].c_str()));
    r.created_unix = std::atoll(kv["created"].c_str());
    return r;
}

}  // namespace

std::optional<Store> Store::open(std::string* err) {
    std::string dir = resolve_dir();
    if (!mkdirs(dir)) {
        if (err) *err = "cannot create config dir: " + dir;
        return std::nullopt;
    }
    ::chmod(dir.c_str(), 0700);
    return Store(dir);
}

bool Store::save(const ConnRecord& r, std::string* err) {
    const std::string path = dir_ + "/" + sanitize(r.name) + ".conn";
    std::ofstream f(path, std::ios::trunc);
    if (!f) {
        if (err) *err = "cannot write " + path;
        return false;
    }
    f << "name: " << r.name << "\n";
    f << "uid: " << base64_encode(as_span(r.uid)) << "\n";
    f << "side: " << (r.side ? 1 : 0) << "\n";
    f << "ula_base: " << base64_encode(as_span(r.ula_base)) << "\n";
    f << "ula_prefix: " << static_cast<int>(r.ula_prefix) << "\n";
    f << "own_priv: " << base64_encode(as_span(r.own_priv)) << "\n";
    f << "own_pub: " << base64_encode(as_span(r.own_pub)) << "\n";
    f << "peer_pub: " << base64_encode(as_span(r.peer_pub)) << "\n";
    f << "created: " << r.created_unix << "\n";
    f.close();
    ::chmod(path.c_str(), 0600);
    return true;
}

std::optional<ConnRecord> Store::load(const std::string& name) {
    return parse_file(dir_ + "/" + sanitize(name) + ".conn");
}

std::vector<ConnRecord> Store::load_all() {
    std::vector<ConnRecord> out;
    DIR* d = ::opendir(dir_.c_str());
    if (!d) return out;
    while (dirent* e = ::readdir(d)) {
        std::string n = e->d_name;
        if (n.size() > 5 && n.substr(n.size() - 5) == ".conn") {
            if (auto r = parse_file(dir_ + "/" + n)) out.push_back(*r);
        }
    }
    ::closedir(d);
    return out;
}

}  // namespace spl::peer
