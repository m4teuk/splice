#include "peer/store.h"

#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <map>
#include <sstream>

#include "common/base64.h"
#include "common/config.h"

namespace spl::peer {

namespace {

std::string resolve_dir() { return config_dir(); }

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
    const std::string tmp = path + ".tmp";

    std::ostringstream s;
    s << "name: " << r.name << "\n"
      << "uid: " << base64_encode(as_span(r.uid)) << "\n"
      << "side: " << (r.side ? 1 : 0) << "\n"
      << "ula_base: " << base64_encode(as_span(r.ula_base)) << "\n"
      << "ula_prefix: " << static_cast<int>(r.ula_prefix) << "\n"
      << "own_priv: " << base64_encode(as_span(r.own_priv)) << "\n"
      << "own_pub: " << base64_encode(as_span(r.own_pub)) << "\n"
      << "peer_pub: " << base64_encode(as_span(r.peer_pub)) << "\n"
      << "created: " << r.created_unix << "\n";
    const std::string body = s.str();

    // Write to a 0600 temp file (the private key is never briefly world-readable),
    // then rename into place atomically so a crash can't leave a partial record.
    ::unlink(tmp.c_str());
    int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) {
        if (err) *err = "cannot create " + tmp;
        return false;
    }
    const char* p = body.data();
    size_t left = body.size();
    while (left > 0) {
        ssize_t n = ::write(fd, p, left);
        if (n <= 0) {
            ::close(fd);
            ::unlink(tmp.c_str());
            if (err) *err = "write failed for " + tmp;
            return false;
        }
        p += n;
        left -= static_cast<size_t>(n);
    }
    ::fsync(fd);
    ::close(fd);
    if (::rename(tmp.c_str(), path.c_str()) != 0) {
        ::unlink(tmp.c_str());
        if (err) *err = "rename failed for " + path;
        return false;
    }
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

std::vector<std::string> Store::list() {
    std::vector<std::string> out;
    for (auto& r : load_all()) out.push_back(r.name);
    std::sort(out.begin(), out.end());
    return out;
}

bool Store::exists(const std::string& name) {
    std::ifstream f(dir_ + "/" + sanitize(name) + ".conn");
    return f.good();
}

bool Store::remove(const std::string& name) {
    return std::remove((dir_ + "/" + sanitize(name) + ".conn").c_str()) == 0;
}

// ---- persistent pipe registrations: <dir>/pipes/<peer>/<name> ----

bool Store::save_pipe(const PipeRecord& r, std::string* err) {
    const std::string pdir = dir_ + "/pipes/" + sanitize(r.peer);
    if (!mkdirs(pdir)) {
        if (err) *err = "cannot create " + pdir;
        return false;
    }
    const std::string path = pdir + "/" + sanitize(r.name);
    std::ofstream f(path, std::ios::trunc);
    if (!f) {
        if (err) *err = "cannot write " + path;
        return false;
    }
    f << r.type << "\n";
    for (const auto& a : r.args) f << a << "\n";
    return f.good();
}

std::optional<PipeRecord> Store::load_pipe(const std::string& peer, const std::string& name) {
    std::ifstream f(dir_ + "/pipes/" + sanitize(peer) + "/" + sanitize(name));
    if (!f) return std::nullopt;
    PipeRecord r;
    r.peer = peer;
    r.name = name;
    if (!std::getline(f, r.type) || r.type.empty()) return std::nullopt;
    std::string line;
    while (std::getline(f, line)) r.args.push_back(line);
    return r;
}

std::vector<PipeRecord> Store::list_pipes(const std::string& peer) {
    std::vector<PipeRecord> out;
    const std::string pdir = dir_ + "/pipes/" + sanitize(peer);
    DIR* d = ::opendir(pdir.c_str());
    if (!d) return out;
    std::vector<std::string> names;
    while (dirent* e = ::readdir(d)) {
        std::string n = e->d_name;
        if (!n.empty() && n[0] != '.') names.push_back(n);
    }
    ::closedir(d);
    std::sort(names.begin(), names.end());
    for (const auto& n : names)
        if (auto r = load_pipe(peer, n)) out.push_back(*r);
    return out;
}

bool Store::remove_pipe(const std::string& peer, const std::string& name) {
    return std::remove((dir_ + "/pipes/" + sanitize(peer) + "/" + sanitize(name)).c_str()) == 0;
}

void Store::wipe_pipes() {
    const std::string base = dir_ + "/pipes";
    DIR* d = ::opendir(base.c_str());
    if (!d) return;
    while (dirent* e = ::readdir(d)) {
        std::string peer = e->d_name;
        if (peer.empty() || peer[0] == '.') continue;
        const std::string pdir = base + "/" + peer;
        if (DIR* pd = ::opendir(pdir.c_str())) {
            while (dirent* pe = ::readdir(pd)) {
                std::string n = pe->d_name;
                if (!n.empty() && n[0] != '.') std::remove((pdir + "/" + n).c_str());
            }
            ::closedir(pd);
        }
        ::rmdir(pdir.c_str());
    }
    ::closedir(d);
}

bool Store::rename(const std::string& from, const std::string& to, std::string* err) {
    auto rec = load(from);
    if (!rec) {
        if (err) *err = "no connection named '" + from + "'";
        return false;
    }
    const std::string from_path = dir_ + "/" + sanitize(from) + ".conn";
    const std::string to_path = dir_ + "/" + sanitize(to) + ".conn";
    if (from_path != to_path && exists(to)) {
        if (err) *err = "'" + to + "' already exists";
        return false;
    }
    rec->name = to;
    if (!save(*rec, err)) return false;  // writes to_path
    if (from_path != to_path) std::remove(from_path.c_str());
    return true;
}

}  // namespace spl::peer
