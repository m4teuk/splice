// Shell-completion engine. The shell wrappers forward the current word list and
// cursor index here; we print the candidate set for that position and let the
// shell filter by prefix. All the position logic lives here so adding a command
// or flag never touches the per-shell scripts.
#include "peer/complete.h"

#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <set>
#include <sstream>
#include <string>
#include <vector>

#include "peer/daemon_client.h"
#include "peer/store.h"

namespace spl::peer {

namespace {

void emit(const std::vector<std::string>& cands) {
    for (const auto& c : cands) std::printf("%s\n", c.c_str());
}

const std::vector<std::string> kCommands = {
    "server",   "pair",   "status", "serve",      "get",  "chat", "start",
    "stop",     "reset",  "register", "unregister", "open", "close", "ls",
    "rename",   "remove", "add",    "peer"};
const std::vector<std::string> kTypes = {"ECHO", "SHARE_FILE", "GET_FILE", "PIPE"};

// Per-command flags. Value-flags consume the following word.
std::set<std::string> value_flags(const std::string& cmd) {
    if (cmd == "serve") return {"--name", "--server", "--port"};
    if (cmd == "get") return {"-o", "--out", "--server", "--port"};
    if (cmd == "register") return {"LIMIT", "--server", "--port"};
    if (cmd == "open" || cmd == "unregister" || cmd == "close" || cmd == "chat" ||
        cmd == "start")
        return {"--server", "--port"};
    if (cmd == "pair" || cmd == "add") return {"--name", "--server", "--port"};
    if (cmd == "server") return {"--bind", "--port", "--cert", "--key"};
    return {};
}
std::set<std::string> bool_flags(const std::string& cmd) {
    if (cmd == "get") return {"-f", "--force", "-b", "--background"};
    if (cmd == "open") return {"--wait"};
    if (cmd == "status") return {"-v", "--verbose"};
    if (cmd == "start") return {"--foreground"};
    if (cmd == "pair" || cmd == "add") return {"--insecure", "-v", "--verbose"};
    if (cmd == "server") return {"--setup"};
    return {};
}
std::vector<std::string> all_flags(const std::string& cmd) {
    std::vector<std::string> f;
    for (const auto& v : value_flags(cmd)) f.push_back(v);
    for (const auto& b : bool_flags(cmd)) f.push_back(b);
    return f;
}

std::vector<std::string> peer_names() {
    auto store = Store::open(nullptr);
    return store ? store->list() : std::vector<std::string>{};
}

// One STATUS RAW round-trip, only if the daemon is already running (never start it).
std::vector<std::string> status_raw_lines() {
    std::vector<std::string> out;
    int fd = daemon_connect();
    if (fd < 0) return out;
    std::string first = send_command(fd, "STATUS RAW");
    if (first.rfind("OK", 0) == 0) {
        std::string body, buf(4096, '\0');
        for (;;) {
            ssize_t n = ::read(fd, buf.data(), buf.size());
            if (n <= 0) break;
            body.append(buf.data(), static_cast<size_t>(n));
        }
        std::istringstream is(body);
        std::string line;
        while (std::getline(is, line))
            if (!line.empty()) out.push_back(line);
    }
    ::close(fd);
    return out;
}

std::vector<std::string> split_tabs(const std::string& s) {
    std::vector<std::string> f;
    std::string cur;
    for (char c : s) {
        if (c == '\t') {
            f.push_back(cur);
            cur.clear();
        } else {
            cur += c;
        }
    }
    f.push_back(cur);
    return f;
}

// Our registered pipe names toward `peer` (persisted + live), for `unregister`.
std::vector<std::string> my_pipes(const std::string& peer) {
    std::set<std::string> names;
    if (auto store = Store::open(nullptr))
        for (const auto& r : store->list_pipes(peer)) names.insert(r.name);
    for (const auto& l : status_raw_lines()) {
        auto f = split_tabs(l);
        if (f.size() >= 4 && f[0] == "reg" && f[1] == peer) names.insert(f[2]);
    }
    return {names.begin(), names.end()};
}

// Live instance ids on `peer`, for `close`.
std::vector<std::string> instance_ids(const std::string& peer) {
    std::vector<std::string> ids;
    for (const auto& l : status_raw_lines()) {
        auto f = split_tabs(l);
        if (f.size() >= 5 && f[0] == "inst" && f[1] == peer) ids.push_back(f[2]);
    }
    return ids;
}

// Candidates for the n-th positional slot of `cmd`. `pos` holds the positional
// words already typed (so e.g. pos[0] is the peer when completing a later slot).
std::vector<std::string> positional(const std::string& cmd, size_t idx,
                                    const std::vector<std::string>& pos) {
    auto peer = [&]() { return peer_names(); };
    auto type_args = [&](size_t type_slot) -> std::vector<std::string> {
        // After the TYPE word: SHARE_FILE/GET_FILE take a path; others take none.
        if (pos.size() > type_slot && (pos[type_slot] == "SHARE_FILE" || pos[type_slot] == "GET_FILE"))
            return {"__FILES__"};
        return {};
    };
    if (cmd == "serve") return idx == 0 ? peer() : std::vector<std::string>{"__FILES__"};
    if (cmd == "get") return idx == 0 ? peer() : std::vector<std::string>{};  // idx1: remote pipe (LIST later)
    if (cmd == "chat" || cmd == "remove" || cmd == "rm") return idx == 0 ? peer() : std::vector<std::string>{};
    if (cmd == "rename") return idx == 0 ? peer() : std::vector<std::string>{};
    if (cmd == "unregister") return idx == 0 ? peer() : (idx == 1 ? my_pipes(pos.empty() ? "" : pos[0]) : std::vector<std::string>{});
    if (cmd == "close") return idx == 0 ? peer() : (idx == 1 ? instance_ids(pos.empty() ? "" : pos[0]) : std::vector<std::string>{});
    if (cmd == "register") {
        if (idx == 0) return peer();
        if (idx == 1) return {};       // new pipe name: nothing to complete
        if (idx == 2) return kTypes;   // TYPE
        return type_args(2);           // args after TYPE
    }
    if (cmd == "open") {
        if (idx == 0) return peer();
        if (idx == 1) return {};       // remote pipe (LIST later)
        if (idx == 2) return kTypes;   // local TYPE
        return type_args(2);
    }
    return {};
}

}  // namespace

int complete_main(int argc, char** argv) {
    // argv: [__complete] [cword] [spl] [w1] [w2] ...
    if (argc < 3) return 0;
    int cword = std::atoi(argv[1]);
    std::vector<std::string> words;
    for (int i = 2; i < argc; ++i) words.emplace_back(argv[i]);  // words[0] == "spl"

    // The `peer` keyword is an optional prefix: drop it and shift the cursor.
    if (words.size() > 1 && words[1] == "peer") {
        words.erase(words.begin() + 1);
        if (cword >= 1) --cword;
    }

    if (cword <= 1) {  // completing the command itself
        emit(kCommands);
        return 0;
    }
    const std::string cmd = words.size() > 1 ? words[1] : "";
    const std::string partial = (cword >= 0 && static_cast<size_t>(cword) < words.size())
                                    ? words[cword]
                                    : "";
    const std::string prev = (cword - 1 >= 0 && static_cast<size_t>(cword - 1) < words.size())
                                 ? words[cword - 1]
                                 : "";

    // If the previous word is a value-flag, complete its value.
    if (value_flags(cmd).count(prev)) {
        if (prev == "-o" || prev == "--out") emit({"__FILES__"});
        return 0;  // --server/--port/--name/LIMIT/etc: free text, no candidates
    }
    // Completing a flag.
    if (!partial.empty() && partial[0] == '-') {
        emit(all_flags(cmd));
        return 0;
    }
    // Otherwise a positional: count the positional words before the cursor.
    std::vector<std::string> pos;
    bool prev_value_flag = false;
    for (int i = 2; i < cword; ++i) {
        const std::string& w = words[i];
        if (prev_value_flag) {
            prev_value_flag = false;
            continue;
        }
        if (value_flags(cmd).count(w)) {
            prev_value_flag = true;
            continue;
        }
        if (bool_flags(cmd).count(w)) continue;
        pos.push_back(w);
    }
    emit(positional(cmd, pos.size(), pos));
    return 0;
}

}  // namespace spl::peer
