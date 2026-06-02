#include "peer/xfer.h"

#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include "common/bytes.h"
#include "common/log.h"
#include "common/time.h"
#include "peer/runtime.h"

namespace fs = std::filesystem;

namespace spl::peer {

namespace {

constexpr uint16_t kFilePort = 7772;
constexpr uint32_t kMaxCtrlFrame = 64 * 1024;

// Control messages (length-prefixed frames). Between an ACCEPT and the next
// frame, the sender streams exactly `size` raw bytes of file data.
constexpr uint8_t kOffer = 0x01;   // [u16 rel_len][relpath][u64 size]
constexpr uint8_t kAccept = 0x02;  // receiver -> sender: send this file's data
constexpr uint8_t kCancel = 0x03;  // receiver -> sender: abort the whole transfer
constexpr uint8_t kDone = 0x04;    // receiver -> sender: everything written
constexpr uint8_t kSkip = 0x05;    // receiver -> sender: skip this file, continue
constexpr uint8_t kEnd = 0x06;     // sender -> receiver: no more files

Bytes frame(ByteSpan payload) {
    ByteWriter w;
    w.u32(static_cast<uint32_t>(payload.size()));
    w.raw(payload);
    return w.take();
}
Bytes encode_offer(const std::string& rel, uint64_t size) {
    ByteWriter p;
    p.u8(kOffer);
    p.lp16(as_span(rel));
    p.u64(size);
    return frame(as_span(p.data()));
}
Bytes one_byte(uint8_t t) {
    ByteWriter p;
    p.u8(t);
    return frame(as_span(p.data()));
}
Bytes encode_cancel(const std::string& reason) {
    ByteWriter p;
    p.u8(kCancel);
    p.lp16(as_span(reason));
    return frame(as_span(p.data()));
}

// A peer-supplied relative path, reduced to a safe path under the cwd: split on
// '/', drop empty / "." / ".." components (which neutralises traversal and
// absolute paths), keeping the subdirectory structure. No blacklist.
std::string sanitize_relpath(const std::string& rel) {
    std::vector<std::string> parts;
    std::stringstream ss(rel);
    std::string c;
    while (std::getline(ss, c, '/')) {
        if (c.empty() || c == "." || c == "..") continue;
        std::string clean;
        for (char ch : c)
            if (ch != '\0') clean += ch;
        if (!clean.empty()) parts.push_back(clean);
    }
    if (parts.empty()) return "received_file";
    std::string out = parts[0];
    for (size_t i = 1; i < parts.size(); ++i) out += "/" + parts[i];
    return out;
}

bool path_exists(const std::string& p) {
    struct stat st;
    return ::stat(p.c_str(), &st) == 0;
}

void print_progress(bool tty, Millis* last, Millis start, const std::string& verb,
                    const std::string& name, uint64_t done, uint64_t total) {
    if (!tty) return;
    Millis now = mono_ms();
    bool fin = done >= total;
    if (!fin && now - *last < 200) return;
    *last = now;
    int pct = total ? static_cast<int>(done * 100 / total) : 100;
    double secs = (now - start) / 1000.0;
    uint64_t rate = secs > 0.0 ? static_cast<uint64_t>(done / secs) : 0;
    std::fprintf(stderr, "\r%s %s: %3d%% (%s / %s) %s/s   ", verb.c_str(), name.c_str(), pct,
                 human_bytes(done).c_str(), human_bytes(total).c_str(), human_bytes(rate).c_str());
    if (fin) std::fputc('\n', stderr);
    std::fflush(stderr);
}

struct Item {
    std::string abspath;
    std::string relpath;  // name shown to / written by the receiver
    uint64_t size;
};

// Expands one `path[:newname]` argument into transfer items (a directory becomes
// all of its regular files, keyed under the directory's name).
bool enumerate(const std::string& arg, std::vector<Item>* items, std::string* err) {
    std::string path = arg, rename;
    auto colon = arg.rfind(':');
    if (colon != std::string::npos) {
        path = arg.substr(0, colon);
        rename = arg.substr(colon + 1);
    }
    std::error_code ec;
    auto st = fs::status(path, ec);
    if (ec) {
        *err = "cannot access '" + path + "'";
        return false;
    }
    if (fs::is_regular_file(st)) {
        std::string rel = rename.empty() ? fs::path(path).filename().string() : rename;
        items->push_back({path, rel, static_cast<uint64_t>(fs::file_size(path))});
        return true;
    }
    if (fs::is_directory(st)) {
        std::string norm = path;
        while (norm.size() > 1 && norm.back() == '/') norm.pop_back();
        std::string root = rename.empty() ? fs::path(norm).filename().string() : rename;
        try {
            for (auto& e : fs::recursive_directory_iterator(
                     path, fs::directory_options::skip_permission_denied)) {
                std::error_code fec;
                if (e.is_regular_file(fec)) {
                    std::string sub = fs::relative(e.path(), path, fec).generic_string();
                    items->push_back({e.path().string(), root + "/" + sub,
                                      static_cast<uint64_t>(e.file_size(fec))});
                }
            }
        } catch (const std::exception& ex) {
            *err = "error reading '" + path + "': " + ex.what();
            return false;
        }
        return true;
    }
    *err = "'" + path + "' is not a file or directory";
    return false;
}

bool take_frame(Bytes& buf, Bytes* payload) {
    if (buf.size() < 4) return false;
    uint32_t len = (uint32_t(buf[0]) << 24) | (uint32_t(buf[1]) << 16) | (uint32_t(buf[2]) << 8) |
                   buf[3];
    if (len > kMaxCtrlFrame || buf.size() < 4u + len) return false;
    payload->assign(buf.begin() + 4, buf.begin() + 4 + len);
    buf.erase(buf.begin(), buf.begin() + 4 + len);
    return true;
}

void parse_common(int argc, char** argv, PeerOpts* opts, std::vector<std::string>* pos) {
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--server" && i + 1 < argc)
            opts->server = argv[++i];
        else if (a == "--port" && i + 1 < argc)
            opts->port = static_cast<uint16_t>(std::atoi(argv[++i]));
        else if (a == "-v" || a == "--verbose")
            opts->verbose = true;
        else
            pos->push_back(a);
    }
}

}  // namespace

int send_main(int argc, char** argv) {
    PeerOpts opts = default_peer_opts();
    std::vector<std::string> pos;
    parse_common(argc, argv, &opts, &pos);
    if (pos.size() < 2) {
        spl::logf("usage: spl send <name> <path[:newname]> [path ...]");
        return 2;
    }
    const std::string name = pos[0];

    std::vector<Item> items;
    std::string err;
    for (size_t i = 1; i < pos.size(); ++i) {
        if (!enumerate(pos[i], &items, &err)) {
            spl::logf("spl send: %s", err.c_str());
            return 1;
        }
    }
    if (items.empty()) {
        spl::logf("spl send: nothing to send");
        return 1;
    }

    auto rt = PeerRuntime::create(name, opts, &err);
    if (!rt) {
        spl::logf("spl send: %s", err.c_str());
        return 1;
    }

    TcpConn* conn = nullptr;
    Bytes inbuf;
    size_t idx = 0, sent_count = 0;
    std::ifstream file;
    bool cur_open = false, prog_done = false;
    uint64_t remaining = 0;
    int result = 1;
    bool tty = isatty(STDERR_FILENO);
    Millis last_prog = 0, t_start = 0;

    auto send_next = [&]() {
        // Open the next readable file (re-stating its size), skipping any we can no
        // longer read, then offer it (or END when none remain).
        while (idx < items.size()) {
            file.clear();
            file.open(items[idx].abspath, std::ios::binary);
            if (file) {
                struct stat st;
                if (::stat(items[idx].abspath.c_str(), &st) == 0)
                    items[idx].size = static_cast<uint64_t>(st.st_size);
                cur_open = true;
                remaining = items[idx].size;
                prog_done = false;
                break;
            }
            spl::logf("spl send: skipping unreadable '%s'", items[idx].abspath.c_str());
            ++idx;
        }
        if (idx < items.size())
            conn->send(as_span(encode_offer(items[idx].relpath, items[idx].size)));
        else
            conn->send(as_span(one_byte(kEnd)));
    };

    auto pump = [&]() {
        if (!conn || !cur_open) return;
        std::vector<char> chunk;
        while (remaining > 0) {
            size_t space = conn->sndbuf();
            if (space == 0) break;
            size_t n =
                static_cast<size_t>(std::min<uint64_t>(remaining, std::min<size_t>(space, 32768)));
            chunk.resize(n);
            file.read(chunk.data(), static_cast<std::streamsize>(n));
            std::streamsize got = file.gcount();
            if (got <= 0) {  // file shrank mid-transfer: pad so the receiver gets `size` bytes
                std::fill(chunk.begin(), chunk.end(), 0);
                got = static_cast<std::streamsize>(n);
            }
            conn->send(ByteSpan(reinterpret_cast<uint8_t*>(chunk.data()), static_cast<size_t>(got)));
            remaining -= static_cast<uint64_t>(got);
        }
        const Item& it = items[idx];
        char verb[48];
        std::snprintf(verb, sizeof(verb), "sending [%zu/%zu]", idx + 1, items.size());
        if (remaining > 0) {
            print_progress(tty, &last_prog, t_start, verb, it.relpath, it.size - remaining, it.size);
        } else if (!prog_done) {
            prog_done = true;
            print_progress(tty, &last_prog, t_start, verb, it.relpath, it.size, it.size);
            file.close();
            cur_open = false;
            conn->on_writable = nullptr;
            ++sent_count;
            ++idx;
            send_next();
        }
    };

    rt->ns().connect(
        rt->peer_addr(), kFilePort,
        [&](TcpConn* c) {
            conn = c;
            c->on_recv = [&](ByteSpan b) {
                inbuf.insert(inbuf.end(), b.begin(), b.end());
                Bytes payload;
                while (take_frame(inbuf, &payload)) {
                    if (payload.empty()) continue;
                    uint8_t t = payload[0];
                    if (t == kAccept) {
                        t_start = mono_ms();  // file already open from send_next()
                        conn->on_writable = pump;
                        pump();
                    } else if (t == kSkip) {
                        if (opts.verbose)
                            spl::logf("[send] peer skipped %s", items[idx].relpath.c_str());
                        if (cur_open) {
                            file.close();
                            cur_open = false;
                        }
                        ++idx;
                        send_next();
                    } else if (t == kCancel) {
                        ByteReader r(as_span(payload));
                        r.u8();
                        Bytes reason = r.lp16();
                        spl::logf("spl send: cancelled by peer: %.*s",
                                  static_cast<int>(reason.size()),
                                  reinterpret_cast<const char*>(reason.data()));
                        g_stop.store(true);
                    } else if (t == kDone) {
                        result = 0;
                        std::printf("sent %zu file%s\n", sent_count, sent_count == 1 ? "" : "s");
                        conn->close();
                        g_stop.store(true);
                    }
                }
            };
            c->on_closed = [&]() { g_stop.store(true); };
            c->on_error = [&]() { g_stop.store(true); };
            send_next();  // first OFFER
        },
        [&]() {
            spl::logf("spl send: could not connect to '%s'", name.c_str());
            g_stop.store(true);
        });

    rt->run();
    return result;
}

int receive_main(int argc, char** argv) {
    PeerOpts opts = default_peer_opts();
    std::vector<std::string> pos;
    parse_common(argc, argv, &opts, &pos);
    if (pos.empty()) {
        spl::logf("usage: spl receive <name>");
        return 2;
    }
    const std::string name = pos[0];

    std::string err;
    auto rt = PeerRuntime::create(name, opts, &err);
    if (!rt) {
        spl::logf("spl receive: %s", err.c_str());
        return 1;
    }

    enum State { WaitOffer, Writing } state = WaitOffer;
    Bytes inbuf;
    uint64_t remaining = 0, total = 0;
    std::ofstream out;
    std::string final_name;
    size_t recv_count = 0;
    int result = 1;
    TcpConn* conn = nullptr;
    bool tty = isatty(STDERR_FILENO);
    Millis last_prog = 0, t_start = 0;

    auto process = [&]() {
        for (;;) {
            if (state == WaitOffer) {
                Bytes payload;
                if (!take_frame(inbuf, &payload)) return;
                if (payload.empty()) {
                    g_stop.store(true);
                    return;
                }
                if (payload[0] == kEnd) {
                    Bytes d = one_byte(kDone);
                    conn->send(as_span(d));
                    result = 0;
                    std::printf("received %zu file%s\n", recv_count, recv_count == 1 ? "" : "s");
                    conn->close();
                    g_stop.store(true);
                    return;
                }
                if (payload[0] != kOffer) {
                    g_stop.store(true);
                    return;
                }
                ByteReader r(as_span(payload));
                r.u8();
                Bytes nm = r.lp16();
                uint64_t size = r.u64();
                if (!r.ok()) {
                    g_stop.store(true);
                    return;
                }
                std::string target = sanitize_relpath(std::string(nm.begin(), nm.end()));

                bool skip = false, cancel = false;
                while (path_exists(target)) {
                    std::printf("'%s' exists. [o]verwrite / [s]kip / [r]ename / [c]ancel? ",
                                target.c_str());
                    std::fflush(stdout);
                    std::string line;
                    std::getline(std::cin, line);
                    char ch = line.empty() ? 'c' : static_cast<char>(std::tolower(line[0]));
                    if (ch == 'o') break;
                    if (ch == 's') { skip = true; break; }
                    if (ch == 'r') {
                        std::printf("new name: ");
                        std::fflush(stdout);
                        std::string nn;
                        std::getline(std::cin, nn);
                        target = sanitize_relpath(nn);
                    } else { cancel = true; break; }
                }
                if (cancel) {
                    Bytes c = encode_cancel("cancelled");
                    conn->send(as_span(c));
                    conn->close();
                    std::printf("cancelled\n");
                    g_stop.store(true);
                    return;
                }
                if (skip) {
                    conn->send(as_span(one_byte(kSkip)));
                    continue;  // wait for the next OFFER
                }

                std::error_code ec;
                fs::path parent = fs::path(target).parent_path();
                if (!parent.empty()) fs::create_directories(parent, ec);
                out.open(target, std::ios::binary | std::ios::trunc);
                if (!out) {
                    conn->send(as_span(encode_cancel("cannot write '" + target + "'")));
                    conn->close();
                    spl::logf("spl receive: cannot write '%s'", target.c_str());
                    g_stop.store(true);
                    return;
                }
                final_name = target;
                remaining = size;
                total = size;
                t_start = mono_ms();
                conn->send(as_span(one_byte(kAccept)));
                state = Writing;
            }
            if (state == Writing) {
                if (inbuf.empty()) return;
                size_t take = static_cast<size_t>(std::min<uint64_t>(remaining, inbuf.size()));
                out.write(reinterpret_cast<const char*>(inbuf.data()),
                          static_cast<std::streamsize>(take));
                remaining -= take;
                inbuf.erase(inbuf.begin(), inbuf.begin() + take);
                print_progress(tty, &last_prog, t_start, "receiving", final_name, total - remaining,
                               total);
                if (remaining == 0) {
                    out.close();
                    ++recv_count;
                    state = WaitOffer;
                    continue;  // next OFFER / END
                }
                return;
            }
        }
    };

    rt->ns().listen(kFilePort, [&](TcpConn* c) {
        conn = c;
        c->on_recv = [&](ByteSpan b) {
            inbuf.insert(inbuf.end(), b.begin(), b.end());
            process();
        };
        c->on_closed = [&]() {
            if (result != 0) spl::logf("spl receive: transfer incomplete");
            g_stop.store(true);
        };
        c->on_error = [&]() { g_stop.store(true); };
    });
    if (opts.verbose) spl::logf("[receive] waiting for '%s'...", name.c_str());

    rt->run();
    return result;
}

}  // namespace spl::peer
