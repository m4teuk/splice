#include "peer/xfer.h"

#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

#include "common/bytes.h"
#include "common/log.h"
#include "peer/runtime.h"

namespace spl::peer {

namespace {

constexpr uint16_t kFilePort = 7772;
constexpr uint32_t kMaxCtrlFrame = 64 * 1024;  // OFFER/ACCEPT/CANCEL are tiny

// Control message types.
constexpr uint8_t kOffer = 0x01;   // [u16 name_len][name][u64 size]
constexpr uint8_t kAccept = 0x02;  // (no body)
constexpr uint8_t kCancel = 0x03;  // [u16 reason_len][reason]
constexpr uint8_t kDone = 0x04;    // receiver -> sender: file written successfully

Bytes frame(ByteSpan payload) {
    ByteWriter w;
    w.u32(static_cast<uint32_t>(payload.size()));
    w.raw(payload);
    return w.take();
}
Bytes encode_offer(const std::string& name, uint64_t size) {
    ByteWriter p;
    p.u8(kOffer);
    p.lp16(as_span(name));
    p.u64(size);
    return frame(as_span(p.data()));
}
Bytes encode_accept() {
    ByteWriter p;
    p.u8(kAccept);
    return frame(as_span(p.data()));
}
Bytes encode_cancel(const std::string& reason) {
    ByteWriter p;
    p.u8(kCancel);
    p.lp16(as_span(reason));
    return frame(as_span(p.data()));
}
Bytes encode_done() {
    ByteWriter p;
    p.u8(kDone);
    return frame(as_span(p.data()));
}

// Reduce a peer-supplied name to a safe basename in the current directory: drop
// any directory part (which neutralises ../ traversal and absolute paths) and
// reject the dot names. No blacklist.
std::string sanitize_filename(const std::string& s) {
    auto slash = s.find_last_of('/');
    std::string base = slash == std::string::npos ? s : s.substr(slash + 1);
    std::string out;
    for (char c : base) {
        if (c == '\0' || c == '/') continue;
        out += c;
    }
    if (out.empty() || out == "." || out == "..") return "received_file";
    return out;
}

bool file_exists(const std::string& path) {
    struct stat st;
    return ::stat(path.c_str(), &st) == 0;
}

std::string basename_of(const std::string& path) {
    auto slash = path.find_last_of('/');
    return slash == std::string::npos ? path : path.substr(slash + 1);
}

// Tries to pull one [u32 len][payload] frame off the front of buf.
bool take_frame(Bytes& buf, Bytes* payload) {
    if (buf.size() < 4) return false;
    uint32_t len = (uint32_t(buf[0]) << 24) | (uint32_t(buf[1]) << 16) | (uint32_t(buf[2]) << 8) |
                   buf[3];
    if (len > kMaxCtrlFrame) return false;  // caller treats false+oversize as error via separate check
    if (buf.size() < 4u + len) return false;
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
        spl::logf("usage: spl send <name> <path[:newname]>");
        return 2;
    }
    const std::string name = pos[0];
    const std::string arg = pos[1];

    std::string path = arg, newname;
    auto colon = arg.rfind(':');
    if (colon != std::string::npos) {
        path = arg.substr(0, colon);
        newname = arg.substr(colon + 1);
    }
    if (newname.empty()) newname = basename_of(path);

    struct stat st;
    if (::stat(path.c_str(), &st) != 0 || !S_ISREG(st.st_mode)) {
        spl::logf("spl send: cannot read file '%s'", path.c_str());
        return 1;
    }
    const uint64_t size = static_cast<uint64_t>(st.st_size);
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        spl::logf("spl send: cannot open '%s'", path.c_str());
        return 1;
    }

    std::string err;
    auto rt = PeerRuntime::create(name, opts, &err);
    if (!rt) {
        spl::logf("spl send: %s", err.c_str());
        return 1;
    }

    TcpConn* conn = nullptr;
    Bytes inbuf;
    uint64_t remaining = size;
    int result = 1;

    auto pump = [&]() {
        if (!conn) return;
        std::vector<char> chunk;
        while (remaining > 0) {
            size_t space = conn->sndbuf();
            if (space == 0) break;
            size_t n = static_cast<size_t>(std::min<uint64_t>(remaining, std::min<size_t>(space, 32768)));
            chunk.resize(n);
            file.read(chunk.data(), static_cast<std::streamsize>(n));
            std::streamsize got = file.gcount();
            if (got <= 0) break;
            conn->send(ByteSpan(reinterpret_cast<uint8_t*>(chunk.data()), static_cast<size_t>(got)));
            remaining -= static_cast<uint64_t>(got);
        }
        // The receiver knows the size, so we don't FIN here; we wait for its DONE
        // (sending a FIN early would race the receiver's close and trigger a RST).
    };

    rt->ns().connect(
        rt->peer_addr(), kFilePort,
        [&](TcpConn* c) {
            conn = c;
            c->on_recv = [&](ByteSpan b) {
                inbuf.insert(inbuf.end(), b.begin(), b.end());
                Bytes payload;
                while (take_frame(inbuf, &payload)) {  // `conn` persists; param `c` does not
                    if (payload.empty()) continue;
                    if (payload[0] == kAccept) {
                        if (opts.verbose)
                            spl::logf("[send] peer accepted; sending %llu bytes",
                                      static_cast<unsigned long long>(size));
                        conn->on_writable = pump;
                        pump();
                    } else if (payload[0] == kCancel) {
                        ByteReader r(as_span(payload));
                        r.u8();
                        Bytes reason = r.lp16();
                        spl::logf("spl send: declined by peer: %.*s",
                                  static_cast<int>(reason.size()),
                                  reinterpret_cast<const char*>(reason.data()));
                        g_stop.store(true);
                    } else if (payload[0] == kDone) {
                        result = 0;
                        std::printf("sent '%s' (%llu bytes)\n", newname.c_str(),
                                    static_cast<unsigned long long>(size));
                        conn->close();
                        g_stop.store(true);
                    }
                }
            };
            c->on_closed = [&]() { g_stop.store(true); };
            c->on_error = [&]() { g_stop.store(true); };
            Bytes offer = encode_offer(newname, size);
            c->send(as_span(offer));
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

    enum State { WaitOffer, Writing, Done } state = WaitOffer;
    Bytes inbuf;
    uint64_t remaining = 0;
    std::ofstream out;
    std::string final_name;
    int result = 1;
    TcpConn* conn = nullptr;

    auto process = [&]() {
        for (;;) {
            if (state == WaitOffer) {
                if (inbuf.size() >= 4) {
                    uint32_t len = (uint32_t(inbuf[0]) << 24) | (uint32_t(inbuf[1]) << 16) |
                                   (uint32_t(inbuf[2]) << 8) | inbuf[3];
                    if (len > kMaxCtrlFrame) {
                        spl::logf("spl receive: oversize control frame");
                        g_stop.store(true);
                        return;
                    }
                }
                Bytes payload;
                if (!take_frame(inbuf, &payload)) return;  // need more
                ByteReader r(as_span(payload));
                if (r.u8() != kOffer) {
                    g_stop.store(true);
                    return;
                }
                Bytes nm = r.lp16();
                uint64_t size = r.u64();
                if (!r.ok()) {
                    g_stop.store(true);
                    return;
                }
                std::string offered(nm.begin(), nm.end());
                std::string target = sanitize_filename(offered);

                while (file_exists(target)) {
                    std::printf("'%s' already exists. [o]verwrite / [c]ancel / [r]ename? ",
                                target.c_str());
                    std::fflush(stdout);
                    std::string line;
                    std::getline(std::cin, line);
                    char ch = line.empty() ? 'c' : static_cast<char>(std::tolower(line[0]));
                    if (ch == 'o') {
                        break;
                    } else if (ch == 'r') {
                        std::printf("new name: ");
                        std::fflush(stdout);
                        std::string nn;
                        std::getline(std::cin, nn);
                        target = sanitize_filename(nn);
                    } else {
                        Bytes c = encode_cancel("declined");
                        conn->send(as_span(c));
                        conn->close();
                        std::printf("cancelled\n");
                        g_stop.store(true);
                        return;
                    }
                }

                out.open(target, std::ios::binary | std::ios::trunc);
                if (!out) {
                    Bytes c = encode_cancel("cannot write file");
                    conn->send(as_span(c));
                    conn->close();
                    spl::logf("spl receive: cannot write '%s'", target.c_str());
                    g_stop.store(true);
                    return;
                }
                final_name = target;
                remaining = size;
                Bytes acc = encode_accept();
                conn->send(as_span(acc));
                if (opts.verbose)
                    spl::logf("[receive] writing '%s' (%llu bytes)", target.c_str(),
                              static_cast<unsigned long long>(size));
                state = Writing;
            }
            if (state == Writing) {
                if (inbuf.empty()) return;
                size_t take = static_cast<size_t>(std::min<uint64_t>(remaining, inbuf.size()));
                out.write(reinterpret_cast<const char*>(inbuf.data()),
                          static_cast<std::streamsize>(take));
                remaining -= take;
                inbuf.erase(inbuf.begin(), inbuf.begin() + take);
                if (remaining == 0) {
                    out.close();
                    state = Done;
                    result = 0;
                    Bytes d = encode_done();  // tell the sender it's safely written
                    conn->send(as_span(d));
                    std::printf("received '%s'\n", final_name.c_str());
                    conn->close();
                    g_stop.store(true);
                }
                return;
            }
            return;  // Done
        }
    };

    rt->ns().listen(kFilePort, [&](TcpConn* c) {
        conn = c;
        c->on_recv = [&](ByteSpan b) {
            inbuf.insert(inbuf.end(), b.begin(), b.end());
            process();
        };
        c->on_closed = [&]() {
            if (state != Done) spl::logf("spl receive: transfer incomplete");
            g_stop.store(true);
        };
        c->on_error = [&]() { g_stop.store(true); };
    });
    if (opts.verbose) spl::logf("[receive] waiting for '%s'...", name.c_str());

    rt->run();
    return result;
}

}  // namespace spl::peer
