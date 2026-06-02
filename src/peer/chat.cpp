#include "peer/chat.h"

#include <unistd.h>

#include <cstdlib>
#include <string>

#include "common/bytes.h"
#include "common/log.h"
#include "peer/runtime.h"

namespace spl::peer {

namespace {

constexpr uint16_t kChatPort = 7771;

void write_all(int fd, ByteSpan b) {
    size_t off = 0;
    while (off < b.size()) {
        ssize_t n = ::write(fd, b.data() + off, b.size() - off);
        if (n <= 0) break;
        off += static_cast<size_t>(n);
    }
}

}  // namespace

int chat_main(int argc, char** argv) {
    PeerOpts opts = default_peer_opts();
    std::string name;
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--server" && i + 1 < argc) {
            opts.server = argv[++i];
        } else if (a == "--port" && i + 1 < argc) {
            opts.port = static_cast<uint16_t>(std::atoi(argv[++i]));
        } else if (a == "-v" || a == "--verbose") {
            opts.verbose = true;
        } else if (!a.empty() && a[0] != '-') {
            name = a;
        } else {
            spl::logf("spl chat: unexpected argument '%s'", a.c_str());
            return 2;
        }
    }
    if (name.empty()) {
        spl::logf("usage: spl chat <name> [--server H --port N]");
        return 2;
    }

    std::string err;
    auto rt = PeerRuntime::create(name, opts, &err);
    if (!rt) {
        spl::logf("spl chat: %s", err.c_str());
        return 1;
    }

    TcpConn* conn = nullptr;
    auto on_stdin = [&]() {
        if (!conn) return;
        uint8_t buf[4096];
        ssize_t n = ::read(STDIN_FILENO, buf, sizeof(buf));
        if (n > 0) {
            conn->send(ByteSpan(buf, static_cast<size_t>(n)));
        } else {  // our stdin closed -> tear the whole chat down
            rt->pm().unwatch_fd();
            conn->close();
            g_stop.store(true);
        }
    };
    auto wire = [&](TcpConn* c) {
        conn = c;
        c->on_recv = [&](ByteSpan b) { write_all(STDOUT_FILENO, b); };
        c->on_closed = [&]() { g_stop.store(true); };  // peer closed -> end chat
        c->on_error = [&]() { g_stop.store(true); };
        rt->pm().watch_fd(STDIN_FILENO, on_stdin);
    };

    if (rt->is_leader()) {
        if (opts.verbose) spl::logf("[chat] waiting for %s...", name.c_str());
        rt->ns().listen(kChatPort, [&](TcpConn* c) {
            if (opts.verbose) spl::logf("[chat] connected");
            wire(c);
        });
    } else {
        rt->ns().connect(
            rt->peer_addr(), kChatPort,
            [&](TcpConn* c) {
                if (opts.verbose) spl::logf("[chat] connected");
                wire(c);
            },
            [&]() {
                spl::logf("[chat] could not connect to %s", name.c_str());
                g_stop.store(true);
            });
    }

    rt->run();
    return 0;
}

}  // namespace spl::peer
