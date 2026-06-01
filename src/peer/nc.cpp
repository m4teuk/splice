#include "peer/nc.h"

#include <unistd.h>

#include <atomic>
#include <csignal>
#include <cstdlib>
#include <cstring>
#include <string>

#include "common/bytes.h"
#include "common/log.h"
#include "net/socket.h"
#include "peer/netstack.h"
#include "peer/pathman.h"
#include "peer/store.h"

namespace spl::peer {

namespace {

std::atomic<bool> g_stop{false};
void on_sig(int) { g_stop.store(true); }

constexpr uint16_t kTunnelPort = 7777;  // the app port on the tunnel

void write_all(int fd, ByteSpan b) {
    size_t off = 0;
    while (off < b.size()) {
        ssize_t n = ::write(fd, b.data() + off, b.size() - off);
        if (n <= 0) break;
        off += static_cast<size_t>(n);
    }
}

}  // namespace

int nc_main(bool is_send, int argc, char** argv) {
    std::string name, server = "127.0.0.1";
    uint16_t port = 7777;
    bool verbose = false;
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        auto need = [&](const char* n) -> const char* {
            if (i + 1 >= argc) {
                spl::logf("missing value for %s", n);
                return nullptr;
            }
            return argv[++i];
        };
        if (a == "--server") {
            auto v = need("--server");
            if (!v) return 2;
            server = v;
        } else if (a == "--port") {
            auto v = need("--port");
            if (!v) return 2;
            port = static_cast<uint16_t>(std::atoi(v));
        } else if (a == "-v" || a == "--verbose") {
            verbose = true;
        } else if (!a.empty() && a[0] != '-') {
            name = a;
        } else {
            spl::logf("spl %s: unknown option '%s'", is_send ? "send" : "receive", a.c_str());
            return 2;
        }
    }
    if (name.empty()) {
        spl::logf("usage: spl %s <name> [--server H --port N]", is_send ? "send" : "receive");
        return 2;
    }

    std::string err;
    auto store = Store::open(&err);
    if (!store) {
        spl::logf("store: %s", err.c_str());
        return 1;
    }
    auto rec = store->load(name);
    if (!rec) {
        spl::logf("no connection named '%s' (pair first)", name.c_str());
        return 1;
    }
    auto srv = net::resolve(server, port);
    if (!srv) {
        spl::logf("cannot resolve %s:%u", server.c_str(), port);
        return 1;
    }
    net::Fd udp = net::udp_bind("", 0, &err);
    if (!udp) {
        spl::logf("udp_bind: %s", err.c_str());
        return 1;
    }

    PathConfig cfg;
    cfg.uid = rec->uid;
    cfg.own_priv = rec->own_priv;
    cfg.peer_pub = rec->peer_pub;
    cfg.server = *srv;
    cfg.verbose = verbose;
    PathManager pm(std::move(udp), cfg);

    proto::Ip6 own_addr = rec->ula_base;
    own_addr[15] = rec->side ? 2 : 1;
    proto::Ip6 peer_addr = rec->ula_base;
    peer_addr[15] = rec->side ? 1 : 2;

    Netstack ns;
    ns.configure(own_addr);
    pm.on_inner = [&](ByteSpan inner, Path) { ns.input(inner); };
    ns.on_output = [&](ByteSpan ip) { pm.send_inner(ip); };
    pm.on_tick = [&](Millis) { ns.check_timeouts(); };

    TcpConn* conn = nullptr;
    bool tx_closed = false, rx_closed = false;
    auto check_done = [&]() {
        if (tx_closed && rx_closed) g_stop.store(true);
    };
    auto on_stdin = [&]() {
        if (!conn) return;
        uint8_t buf[4096];
        ssize_t n = ::read(STDIN_FILENO, buf, sizeof(buf));
        if (n > 0) {
            conn->send(ByteSpan(buf, static_cast<size_t>(n)));
        } else {  // stdin EOF: half-close our send direction, keep receiving
            tx_closed = true;
            pm.unwatch_fd();
            conn->end_tx();
            check_done();
        }
    };
    auto wire = [&](TcpConn* c) {
        conn = c;
        c->on_recv = [&](ByteSpan b) { write_all(STDOUT_FILENO, b); };
        c->on_closed = [&]() {
            rx_closed = true;
            check_done();
        };
        c->on_error = [&]() { g_stop.store(true); };
        pm.watch_fd(STDIN_FILENO, on_stdin);
    };

    std::signal(SIGINT, on_sig);
    std::signal(SIGTERM, on_sig);
    std::signal(SIGPIPE, SIG_IGN);

    if (is_send) {
        ns.connect(
            peer_addr, kTunnelPort,
            [&](TcpConn* c) {
                if (verbose) spl::logf("[nc] connected to %s", name.c_str());
                wire(c);
            },
            [&]() {
                spl::logf("[nc] connection to %s failed", name.c_str());
                g_stop.store(true);
            });
    } else {
        ns.listen(kTunnelPort, [&](TcpConn* c) {
            if (verbose) spl::logf("[nc] %s connected", name.c_str());
            wire(c);
        });
        if (verbose) spl::logf("[nc] waiting for %s...", name.c_str());
    }

    pm.run(g_stop);
    return 0;
}

}  // namespace spl::peer
