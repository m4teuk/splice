#include "peer/datatest.h"

#include <csignal>
#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

#include "common/bytes.h"
#include "common/log.h"
#include "net/poller.h"
#include "net/socket.h"
#include "peer/pathman.h"
#include "peer/pathwatch.h"
#include "peer/store.h"

namespace spl::peer {

namespace {

std::atomic<bool> g_stop{false};
void on_sig(int) { g_stop.store(true); }

constexpr uint8_t MAGIC[4] = {'S', 'P', 'L', '0'};

// IPv6 header (40) + 8-byte payload: [MAGIC:4][seq:4].
Bytes make_echo(const proto::Ip6& src, const proto::Ip6& dst, uint32_t seq) {
    Bytes p(48, 0);
    p[0] = 0x60;        // version 6
    p[5] = 8;           // payload length
    p[6] = 59;          // next header = none
    p[7] = 64;          // hop limit
    std::memcpy(p.data() + 8, src.data(), 16);
    std::memcpy(p.data() + 24, dst.data(), 16);
    std::memcpy(p.data() + 40, MAGIC, 4);
    p[44] = static_cast<uint8_t>(seq >> 24);
    p[45] = static_cast<uint8_t>(seq >> 16);
    p[46] = static_cast<uint8_t>(seq >> 8);
    p[47] = static_cast<uint8_t>(seq);
    return p;
}

bool parse_echo(ByteSpan pkt, uint32_t* seq) {
    if (pkt.size() < 48 || std::memcmp(pkt.data() + 40, MAGIC, 4) != 0) return false;
    *seq = (uint32_t(pkt[44]) << 24) | (uint32_t(pkt[45]) << 16) | (uint32_t(pkt[46]) << 8) |
           pkt[47];
    return true;
}

void swap_addrs(Bytes& p) {
    for (int i = 0; i < 16; ++i) std::swap(p[8 + i], p[24 + i]);
}

}  // namespace

int datatest_main(int argc, char** argv) {
    std::string name, server = "127.0.0.1";
    uint16_t port = 7777;
    bool initiate = false, verbose = false;
    Millis disco_delay = 0, run_seconds = 0, kill_direct = 0;
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
        } else if (a == "--disco-delay") {
            auto v = need("--disco-delay");
            if (!v) return 2;
            disco_delay = std::atoll(v);
        } else if (a == "--run-seconds") {
            auto v = need("--run-seconds");
            if (!v) return 2;
            run_seconds = std::atoll(v);
        } else if (a == "--kill-direct-after") {
            auto v = need("--kill-direct-after");
            if (!v) return 2;
            kill_direct = std::atoll(v);
        } else if (a == "--initiate") {
            initiate = true;
        } else if (a == "-v" || a == "--verbose") {
            verbose = true;
        } else if (!a.empty() && a[0] != '-') {
            name = a;
        } else {
            spl::logf("__datatest: unknown arg '%s'", a.c_str());
            return 2;
        }
    }
    if (name.empty()) {
        spl::logf("usage: spl __datatest <name> [--initiate] [--server H --port N] [-v]");
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
        spl::logf("no connection named '%s'", name.c_str());
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
    cfg.disco_delay_ms = disco_delay;
    PathManager pm(std::move(udp), cfg);

    proto::Ip6 own_addr = rec->ula_base;
    own_addr[15] = rec->side ? 2 : 1;
    proto::Ip6 peer_addr = rec->ula_base;
    peer_addr[15] = rec->side ? 1 : 2;

    std::signal(SIGINT, on_sig);
    std::signal(SIGTERM, on_sig);
    std::signal(SIGPIPE, SIG_IGN);

    bool seen_relay = false, seen_direct = false, killed = false;
    const bool early_stop = (run_seconds == 0);
    uint32_t seq = 0;
    Millis t0 = 0, deadline = 0, t_send = 0;

    pm.on_inner = [&](ByteSpan inner, Path via) {
        uint32_t s;
        if (!parse_echo(inner, &s)) return;
        if (initiate) {
            (via == Path::Relay ? seen_relay : seen_direct) = true;
            std::printf("reply seq=%u over %s\n", s, path_name(via));
            std::fflush(stdout);
            if (early_stop && seen_relay && seen_direct) {
                std::printf("UPGRADE OK: relay then direct\n");
                std::fflush(stdout);
                g_stop.store(true);
            }
        } else {
            Bytes echo(inner.begin(), inner.end());
            swap_addrs(echo);
            pm.send_inner(as_span(echo));
        }
    };
    if (verbose)
        spl::logf("datatest '%s' as %s (side %d)", name.c_str(),
                  initiate ? "initiator" : "responder", rec->side ? 1 : 0);
    t0 = mono_ms();
    deadline = t0 + (run_seconds > 0 ? run_seconds * 1000 : 25000);

    net::Poller poller;
    PathWatch watch;
    poller.set(pm.fd(), [&] { pm.handle_io(mono_ms()); });
    poller.run(g_stop, [&](Millis now) {
        pm.tick(now);
        if (verbose) watch.render(pm.status(now), now);
        if (now >= deadline) {
            g_stop.store(true);
            return;
        }
        if (kill_direct > 0 && !killed && now - t0 >= kill_direct) {
            killed = true;
            pm.set_force_relay(true);
            if (verbose) spl::logf("[test] forcing relay (simulated direct loss)");
        }
        if (initiate && now - t_send >= 400) {
            t_send = now;
            Bytes req = make_echo(own_addr, peer_addr, ++seq);
            pm.send_inner(as_span(req));
        }
    });

    if (initiate && early_stop) return (seen_relay && seen_direct) ? 0 : 1;
    return 0;
}

}  // namespace spl::peer
