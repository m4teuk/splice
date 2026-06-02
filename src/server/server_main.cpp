#include "server/server_main.h"

#include <csignal>
#include <cstdlib>
#include <cstring>
#include <atomic>
#include <memory>
#include <string>
#include <thread>

#include "common/config.h"
#include "common/log.h"
#include "net/socket.h"
#include "net/tls.h"
#include "server/pairing_server.h"
#include "server/relay_server.h"

namespace spl::server {

namespace {

std::atomic<bool> g_stop{false};
void on_signal(int) { g_stop.store(true); }

void usage() {
    spl::logf(
        "usage: spl server [options]\n"
        "  --bind HOST     address to bind (default: all interfaces)\n"
        "  --port N        TCP (pairing) and UDP (relay) port (default: 7777)\n"
        "  --tcp-port N    override pairing TCP port\n"
        "  --udp-port N    override relay UDP port\n"
        "  --cert FILE     TLS certificate (PEM); ephemeral self-signed if omitted\n"
        "  --key FILE      TLS private key (PEM)\n"
        "  -v, --verbose   verbose logging");
}

}  // namespace

int server_main(int argc, char** argv) {
    Config cfg = load_config();
    std::string bind = cfg.server.addr, cert, key;
    uint16_t port = cfg.server.port ? cfg.server.port : 7777, tcp_port = 0, udp_port = 0;
    bool verbose = false;

    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        auto need = [&](const char* name) -> const char* {
            if (i + 1 >= argc) {
                spl::logf("spl server: missing value for %s", name);
                return nullptr;
            }
            return argv[++i];
        };
        if (a == "--bind") {
            auto v = need("--bind");
            if (!v) return 2;
            bind = v;
        } else if (a == "--port") {
            auto v = need("--port");
            if (!v) return 2;
            port = static_cast<uint16_t>(std::atoi(v));
        } else if (a == "--tcp-port") {
            auto v = need("--tcp-port");
            if (!v) return 2;
            tcp_port = static_cast<uint16_t>(std::atoi(v));
        } else if (a == "--udp-port") {
            auto v = need("--udp-port");
            if (!v) return 2;
            udp_port = static_cast<uint16_t>(std::atoi(v));
        } else if (a == "--cert") {
            auto v = need("--cert");
            if (!v) return 2;
            cert = v;
        } else if (a == "--key") {
            auto v = need("--key");
            if (!v) return 2;
            key = v;
        } else if (a == "-v" || a == "--verbose") {
            verbose = true;
        } else if (a == "-h" || a == "--help") {
            usage();
            return 0;
        } else {
            spl::logf("spl server: unknown argument '%s'", a.c_str());
            usage();
            return 2;
        }
    }
    if (tcp_port == 0) tcp_port = port;
    if (udp_port == 0) udp_port = port;

    std::string err;
    std::shared_ptr<net::TlsContext> ctx;
    if (!cert.empty() || !key.empty()) {
        if (cert.empty() || key.empty()) {
            spl::logf("spl server: --cert and --key must be given together");
            return 2;
        }
        auto c = net::TlsContext::server_from_files(cert, key, &err);
        if (!c) {
            spl::logf("spl server: tls: %s", err.c_str());
            return 1;
        }
        ctx = std::make_shared<net::TlsContext>(std::move(*c));
    } else {
        auto c = net::TlsContext::server_ephemeral(&err);
        if (!c) {
            spl::logf("spl server: tls: %s", err.c_str());
            return 1;
        }
        ctx = std::make_shared<net::TlsContext>(std::move(*c));
        spl::logf(
            "WARNING: using an ephemeral self-signed TLS cert (dev mode). "
            "Security relies on SPAKE2, not on TLS.");
    }

    net::Fd listen = net::tcp_listen(bind, tcp_port, 64, &err);
    if (!listen) {
        spl::logf("spl server: tcp_listen: %s", err.c_str());
        return 1;
    }
    net::Fd udp = net::udp_bind(bind, udp_port, &err);
    if (!udp) {
        spl::logf("spl server: udp_bind: %s", err.c_str());
        return 1;
    }

    std::signal(SIGINT, on_signal);
    std::signal(SIGTERM, on_signal);
    std::signal(SIGPIPE, SIG_IGN);  // writes to closed peers must not kill us

    RelayConfig rcfg;
    rcfg.verbose = verbose;
    PairingConfig pcfg;
    pcfg.verbose = verbose;

    // Intentionally leaked: detached pairing-handler threads may reference the
    // server objects past run()'s return; the process is exiting anyway.
    auto* relay = new RelayServer(std::move(udp), rcfg);
    auto* pairing = new PairingServer(std::move(listen), ctx, pcfg);

    spl::logf("splice server up: pairing tcp/%u, relay udp/%u (bind %s)", tcp_port, udp_port,
              bind.empty() ? "*" : bind.c_str());

    std::thread relay_thr([relay]() { relay->run(g_stop); });
    pairing->run(g_stop);
    g_stop.store(true);
    relay_thr.join();
    spl::logf("splice server stopped");
    return 0;
}

}  // namespace spl::server
