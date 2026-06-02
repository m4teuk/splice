#include "server/server_main.h"

#include <unistd.h>

#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <atomic>
#include <iostream>
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

// Suggested values offered during setup — never assumed silently for a fresh run;
// the operator confirms (or overrides) each one in the walkthrough.
namespace suggest {
constexpr const char* addr = "::";
constexpr uint16_t port = 7777;
constexpr double per_ip_rate = 500, per_ip_burst = 1000;
constexpr double global_rate = 100000, global_burst = 200000;
}  // namespace suggest

void usage() {
    spl::logf(
        "usage: spl server [options]\n"
        "  --setup         (re)run the interactive configuration walkthrough\n"
        "  --bind HOST     address to bind\n"
        "  --port N        TCP (pairing) and UDP (relay) port\n"
        "  --tcp-port N    override pairing TCP port\n"
        "  --udp-port N    override relay UDP port\n"
        "  --cert FILE     TLS certificate (PEM); ephemeral self-signed if omitted\n"
        "  --key FILE      TLS private key (PEM)\n"
        "  -v, --verbose   verbose logging\n"
        "\n"
        "With no config and no flags, the first run walks you through setup.");
}

// Render a number as a plain integer when whole (for prompt defaults).
std::string num_str(double v) {
    if (v == static_cast<long long>(v)) return std::to_string(static_cast<long long>(v));
    return std::to_string(v);
}

// Prompt with a suggested default; an empty answer accepts the suggestion.
std::string ask(const std::string& label, const std::string& def) {
    if (def.empty())
        std::printf("%s: ", label.c_str());
    else
        std::printf("%s [%s]: ", label.c_str(), def.c_str());
    std::fflush(stdout);
    std::string line;
    if (!std::getline(std::cin, line)) return def;  // EOF -> accept the default
    size_t a = line.find_first_not_of(" \t\r\n");
    if (a == std::string::npos) return def;
    size_t b = line.find_last_not_of(" \t\r\n");
    return line.substr(a, b - a + 1);
}

// The address a client should put in its config to reach this server. A wildcard
// bind tells us nothing routable, so we ask the operator to fill it in.
std::string client_addr_hint(const std::string& bind) {
    if (bind.empty() || bind == "::" || bind == "0.0.0.0" || bind == "*")
        return "<this server's hostname or public IP>";
    return bind;
}

ServerConfig run_setup() {
    std::printf("\nLet's configure your splice relay server.\n");
    std::printf("Press Enter to accept the [suggested] value, or type your own.\n\n");

    ServerConfig s;
    s.addr = ask("Bind address (interface to listen on)", suggest::addr);
    s.port = static_cast<uint16_t>(std::atoi(
        ask("Port (TCP for pairing + UDP for relay)", std::to_string(suggest::port)).c_str()));

    std::printf("\n  Clients reach this server over the network. Once setup is done,\n");
    std::printf("  put this in each client's config [peer] section:\n");
    std::printf("    addr = %s\n    port = %u\n\n", client_addr_hint(s.addr).c_str(), s.port);

    std::printf("Rate limits (cost-control safeguard, not security):\n");
    s.per_ip_rate = std::atof(ask("  Per-IP packets/sec", num_str(suggest::per_ip_rate)).c_str());
    s.per_ip_burst = std::atof(ask("  Per-IP burst", num_str(suggest::per_ip_burst)).c_str());
    s.global_rate = std::atof(ask("  Global packets/sec", num_str(suggest::global_rate)).c_str());
    s.global_burst = std::atof(ask("  Global burst", num_str(suggest::global_burst)).c_str());

    std::printf("\nTLS certificate (blank = ephemeral self-signed dev cert):\n");
    s.cert = ask("  Certificate path (PEM)", "");
    if (!s.cert.empty()) s.key = ask("  Private key path (PEM)", "");
    return s;
}

}  // namespace

int server_main(int argc, char** argv) {
    Config cfg = load_config();
    const bool have_config = config_exists();

    std::string cli_bind, cli_cert, cli_key;
    uint16_t cli_port = 0, cli_tcp = 0, cli_udp = 0;
    bool verbose = false, force_setup = false;
    bool has_bind = false, has_port = false, has_cert = false, has_key = false;

    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        auto need = [&](const char* name) -> const char* {
            if (i + 1 >= argc) {
                spl::logf("spl server: missing value for %s", name);
                return nullptr;
            }
            return argv[++i];
        };
        if (a == "--setup") {
            force_setup = true;
        } else if (a == "--bind") {
            auto v = need("--bind");
            if (!v) return 2;
            cli_bind = v;
            has_bind = true;
        } else if (a == "--port") {
            auto v = need("--port");
            if (!v) return 2;
            cli_port = static_cast<uint16_t>(std::atoi(v));
            has_port = true;
        } else if (a == "--tcp-port") {
            auto v = need("--tcp-port");
            if (!v) return 2;
            cli_tcp = static_cast<uint16_t>(std::atoi(v));
        } else if (a == "--udp-port") {
            auto v = need("--udp-port");
            if (!v) return 2;
            cli_udp = static_cast<uint16_t>(std::atoi(v));
        } else if (a == "--cert") {
            auto v = need("--cert");
            if (!v) return 2;
            cli_cert = v;
            has_cert = true;
        } else if (a == "--key") {
            auto v = need("--key");
            if (!v) return 2;
            cli_key = v;
            has_key = true;
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

    const bool any_cli = has_bind || has_port || has_cert || has_key || cli_tcp || cli_udp;

    // Decide where settings come from: an explicit walkthrough, an existing config,
    // explicit CLI flags, or — refusing to silently assume defaults — a clear error.
    ServerConfig eff;
    if (force_setup || (!have_config && !any_cli && ::isatty(STDIN_FILENO))) {
        if (have_config)
            std::printf("Reconfiguring (a config already exists at %s).\n", config_path().c_str());
        eff = run_setup();
        std::string werr;
        if (write_server_config(eff, &werr))
            std::printf("\nSaved configuration to %s\n", config_path().c_str());
        else
            spl::logf("warning: could not save config: %s", werr.c_str());
        std::printf("To connect a client to this server, set in its config [peer] section:\n");
        std::printf("  addr = %s\n  port = %u\n", client_addr_hint(eff.addr).c_str(), eff.port);
        std::printf("(or pass:  spl pair --server %s --port %u)\n\n",
                    client_addr_hint(eff.addr).c_str(), eff.port);
        std::fflush(stdout);
    } else if (have_config) {
        eff = cfg.server;
    } else if (any_cli) {
        eff = ServerConfig{};  // flags supply what matters; suggestions fill the rest below
    } else {
        spl::logf(
            "No configuration found. Run `spl server` in a terminal to set it up\n"
            "(or `spl server --setup`), or pass flags like --port. See %s.",
            config_path().c_str());
        return 1;
    }

    // CLI flags override whatever source we chose.
    if (has_bind) eff.addr = cli_bind;
    if (has_port) eff.port = cli_port;
    if (has_cert) eff.cert = cli_cert;
    if (has_key) eff.key = cli_key;

    // Backfill anything still unset from the documented suggestions (a config or
    // CLI invocation that omits rate limits still gets a working limiter).
    if (eff.port == 0) eff.port = suggest::port;
    if (eff.per_ip_rate == 0) eff.per_ip_rate = suggest::per_ip_rate;
    if (eff.per_ip_burst == 0) eff.per_ip_burst = suggest::per_ip_burst;
    if (eff.global_rate == 0) eff.global_rate = suggest::global_rate;
    if (eff.global_burst == 0) eff.global_burst = suggest::global_burst;

    const std::string bind = eff.addr;  // "" / "::" both mean any interface
    const uint16_t tcp_port = cli_tcp ? cli_tcp : eff.port;
    const uint16_t udp_port = cli_udp ? cli_udp : eff.port;

    std::string err;
    std::shared_ptr<net::TlsContext> ctx;
    if (!eff.cert.empty() || !eff.key.empty()) {
        if (eff.cert.empty() || eff.key.empty()) {
            spl::logf("spl server: cert and key must be given together");
            return 2;
        }
        auto c = net::TlsContext::server_from_files(eff.cert, eff.key, &err);
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
    rcfg.per_ip_rate = eff.per_ip_rate;
    rcfg.per_ip_burst = eff.per_ip_burst;
    rcfg.global_rate = eff.global_rate;
    rcfg.global_burst = eff.global_burst;
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
