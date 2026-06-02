#include "peer/runtime.h"

#include <csignal>

#include "common/config.h"
#include "net/socket.h"

namespace spl::peer {

std::atomic<bool> g_stop{false};

namespace {
void on_signal(int) { g_stop.store(true); }

PathConfig make_cfg(const ConnRecord& rec, const Endpoint& server, bool verbose) {
    PathConfig c;
    c.uid = rec.uid;
    c.own_priv = rec.own_priv;
    c.peer_pub = rec.peer_pub;
    c.server = server;
    c.verbose = verbose;
    return c;
}
}  // namespace

PeerRuntime::PeerRuntime(ConnRecord rec, net::Fd udp, Endpoint server, bool verbose)
    : rec_(std::move(rec)), pm_(std::move(udp), make_cfg(rec_, server, verbose)), ns_() {
    own_ = rec_.ula_base;
    own_[15] = rec_.side ? 2 : 1;
    peer_ = rec_.ula_base;
    peer_[15] = rec_.side ? 1 : 2;

    ns_.configure(own_);
    pm_.on_inner = [this](ByteSpan inner, Path) { ns_.input(inner); };
    ns_.on_output = [this](ByteSpan ip) { pm_.send_inner(ip); };
    pm_.on_tick = [this](Millis now) {
        ns_.check_timeouts();
        if (on_app_tick) on_app_tick(now);
    };

    std::signal(SIGINT, on_signal);
    std::signal(SIGTERM, on_signal);
    std::signal(SIGPIPE, SIG_IGN);
}

std::unique_ptr<PeerRuntime> PeerRuntime::create(const std::string& conn_name, const PeerOpts& opts,
                                                 std::string* err) {
    auto store = Store::open(err);
    if (!store) return nullptr;
    auto rec = store->load(conn_name);
    if (!rec) {
        if (err) *err = "no connection named '" + conn_name + "' (pair first)";
        return nullptr;
    }
    auto srv = net::resolve(opts.server, opts.port);
    if (!srv) {
        if (err) *err = "cannot resolve " + opts.server;
        return nullptr;
    }
    std::string e2;
    net::Fd udp = net::udp_bind("", 0, &e2);
    if (!udp) {
        if (err) *err = "udp_bind: " + e2;
        return nullptr;
    }
    return std::unique_ptr<PeerRuntime>(
        new PeerRuntime(std::move(*rec), std::move(udp), *srv, opts.verbose));
}

void PeerRuntime::run() { pm_.run(g_stop); }

PeerOpts default_peer_opts() {
    PeerOpts o;
    Config c = load_config();
    if (!c.peer.addr.empty()) o.server = c.peer.addr;
    if (c.peer.port) o.port = c.peer.port;
    return o;
}

}  // namespace spl::peer
