#include "server/pairing_server.h"

#include <poll.h>

#include <chrono>
#include <thread>
#include <variant>

#include "common/log.h"
#include "proto/frame.h"

namespace spl::server {

PairingServer::PairingServer(net::Fd listen, std::shared_ptr<net::TlsContext> ctx,
                             PairingConfig cfg)
    : listen_(std::move(listen)), ctx_(std::move(ctx)), cfg_(cfg) {}

bool PairingServer::send_ctrl(net::TlsConn& c, const proto::CtrlMessage& m) {
    Bytes b = proto::encode_ctrl(m);
    return net::write_frame(c, as_span(b));
}

void PairingServer::cleanup(uint64_t code) {
    std::lock_guard<std::mutex> lk(mu_);
    sessions_.erase(code);
    alloc_.release(code, mono_ms());
}

void PairingServer::run(std::atomic<bool>& stop) {
    net::set_nonblocking(listen_.get(), true);
    while (!stop.load()) {
        pollfd pfd{listen_.get(), POLLIN, 0};
        if (::poll(&pfd, 1, 500) <= 0) continue;
        if (!(pfd.revents & POLLIN)) continue;
        for (;;) {
            Endpoint peer;
            net::Fd c = net::tcp_accept(listen_.get(), &peer);
            if (!c) break;  // drained
            std::thread(&PairingServer::handle, this, std::move(c), peer).detach();
        }
    }
}

void PairingServer::handle(net::Fd raw, Endpoint peer) {
    std::string err;
    net::set_recv_timeout(raw.get(), static_cast<int>(cfg_.bridge_timeout_ms));
    auto conn_opt = net::TlsConn::accept(*ctx_, std::move(raw), &err);
    if (!conn_opt) {
        if (cfg_.verbose) logf("[pair] TLS accept from %s failed: %s", peer.to_string().c_str(),
                               err.c_str());
        return;
    }
    net::TlsConn conn = std::move(*conn_opt);

    auto first = net::read_frame(conn, proto::kMaxFrameLen);
    if (!first) return;
    auto msg = proto::decode_ctrl(as_span(*first));
    if (!msg) {
        send_ctrl(conn, proto::Error{1, "bad message"});
        return;
    }

    if (std::holds_alternative<proto::Init>(*msg)) {
        handle_leader(conn, peer);
    } else if (std::holds_alternative<proto::Join>(*msg)) {
        handle_follower(conn, peer, std::get<proto::Join>(*msg).code);
    } else {
        send_ctrl(conn, proto::Error{2, "unexpected message"});
    }
}

void PairingServer::handle_leader(net::TlsConn& conn, const Endpoint& peer) {
    if (active_sessions_.fetch_add(1) + 1 > cfg_.max_sessions) {
        active_sessions_.fetch_sub(1);
        send_ctrl(conn, proto::Error{3, "server busy"});
        return;
    }

    uint64_t code = 0;
    auto p = std::make_shared<Pending>();
    {
        std::lock_guard<std::mutex> lk(mu_);
        auto c = alloc_.allocate(mono_ms(), cfg_.code_ttl_ms);
        if (!c) {
            active_sessions_.fetch_sub(1);
            send_ctrl(conn, proto::Error{4, "no codes available"});
            return;
        }
        code = *c;
        sessions_[code] = p;
    }

    if (!send_ctrl(conn, proto::Code{code, static_cast<uint32_t>(cfg_.code_ttl_ms / 1000)})) {
        cleanup(code);
        active_sessions_.fetch_sub(1);
        return;
    }
    if (cfg_.verbose)
        logf("[pair] %s -> code %llu", peer.to_string().c_str(), (unsigned long long)code);

    std::optional<net::TlsConn> follower;
    {
        std::unique_lock<std::mutex> lk(p->m);
        p->cv.wait_for(lk, std::chrono::milliseconds(cfg_.code_ttl_ms),
                       [&] { return p->follower.has_value(); });
        if (p->follower) follower = std::move(*p->follower);
    }

    if (!follower) {
        send_ctrl(conn, proto::Error{5, "pairing code expired"});
    } else {
        net::TlsConn fconn = std::move(*follower);
        if (send_ctrl(conn, proto::Paired{}) && send_ctrl(fconn, proto::Paired{})) {
            if (cfg_.verbose) logf("[pair] code %llu paired, bridging", (unsigned long long)code);
            bridge(conn, fconn);
        }
    }

    cleanup(code);
    active_sessions_.fetch_sub(1);
}

void PairingServer::handle_follower(net::TlsConn& conn, const Endpoint& peer, uint64_t code) {
    std::shared_ptr<Pending> p;
    {
        std::lock_guard<std::mutex> lk(mu_);
        auto it = sessions_.find(code);
        if (it == sessions_.end() || it->second->taken) {
            send_ctrl(conn, proto::Error{6, "unknown or already-claimed code"});
            return;
        }
        it->second->taken = true;
        p = it->second;
    }
    if (cfg_.verbose)
        logf("[pair] %s -> joins code %llu", peer.to_string().c_str(), (unsigned long long)code);

    // Hand ownership of this connection to the waiting leader thread.
    std::lock_guard<std::mutex> lk(p->m);
    p->follower = std::move(conn);
    p->cv.notify_one();
}

void PairingServer::bridge(net::TlsConn& leader, net::TlsConn& follower) {
    // Strictly turn-based, leader first: read one frame from the side whose turn
    // it is, forward it to the other, then swap. One thread touches both SSLs, so
    // there is never concurrent access to an SSL object.
    net::TlsConn* turn = &leader;
    net::TlsConn* other = &follower;
    for (;;) {
        auto frame = net::read_frame(*turn, proto::kMaxFrameLen);
        if (!frame) break;  // EOF / error / timeout
        if (!net::write_frame(*other, *frame)) break;
        std::swap(turn, other);
    }
}

}  // namespace spl::server
