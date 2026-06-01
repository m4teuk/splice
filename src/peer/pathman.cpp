#include "peer/pathman.h"

#include <poll.h>
#include <sys/socket.h>

#include <cstring>

#include "common/bytes.h"
#include "common/log.h"
#include "native/native.h"
#include "proto/relay.h"

namespace spl::peer {

namespace {

constexpr uint8_t CH_WG = 0x00;
constexpr uint8_t CH_DISCO = 0x01;
constexpr uint8_t DISCO_CALLME = 0x01;
constexpr uint8_t DISCO_PING = 0x02;
constexpr uint8_t DISCO_PONG = 0x03;

constexpr Millis kTickMs = 250;
constexpr Millis kRegisterMs = 4000;
constexpr Millis kWhereamiMs = 1000;
constexpr Millis kCallmeMs = 1000;
constexpr Millis kPingMs = 700;
constexpr Millis kDirectDeadMs = 3000;

void send_to(int fd, const Endpoint& ep, ByteSpan d) {
    sockaddr_storage ss{};
    socklen_t len = 0;
    sockaddr_from_endpoint(ep, &ss, &len);
    ::sendto(fd, d.data(), d.size(), 0, reinterpret_cast<sockaddr*>(&ss), len);
}

Bytes build_inner(uint8_t ch, ByteSpan body) {
    Bytes b;
    b.reserve(1 + body.size());
    b.push_back(ch);
    b.insert(b.end(), body.begin(), body.end());
    return b;
}

Bytes build_callme(const Endpoint& e) {
    ByteWriter w;
    w.u8(DISCO_CALLME);
    w.array(e.ip);
    w.u16(e.port);
    return w.take();
}
Bytes build_ping(uint64_t tx) {
    ByteWriter w;
    w.u8(DISCO_PING);
    w.u64(tx);
    return w.take();
}
Bytes build_pong(uint64_t tx) {
    ByteWriter w;
    w.u8(DISCO_PONG);
    w.u64(tx);
    return w.take();
}

}  // namespace

const char* path_name(Path p) { return p == Path::Direct ? "DIRECT" : "RELAY"; }

PathManager::PathManager(net::Fd udp, PathConfig cfg)
    : udp_(std::move(udp)),
      cfg_(cfg),
      wg_(WgTunnel::create(cfg.own_priv, cfg.peer_pub, 1)) {}

void PathManager::send_payload(Path path, const Endpoint* direct_to, ByteSpan payload) {
    if (path == Path::Relay) {
        Bytes pkt = proto::encode_relay_up(cfg_.uid, payload);
        send_to(udp_.get(), cfg_.server, as_span(pkt));
    } else if (direct_to) {
        send_to(udp_.get(), *direct_to, payload);
    }
}

void PathManager::send_wg(ByteSpan wg) {
    Bytes payload = build_inner(CH_WG, wg);
    if (!force_relay_ && tx_path_ == Path::Direct && peer_direct_) {
        send_payload(Path::Direct, &*peer_direct_, as_span(payload));
    } else {
        send_payload(Path::Relay, nullptr, as_span(payload));
    }
}

void PathManager::send_register() {
    Bytes pkt = proto::encode_relay_up(cfg_.uid, {});  // empty payload = registration
    send_to(udp_.get(), cfg_.server, as_span(pkt));
}

bool PathManager::send_inner(ByteSpan ip_packet) {
    WgResult r = wg_.encapsulate(ip_packet);
    if (r.op == WgOp::WriteToNetwork) send_wg(as_span(r.data));
    return r.op != WgOp::Err;
}

void PathManager::pump_wg(WgResult r, Path via) {
    while (r.op == WgOp::WriteToNetwork) {
        send_wg(as_span(r.data));
        r = wg_.decapsulate({});
    }
    if (r.op == WgOp::WriteToTunnel) {
        if (via == Path::Direct && !direct_confirmed_) {
            direct_confirmed_ = true;
            if (cfg_.verbose) spl::logf("[path] direct path confirmed (data)");
        }
        if (on_inner) on_inner(as_span(r.data), via);
    }
}

void PathManager::handle_wg(ByteSpan body, Path via, Millis /*now*/) {
    pump_wg(wg_.decapsulate(body), via);
}

void PathManager::handle_disco(ByteSpan body, const Endpoint* from, Millis now) {
    ByteReader r(body);
    const uint8_t dt = r.u8();
    if (!r.ok()) return;
    if (dt == DISCO_CALLME) {
        Endpoint e{r.array<16>(), r.u16()};
        if (!r.ok()) return;
        if (!peer_direct_ || *peer_direct_ != e) {
            peer_direct_ = e;
            if (cfg_.verbose) spl::logf("[path] peer direct candidate %s", e.to_string().c_str());
        }
    } else if (dt == DISCO_PING) {
        const uint64_t tx = r.u64();
        if (!r.ok() || !from) return;
        Bytes pong = build_inner(CH_DISCO, as_span(build_pong(tx)));
        send_payload(Path::Direct, from, as_span(pong));
    } else if (dt == DISCO_PONG) {
        if (!direct_confirmed_) {
            direct_confirmed_ = true;
            if (cfg_.verbose) spl::logf("[path] direct path confirmed (pong)");
        }
        last_direct_recv_ = now;
    }
}

void PathManager::dispatch_inner(ByteSpan inner, Path via, const Endpoint* from, Millis now) {
    if (inner.empty()) return;
    if (via == Path::Direct) {
        last_direct_recv_ = now;
        if (from && (!peer_direct_ || *peer_direct_ != *from)) peer_direct_ = *from;
    }
    const uint8_t ch = inner[0];
    ByteSpan body = inner.subspan(1);
    if (ch == CH_WG) {
        handle_wg(body, via, now);
    } else if (ch == CH_DISCO) {
        handle_disco(body, from, now);
    }
}

void PathManager::process(const Endpoint& src, ByteSpan raw, Millis now) {
    if (force_relay_ && !(src == cfg_.server)) return;  // pretend the direct path is gone
    if (src == cfg_.server) {
        auto t = proto::peek_udp_type(raw);
        if (t == proto::UdpType::kWhereami) {
            auto rep = proto::decode_whereami_reply(raw);
            if (rep && rep->token == whereami_token_) {
                Endpoint e{rep->ip, rep->port};
                if (!external_ || *external_ != e) {
                    external_ = e;
                    if (cfg_.verbose) spl::logf("[path] external address %s", e.to_string().c_str());
                }
            }
        } else if (t == proto::UdpType::kRelay) {
            auto inner = proto::decode_relay_down(raw);
            if (inner) dispatch_inner(as_span(*inner), Path::Relay, nullptr, now);
        }
    } else {
        dispatch_inner(raw, Path::Direct, &src, now);
    }
}

void PathManager::update_tx_path(Millis now) {
    const bool direct_ok =
        !force_relay_ && direct_confirmed_ && peer_direct_ && (now - last_direct_recv_ < kDirectDeadMs);
    const Path want = direct_ok ? Path::Direct : Path::Relay;
    if (want != tx_path_) {
        tx_path_ = want;
        if (cfg_.verbose) spl::logf("[path] switched to %s", path_name(want));
    }
}

void PathManager::run(std::atomic<bool>& stop) {
    net::set_nonblocking(udp_.get(), true);
    send_register();
    start_ = mono_ms();

    std::vector<uint8_t> buf(4096);
    while (!stop.load()) {
        pollfd pfds[2];
        pfds[0] = pollfd{udp_.get(), POLLIN, 0};
        int nfds = 1;
        if (extra_fd_ >= 0) {
            pfds[1] = pollfd{extra_fd_, POLLIN, 0};
            nfds = 2;
        }
        ::poll(pfds, nfds, 100);
        const Millis now = mono_ms();

        if (pfds[0].revents & POLLIN) {
            for (;;) {
                sockaddr_storage ss{};
                socklen_t slen = sizeof(ss);
                ssize_t n = ::recvfrom(udp_.get(), buf.data(), buf.size(), 0,
                                       reinterpret_cast<sockaddr*>(&ss), &slen);
                if (n < 0) break;
                process(endpoint_from_sockaddr(ss), ByteSpan(buf.data(), static_cast<size_t>(n)),
                        now);
            }
        }
        if (nfds == 2 && (pfds[1].revents & (POLLIN | POLLHUP | POLLERR)) && on_extra_readable_) {
            on_extra_readable_();
        }

        if (now - t_tick_ >= kTickMs) {
            t_tick_ = now;
            WgResult r = wg_.tick();
            if (r.op == WgOp::WriteToNetwork) send_wg(as_span(r.data));
        }
        if (now - t_register_ >= kRegisterMs) {
            t_register_ = now;
            send_register();
        }
        // Hole-punching (disco) — optionally delayed so the relay phase is observable.
        if (now - start_ >= cfg_.disco_delay_ms) {
            if (!external_ && now - t_whereami_ >= kWhereamiMs) {
                t_whereami_ = now;
                spl_random_bytes(reinterpret_cast<uint8_t*>(&whereami_token_),
                                 sizeof(whereami_token_));
                Bytes q = proto::encode_whereami_req(whereami_token_);
                send_to(udp_.get(), cfg_.server, as_span(q));
            }
            if (external_ && !direct_confirmed_ && now - t_callme_ >= kCallmeMs) {
                t_callme_ = now;
                Bytes inner = build_inner(CH_DISCO, as_span(build_callme(*external_)));
                send_payload(Path::Relay, nullptr, as_span(inner));
            }
            if (!force_relay_ && peer_direct_ && now - t_ping_ >= kPingMs) {
                t_ping_ = now;
                Bytes inner = build_inner(CH_DISCO, as_span(build_ping(++ping_txid_)));
                send_payload(Path::Direct, &*peer_direct_, as_span(inner));
            }
        }

        update_tx_path(now);
        if (on_tick) on_tick(now);
    }
}

}  // namespace spl::peer
