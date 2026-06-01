#include "server/relay_server.h"

#include <poll.h>
#include <sys/socket.h>

#include <vector>

#include "common/log.h"
#include "proto/relay.h"

namespace spl::server {

RelayServer::RelayServer(net::Fd udp, RelayConfig cfg)
    : udp_(std::move(udp)),
      cfg_(cfg),
      table_(cfg.entry_ttl_ms),
      limiter_(cfg.per_ip_rate, cfg.per_ip_burst, cfg.global_rate, cfg.global_burst) {}

namespace {
void udp_send(int fd, const Endpoint& ep, ByteSpan data) {
    sockaddr_storage ss{};
    socklen_t len = 0;
    sockaddr_from_endpoint(ep, &ss, &len);
    ::sendto(fd, data.data(), data.size(), 0, reinterpret_cast<sockaddr*>(&ss), len);
}
}  // namespace

void RelayServer::run(std::atomic<bool>& stop) {
    net::set_nonblocking(udp_.get(), true);
    std::vector<uint8_t> buf(2048);
    Millis last_maint = mono_ms();

    while (!stop.load()) {
        pollfd pfd{udp_.get(), POLLIN, 0};
        int pr = ::poll(&pfd, 1, 500);
        const Millis now = mono_ms();

        if (pr > 0 && (pfd.revents & POLLIN)) {
            for (;;) {
                sockaddr_storage ss{};
                socklen_t slen = sizeof(ss);
                ssize_t n = ::recvfrom(udp_.get(), buf.data(), buf.size(), 0,
                                       reinterpret_cast<sockaddr*>(&ss), &slen);
                if (n < 0) break;  // drained (EAGAIN)
                const Endpoint src = endpoint_from_sockaddr(ss);
                if (!limiter_.allow(src.ip, now)) continue;

                ByteSpan pkt(buf.data(), static_cast<size_t>(n));
                auto type = proto::peek_udp_type(pkt);
                if (!type) continue;

                if (*type == proto::UdpType::kRelay) {
                    auto up = proto::decode_relay_up(pkt);
                    if (!up) continue;
                    auto dst = table_.on_packet(up->uid, src, now);
                    if (dst) {
                        Bytes down = proto::encode_relay_down(as_span(up->payload));
                        udp_send(udp_.get(), *dst, as_span(down));
                    }
                } else {  // whereami
                    auto tok = proto::decode_whereami_req(pkt);
                    if (!tok) continue;
                    Bytes rep =
                        proto::encode_whereami_reply(proto::WhereamiReply{*tok, src.ip, src.port});
                    udp_send(udp_.get(), src, as_span(rep));
                }
            }
        }

        if (now - last_maint > 1000) {
            table_.evict_expired(now);
            limiter_.evict_idle(now, 300'000);
            last_maint = now;
        }
    }
}

}  // namespace spl::server
