// Userspace TCP/IP via lwIP (NO_SYS, IPv6-only). lwIP is process-global, so there
// is one Netstack per process. Outgoing IP packets go to on_output (the path
// manager); received inner packets are fed in via input().
#pragma once

#include <cstdint>
#include <functional>
#include <memory>
#include <vector>

#include "common/bytes.h"
#include "proto/pairing.h"  // Ip6

struct netif;
struct tcp_pcb;
struct pbuf;

namespace spl::peer {

// One TCP connection over the tunnel (raw lwIP API underneath).
class TcpConn {
 public:
    std::function<void(ByteSpan)> on_recv;
    std::function<void()> on_closed;    // peer half-closed (sent FIN; no more data)
    std::function<void()> on_error;     // hard failure (pcb gone)
    std::function<void()> on_writable;  // send buffer freed up (for flow control)

    size_t sndbuf() const;  // bytes that can be queued right now

    explicit TcpConn(tcp_pcb* pcb);

    void send(ByteSpan data);  // queues and flushes subject to TCP flow control
    void end_tx();             // flush, then half-close the send direction (FIN)
    void close();              // flush then close

    // lwIP callback handlers (invoked by the static trampolines).
    int on_lwip_recv(pbuf* p, int err);
    int on_lwip_sent(uint16_t len);
    void on_lwip_err(int err);
    int on_lwip_connected(int err);

    std::function<void(TcpConn*)> connect_cb;
    std::function<void()> fail_cb;
    void attach();  // install recv/sent callbacks (after connect/accept)

 private:
    void flush();
    void do_close();
    void maybe_shutdown_tx();

    tcp_pcb* pcb_;
    Bytes pending_;
    bool want_close_ = false;
    bool tx_shutdown_pending_ = false;
};

class Netstack {
 public:
    Netstack();
    ~Netstack();
    Netstack(const Netstack&) = delete;

    void configure(const proto::Ip6& own_addr);  // bring up the tunnel interface
    void input(ByteSpan ip_packet);              // feed a received inner IP packet
    void check_timeouts();                       // drive lwIP timers + loopback

    std::function<void(ByteSpan)> on_output;  // sink for outgoing inner IP packets

    void listen(uint16_t port, std::function<void(TcpConn*)> on_accept);
    void connect(const proto::Ip6& peer, uint16_t port, std::function<void(TcpConn*)> on_connect,
                 std::function<void()> on_fail);

    // internal (called by trampolines)
    void emit(pbuf* p);
    int on_lwip_accept(tcp_pcb* newpcb, int err);

 private:
    netif* netif_ = nullptr;
    tcp_pcb* listen_pcb_ = nullptr;
    std::function<void(TcpConn*)> accept_cb_;
    std::vector<std::unique_ptr<TcpConn>> conns_;
};

}  // namespace spl::peer
