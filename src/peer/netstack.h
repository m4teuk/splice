// Userspace TCP/IP via lwIP (NO_SYS, IPv6-only). lwIP itself is process-global
// and initialized once; each Netstack owns one netif, so a process may run one
// per peer session (the disjoint ULA /64s route between them). Outgoing IP
// packets go to on_output (the path manager); received inner packets are fed in
// via input(). All Netstacks share one thread — the owner's event loop.
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
    ~TcpConn();  // aborts the pcb if still open (no callbacks fire)

    void send(ByteSpan data);  // queues and flushes subject to TCP flow control
    void close();        // request close; the teardown is deferred to poll_close()
    void poll_close();   // perform a requested close — called from the loop, never a callback

    // lwIP callback handlers (invoked by the static trampolines).
    int on_lwip_recv(pbuf* p, int err);
    int on_lwip_sent(uint16_t len);
    void on_lwip_err(int err);
    int on_lwip_connected(int err);

    std::function<void(TcpConn*)> connect_cb;
    std::function<void()> fail_cb;
    void attach();  // install recv/sent callbacks (after connect/accept); marks established

    // A connect attempt that failed before it ever established: its pcb is gone and
    // it was never handed to the app, so it is safe to reap.
    bool dead_unconnected() const { return !pcb_ && !connected_; }
    // The pcb is gone (closed or errored): nothing can happen anymore. The app
    // must drop its pointer in on_closed/on_error/after close(); the owner reaps
    // dead conns from the loop.
    bool dead() const { return !pcb_; }

 private:
    void flush();
    void do_close();

    tcp_pcb* pcb_;
    Bytes pending_;
    bool connected_ = false;  // ever established (connect succeeded or accepted)
    bool want_close_ = false;
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

    // Listens on our own tunnel address (not IP_ANY, so per-session listeners
    // on the same port don't collide).
    void listen(uint16_t port, std::function<void(TcpConn*)> on_accept);
    void connect(const proto::Ip6& peer, uint16_t port, std::function<void(TcpConn*)> on_connect,
                 std::function<void()> on_fail);

    // internal (called by trampolines)
    void emit(pbuf* p);
    int on_lwip_accept(tcp_pcb* newpcb, int err);

 private:
    netif* netif_ = nullptr;
    proto::Ip6 own_addr_{};
    tcp_pcb* listen_pcb_ = nullptr;
    std::function<void(TcpConn*)> accept_cb_;
    std::vector<std::unique_ptr<TcpConn>> conns_;
};

}  // namespace spl::peer
