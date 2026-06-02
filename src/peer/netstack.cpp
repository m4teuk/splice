#include "peer/netstack.h"

#include <algorithm>
#include <cstdio>
#include <cstring>

#include "lwip/init.h"
#include "lwip/ip6.h"
#include "lwip/ip6_addr.h"
#include "lwip/netif.h"
#include "lwip/pbuf.h"
#include "lwip/tcp.h"
#include "lwip/timeouts.h"

namespace spl::peer {

namespace {

// ---- lwIP C callback trampolines ----

err_t tramp_output_ip6(struct netif* nif, struct pbuf* p, const ip6_addr_t* /*dst*/) {
    static_cast<Netstack*>(nif->state)->emit(p);
    return ERR_OK;
}
err_t tramp_netif_input(struct pbuf* p, struct netif* nif) { return ip6_input(p, nif); }
err_t tramp_netif_init(struct netif* nif) {
    nif->name[0] = 's';
    nif->name[1] = 'l';
    nif->mtu = 1300;
    nif->output_ip6 = tramp_output_ip6;
    nif->flags = NETIF_FLAG_LINK_UP;
    return ERR_OK;
}

err_t tramp_recv(void* arg, tcp_pcb*, pbuf* p, err_t err) {
    return static_cast<TcpConn*>(arg)->on_lwip_recv(p, err);
}
err_t tramp_sent(void* arg, tcp_pcb*, u16_t len) {
    return static_cast<TcpConn*>(arg)->on_lwip_sent(len);
}
void tramp_err(void* arg, err_t err) { static_cast<TcpConn*>(arg)->on_lwip_err(err); }
err_t tramp_connected(void* arg, tcp_pcb*, err_t err) {
    return static_cast<TcpConn*>(arg)->on_lwip_connected(err);
}
err_t tramp_accept(void* arg, tcp_pcb* newpcb, err_t err) {
    return static_cast<Netstack*>(arg)->on_lwip_accept(newpcb, err);
}

ip6_addr_t to_ip6(const proto::Ip6& a) {
    ip6_addr_t out;
    std::memset(&out, 0, sizeof(out));
    std::memcpy(out.addr, a.data(), 16);
    return out;
}

}  // namespace

// ---- TcpConn ----

TcpConn::TcpConn(tcp_pcb* pcb) : pcb_(pcb) {
    tcp_arg(pcb_, this);
    tcp_err(pcb_, tramp_err);
}

void TcpConn::attach() {
    if (!pcb_) return;
    connected_ = true;  // established (connect succeeded or we accepted it)
    tcp_recv(pcb_, tramp_recv);
    tcp_sent(pcb_, tramp_sent);
}

void TcpConn::flush() {
    if (!pcb_) return;
    while (!pending_.empty()) {
        u16_t avail = tcp_sndbuf(pcb_);
        if (avail == 0) break;
        u16_t n = static_cast<u16_t>(std::min<size_t>(pending_.size(), avail));
        if (n > TCP_MSS) n = TCP_MSS;
        if (tcp_write(pcb_, pending_.data(), n, TCP_WRITE_FLAG_COPY) != ERR_OK) break;
        pending_.erase(pending_.begin(), pending_.begin() + n);
    }
    tcp_output(pcb_);
}

void TcpConn::send(ByteSpan data) {
    if (!pcb_) return;
    pending_.insert(pending_.end(), data.begin(), data.end());
    flush();
}

void TcpConn::do_close() {
    if (!pcb_) return;
    tcp_recv(pcb_, nullptr);
    tcp_sent(pcb_, nullptr);
    tcp_err(pcb_, nullptr);
    if (tcp_close(pcb_) != ERR_OK) tcp_abort(pcb_);
    pcb_ = nullptr;
}

void TcpConn::close() {
    want_close_ = true;  // tcp_close/tcp_abort must not run inside an lwIP callback,
    flush();             // so the actual teardown is deferred to poll_close() on the loop
}

void TcpConn::poll_close() {
    if (want_close_ && pending_.empty() && pcb_) do_close();
}

int TcpConn::on_lwip_recv(pbuf* p, int err) {
    if (err != ERR_OK) {
        if (p) pbuf_free(p);
        return ERR_OK;
    }
    if (!p) {  // peer half-closed (FIN): no more data from the peer
        if (on_closed) on_closed();
        return ERR_OK;
    }
    Bytes data(p->tot_len);
    pbuf_copy_partial(p, data.data(), p->tot_len, 0);
    tcp_recved(pcb_, p->tot_len);  // ack before the app callback (which may close)
    pbuf_free(p);
    if (on_recv) on_recv(as_span(data));
    return ERR_OK;
}

int TcpConn::on_lwip_sent(uint16_t) {
    flush();  // push more queued data now that the send buffer freed up
    if (!want_close_ && on_writable) on_writable();
    return ERR_OK;
}

size_t TcpConn::sndbuf() const { return pcb_ ? tcp_sndbuf(pcb_) : 0; }

void TcpConn::on_lwip_err(int) {
    pcb_ = nullptr;  // lwIP already freed the pcb
    if (!connected_ && fail_cb)
        fail_cb();  // the connect attempt failed before establishing — surface it
    else if (on_error)
        on_error();
    else if (on_closed)
        on_closed();
}

int TcpConn::on_lwip_connected(int err) {
    if (err != ERR_OK) {
        pcb_ = nullptr;
        if (fail_cb) fail_cb();
        return ERR_OK;
    }
    attach();
    if (connect_cb) connect_cb(this);
    return ERR_OK;
}

// ---- Netstack ----

Netstack::Netstack() { lwip_init(); }

Netstack::~Netstack() {
    if (listen_pcb_) tcp_close(listen_pcb_);
    delete netif_;
}

void Netstack::configure(const proto::Ip6& own_addr) {
    netif_ = new netif{};
    netif_add(netif_, this, tramp_netif_init, tramp_netif_input);
    netif_set_default(netif_);

    ip6_addr_t a = to_ip6(own_addr);
    netif_ip6_addr_set(netif_, 0, &a);
    netif_ip6_addr_set_state(netif_, 0, IP6_ADDR_PREFERRED);
    netif_set_up(netif_);
    netif_set_link_up(netif_);
}

void Netstack::input(ByteSpan ip_packet) {
    struct pbuf* p = pbuf_alloc(PBUF_RAW, static_cast<u16_t>(ip_packet.size()), PBUF_RAM);
    if (!p) return;
    pbuf_take(p, ip_packet.data(), static_cast<u16_t>(ip_packet.size()));
    if (netif_->input(p, netif_) != ERR_OK) pbuf_free(p);
}

void Netstack::check_timeouts() {
    sys_check_timeouts();
    if (netif_) netif_poll(netif_);  // process loopback queue
    // Perform deferred closes here (off the lwIP callback path), then reap failed
    // connect attempts so `spl send`'s retry loop doesn't accumulate dead conns.
    for (auto& c : conns_) c->poll_close();
    conns_.erase(std::remove_if(conns_.begin(), conns_.end(),
                                [](const std::unique_ptr<TcpConn>& c) {
                                    return c->dead_unconnected();
                                }),
                 conns_.end());
}

void Netstack::emit(pbuf* p) {
    if (!on_output) return;
    Bytes out(p->tot_len);
    pbuf_copy_partial(p, out.data(), p->tot_len, 0);
    on_output(as_span(out));
}

void Netstack::listen(uint16_t port, std::function<void(TcpConn*)> on_accept) {
    accept_cb_ = std::move(on_accept);
    tcp_pcb* pcb = tcp_new_ip_type(IPADDR_TYPE_V6);
    tcp_bind(pcb, IP_ANY_TYPE, port);
    listen_pcb_ = tcp_listen(pcb);
    tcp_arg(listen_pcb_, this);
    tcp_accept(listen_pcb_, tramp_accept);
}

int Netstack::on_lwip_accept(tcp_pcb* newpcb, int err) {
    if (err != ERR_OK || !newpcb) return ERR_VAL;
    auto conn = std::make_unique<TcpConn>(newpcb);
    TcpConn* raw = conn.get();
    conns_.push_back(std::move(conn));
    raw->attach();
    if (accept_cb_) accept_cb_(raw);
    return ERR_OK;
}

void Netstack::connect(const proto::Ip6& peer, uint16_t port,
                       std::function<void(TcpConn*)> on_connect, std::function<void()> on_fail) {
    tcp_pcb* pcb = tcp_new_ip_type(IPADDR_TYPE_V6);
    auto conn = std::make_unique<TcpConn>(pcb);
    TcpConn* raw = conn.get();
    raw->connect_cb = std::move(on_connect);
    raw->fail_cb = std::move(on_fail);
    conns_.push_back(std::move(conn));

    ip_addr_t dst;
    std::memset(&dst, 0, sizeof(dst));
    std::memcpy(&dst, peer.data(), 16);  // ip_addr_t == ip6_addr_t with LWIP_IPV4=0
    tcp_connect(pcb, &dst, port, tramp_connected);
}

}  // namespace spl::peer
