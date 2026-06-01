#include "peer/wg.h"

#include "native/native.h"

namespace spl::peer {

namespace {
WgOp op_from(int32_t o) {
    switch (o) {
        case 0:
            return WgOp::Done;
        case 1:
            return WgOp::WriteToNetwork;
        case 2:
        case 3:
            return WgOp::WriteToTunnel;
        default:
            return WgOp::Err;
    }
}
}  // namespace

WgTunnel WgTunnel::create(const proto::WgKey& own_priv, const proto::WgKey& peer_pub,
                          uint32_t index) {
    return WgTunnel(spl_wg_new(own_priv.data(), peer_pub.data(), index));
}

WgTunnel::WgTunnel(WgTunnel&& o) noexcept : t_(o.t_), scratch_(std::move(o.scratch_)) {
    o.t_ = nullptr;
}
WgTunnel& WgTunnel::operator=(WgTunnel&& o) noexcept {
    if (this != &o) {
        if (t_) spl_wg_free(t_);
        t_ = o.t_;
        scratch_ = std::move(o.scratch_);
        o.t_ = nullptr;
    }
    return *this;
}
WgTunnel::~WgTunnel() {
    if (t_) spl_wg_free(t_);
}

WgResult WgTunnel::encapsulate(ByteSpan ip_packet) {
    SplWgOut o = spl_wg_encapsulate(t_, ip_packet.data(), ip_packet.size(), scratch_.data(),
                                    scratch_.size());
    WgResult r;
    r.op = op_from(o.op);
    if (o.len) r.data.assign(scratch_.begin(), scratch_.begin() + o.len);
    return r;
}

WgResult WgTunnel::decapsulate(ByteSpan datagram) {
    SplWgOut o = spl_wg_decapsulate(t_, datagram.data(), datagram.size(), scratch_.data(),
                                    scratch_.size());
    WgResult r;
    r.op = op_from(o.op);
    if (o.len) r.data.assign(scratch_.begin(), scratch_.begin() + o.len);
    return r;
}

WgResult WgTunnel::tick() {
    SplWgOut o = spl_wg_tick(t_, scratch_.data(), scratch_.size());
    WgResult r;
    r.op = op_from(o.op);
    if (o.len) r.data.assign(scratch_.begin(), scratch_.begin() + o.len);
    return r;
}

}  // namespace spl::peer
