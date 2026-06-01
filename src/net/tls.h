// Minimal blocking TLS over a connected socket, plus length-prefixed frame I/O.
//
// Trust model note: the relay server is untrusted; TLS here only protects the
// pairing traffic from passive network observers. Security comes from SPAKE2,
// so the client does NOT authenticate the server certificate (client_insecure).
#pragma once

#include <openssl/ssl.h>

#include <optional>
#include <string>

#include "common/bytes.h"
#include "net/socket.h"

namespace spl::net {

class TlsContext {
 public:
    // Server context. If cert/key are empty, generates an ephemeral self-signed
    // certificate (dev convenience; logged as such by the caller).
    static std::optional<TlsContext> server_ephemeral(std::string* err);
    static std::optional<TlsContext> server_from_files(const std::string& cert,
                                                       const std::string& key, std::string* err);
    // Client context that does not verify the server certificate (see note above).
    static std::optional<TlsContext> client_insecure(std::string* err);

    TlsContext(TlsContext&& o) noexcept : ctx_(o.ctx_) { o.ctx_ = nullptr; }
    TlsContext& operator=(TlsContext&& o) noexcept;
    TlsContext(const TlsContext&) = delete;
    ~TlsContext();

    SSL_CTX* get() const { return ctx_; }

 private:
    explicit TlsContext(SSL_CTX* c) : ctx_(c) {}
    SSL_CTX* ctx_ = nullptr;
};

class TlsConn {
 public:
    static std::optional<TlsConn> accept(const TlsContext& ctx, Fd fd, std::string* err);
    static std::optional<TlsConn> connect(const TlsContext& ctx, Fd fd, const std::string& sni,
                                          std::string* err);

    TlsConn(TlsConn&& o) noexcept : ssl_(o.ssl_), fd_(std::move(o.fd_)) { o.ssl_ = nullptr; }
    TlsConn& operator=(TlsConn&& o) noexcept;
    TlsConn(const TlsConn&) = delete;
    ~TlsConn();

    // Blocking; return false on EOF/error/timeout.
    bool read_exact(uint8_t* buf, size_t n);
    bool write_all(ByteSpan b);

    int fd() const { return fd_.get(); }

 private:
    TlsConn(SSL* s, Fd f) : ssl_(s), fd_(std::move(f)) {}
    SSL* ssl_ = nullptr;
    Fd fd_;
};

// [u32 length][payload] frame helpers over a TlsConn.
bool write_frame(TlsConn& c, ByteSpan payload);
std::optional<Bytes> read_frame(TlsConn& c, uint32_t max_len);

}  // namespace spl::net
