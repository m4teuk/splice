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
    // Client context: loads the system trust store and computes the verification
    // result, but does NOT abort the handshake on failure — the caller decides
    // (pairing is protected by SPAKE2 regardless). See TlsConn::verify_result().
    static std::optional<TlsContext> client(std::string* err);

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

    TlsConn(TlsConn&& o) noexcept
        : ssl_(o.ssl_), fd_(std::move(o.fd_)), verify_result_(o.verify_result_) {
        o.ssl_ = nullptr;
    }
    TlsConn& operator=(TlsConn&& o) noexcept;
    TlsConn(const TlsConn&) = delete;
    ~TlsConn();

    // Blocking; return false on EOF/error/timeout.
    bool read_exact(uint8_t* buf, size_t n);
    bool write_all(ByteSpan b);

    int fd() const { return fd_.get(); }
    // 0 (X509_V_OK) if the server cert verified against the system trust store and
    // the host matched; otherwise an X509_V_ERR_* code (see tls_verify_error()).
    long verify_result() const { return verify_result_; }

 private:
    TlsConn(SSL* s, Fd f) : ssl_(s), fd_(std::move(f)) {}
    SSL* ssl_ = nullptr;
    Fd fd_;
    long verify_result_ = 0;
};

// [u32 length][payload] frame helpers over a TlsConn.
bool write_frame(TlsConn& c, ByteSpan payload);
std::optional<Bytes> read_frame(TlsConn& c, uint32_t max_len);

// Human-readable string for a TlsConn::verify_result() code.
std::string tls_verify_error(long code);

}  // namespace spl::net
