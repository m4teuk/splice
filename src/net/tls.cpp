#include "net/tls.h"

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

namespace spl::net {

namespace {

std::string tls_err(const char* what) {
    unsigned long e = ERR_get_error();
    char buf[256] = {0};
    if (e) ERR_error_string_n(e, buf, sizeof(buf));
    return std::string(what) + ": " + (e ? buf : "(no detail)");
}

// Generates an ephemeral P-256 self-signed certificate and installs it on ctx.
bool install_self_signed(SSL_CTX* ctx, std::string* err) {
    EVP_PKEY* pkey = EVP_EC_gen("P-256");
    if (!pkey) {
        if (err) *err = tls_err("EVP_EC_gen");
        return false;
    }
    X509* x = X509_new();
    bool ok = false;
    if (x) {
        X509_set_version(x, 2);
        ASN1_INTEGER_set(X509_get_serialNumber(x), 1);
        X509_gmtime_adj(X509_getm_notBefore(x), 0);
        X509_gmtime_adj(X509_getm_notAfter(x), 60L * 60 * 24 * 365);
        X509_set_pubkey(x, pkey);
        X509_NAME* name = X509_get_subject_name(x);
        X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                                   reinterpret_cast<const unsigned char*>("splice"), -1, -1, 0);
        X509_set_issuer_name(x, name);
        if (X509_sign(x, pkey, EVP_sha256()) > 0 && SSL_CTX_use_certificate(ctx, x) == 1 &&
            SSL_CTX_use_PrivateKey(ctx, pkey) == 1) {
            ok = true;
        }
    }
    if (!ok && err) *err = tls_err("self-signed cert");
    if (x) X509_free(x);
    EVP_PKEY_free(pkey);
    return ok;
}

SSL_CTX* new_ctx(const SSL_METHOD* method) {
    SSL_CTX* ctx = SSL_CTX_new(method);
    if (ctx) SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    return ctx;
}

}  // namespace

TlsContext::~TlsContext() {
    if (ctx_) SSL_CTX_free(ctx_);
}
TlsContext& TlsContext::operator=(TlsContext&& o) noexcept {
    if (this != &o) {
        if (ctx_) SSL_CTX_free(ctx_);
        ctx_ = o.ctx_;
        o.ctx_ = nullptr;
    }
    return *this;
}

std::optional<TlsContext> TlsContext::server_ephemeral(std::string* err) {
    SSL_CTX* ctx = new_ctx(TLS_server_method());
    if (!ctx) {
        if (err) *err = tls_err("SSL_CTX_new");
        return std::nullopt;
    }
    if (!install_self_signed(ctx, err)) {
        SSL_CTX_free(ctx);
        return std::nullopt;
    }
    return TlsContext(ctx);
}

std::optional<TlsContext> TlsContext::server_from_files(const std::string& cert,
                                                        const std::string& key, std::string* err) {
    SSL_CTX* ctx = new_ctx(TLS_server_method());
    if (!ctx) {
        if (err) *err = tls_err("SSL_CTX_new");
        return std::nullopt;
    }
    if (SSL_CTX_use_certificate_chain_file(ctx, cert.c_str()) != 1 ||
        SSL_CTX_use_PrivateKey_file(ctx, key.c_str(), SSL_FILETYPE_PEM) != 1) {
        if (err) *err = tls_err("load cert/key");
        SSL_CTX_free(ctx);
        return std::nullopt;
    }
    return TlsContext(ctx);
}

std::optional<TlsContext> TlsContext::client(std::string* err) {
    SSL_CTX* ctx = new_ctx(TLS_client_method());
    if (!ctx) {
        if (err) *err = tls_err("SSL_CTX_new");
        return std::nullopt;
    }
    SSL_CTX_set_default_verify_paths(ctx);              // system trust store
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);  // don't abort; report the result
    return TlsContext(ctx);
}

std::string tls_verify_error(long code) {
    return X509_verify_cert_error_string(code);
}

TlsConn::~TlsConn() {
    if (ssl_) {
        SSL_shutdown(ssl_);
        SSL_free(ssl_);
    }
}
TlsConn& TlsConn::operator=(TlsConn&& o) noexcept {
    if (this != &o) {
        if (ssl_) {
            SSL_shutdown(ssl_);
            SSL_free(ssl_);
        }
        ssl_ = o.ssl_;
        fd_ = std::move(o.fd_);
        verify_result_ = o.verify_result_;
        o.ssl_ = nullptr;
    }
    return *this;
}

std::optional<TlsConn> TlsConn::accept(const TlsContext& ctx, Fd fd, std::string* err) {
    SSL* ssl = SSL_new(ctx.get());
    if (!ssl) {
        if (err) *err = tls_err("SSL_new");
        return std::nullopt;
    }
    SSL_set_fd(ssl, fd.get());
    if (SSL_accept(ssl) <= 0) {
        if (err) *err = tls_err("SSL_accept");
        SSL_free(ssl);
        return std::nullopt;
    }
    return TlsConn(ssl, std::move(fd));
}

std::optional<TlsConn> TlsConn::connect(const TlsContext& ctx, Fd fd, const std::string& sni,
                                        std::string* err) {
    SSL* ssl = SSL_new(ctx.get());
    if (!ssl) {
        if (err) *err = tls_err("SSL_new");
        return std::nullopt;
    }
    SSL_set_fd(ssl, fd.get());
    if (!sni.empty()) {
        SSL_set_tlsext_host_name(ssl, sni.c_str());
        SSL_set1_host(ssl, sni.c_str());  // include the host in the verification result
    }
    if (SSL_connect(ssl) <= 0) {
        if (err) *err = tls_err("SSL_connect");
        SSL_free(ssl);
        return std::nullopt;
    }
    TlsConn conn(ssl, std::move(fd));
    conn.verify_result_ = SSL_get_verify_result(ssl);
    return conn;
}

bool TlsConn::read_exact(uint8_t* buf, size_t n) {
    size_t got = 0;
    while (got < n) {
        int r = SSL_read(ssl_, buf + got, static_cast<int>(n - got));
        if (r <= 0) return false;
        got += static_cast<size_t>(r);
    }
    return true;
}

bool TlsConn::write_all(ByteSpan b) {
    size_t sent = 0;
    while (sent < b.size()) {
        int r = SSL_write(ssl_, b.data() + sent, static_cast<int>(b.size() - sent));
        if (r <= 0) return false;
        sent += static_cast<size_t>(r);
    }
    return true;
}

bool write_frame(TlsConn& c, ByteSpan payload) {
    uint8_t hdr[4];
    const uint32_t len = static_cast<uint32_t>(payload.size());
    hdr[0] = static_cast<uint8_t>(len >> 24);
    hdr[1] = static_cast<uint8_t>(len >> 16);
    hdr[2] = static_cast<uint8_t>(len >> 8);
    hdr[3] = static_cast<uint8_t>(len);
    if (!c.write_all(ByteSpan(hdr, 4))) return false;
    return payload.empty() ? true : c.write_all(payload);
}

std::optional<Bytes> read_frame(TlsConn& c, uint32_t max_len) {
    uint8_t hdr[4];
    if (!c.read_exact(hdr, 4)) return std::nullopt;
    const uint32_t len =
        (uint32_t(hdr[0]) << 24) | (uint32_t(hdr[1]) << 16) | (uint32_t(hdr[2]) << 8) | hdr[3];
    if (len > max_len) return std::nullopt;
    Bytes p(len);
    if (len && !c.read_exact(p.data(), len)) return std::nullopt;
    return p;
}

}  // namespace spl::net
