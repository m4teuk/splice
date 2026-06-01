#include "crypto/aead.h"

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>

namespace spl::crypto {

Bytes hkdf_sha256(ByteSpan ikm, ByteSpan salt, ByteSpan info, size_t out_len) {
    Bytes out(out_len);
    EVP_PKEY_CTX* p = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
    if (!p) return {};
    bool ok = EVP_PKEY_derive_init(p) > 0 && EVP_PKEY_CTX_set_hkdf_md(p, EVP_sha256()) > 0 &&
              EVP_PKEY_CTX_set1_hkdf_key(p, ikm.data(), static_cast<int>(ikm.size())) > 0;
    if (ok && !salt.empty()) {
        ok = EVP_PKEY_CTX_set1_hkdf_salt(p, salt.data(), static_cast<int>(salt.size())) > 0;
    }
    if (ok && !info.empty()) {
        ok = EVP_PKEY_CTX_add1_hkdf_info(p, info.data(), static_cast<int>(info.size())) > 0;
    }
    size_t len = out_len;
    if (ok) ok = EVP_PKEY_derive(p, out.data(), &len) > 0;
    EVP_PKEY_CTX_free(p);
    if (!ok) return {};
    out.resize(len);
    return out;
}

std::array<uint8_t, 32> hmac_sha256(ByteSpan key, ByteSpan data) {
    std::array<uint8_t, 32> mac{};
    unsigned int len = 32;
    HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()), data.data(), data.size(),
         mac.data(), &len);
    return mac;
}

Bytes aead_seal(ByteSpan key32, ByteSpan nonce12, ByteSpan pt, ByteSpan aad) {
    Bytes out(pt.size() + 16);
    EVP_CIPHER_CTX* c = EVP_CIPHER_CTX_new();
    if (!c) return {};
    int outl = 0;
    bool ok =
        EVP_EncryptInit_ex(c, EVP_chacha20_poly1305(), nullptr, nullptr, nullptr) > 0 &&
        EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_AEAD_SET_IVLEN, static_cast<int>(nonce12.size()), nullptr) >
            0 &&
        EVP_EncryptInit_ex(c, nullptr, nullptr, key32.data(), nonce12.data()) > 0;
    if (ok && !aad.empty()) {
        ok = EVP_EncryptUpdate(c, nullptr, &outl, aad.data(), static_cast<int>(aad.size())) > 0;
    }
    int total = 0;
    if (ok) ok = EVP_EncryptUpdate(c, out.data(), &outl, pt.data(), static_cast<int>(pt.size())) > 0;
    if (ok) {
        total = outl;
        ok = EVP_EncryptFinal_ex(c, out.data() + total, &outl) > 0;
        total += outl;
    }
    if (ok) ok = EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_AEAD_GET_TAG, 16, out.data() + total) > 0;
    EVP_CIPHER_CTX_free(c);
    if (!ok) return {};
    out.resize(static_cast<size_t>(total) + 16);
    return out;
}

std::optional<Bytes> aead_open(ByteSpan key32, ByteSpan nonce12, ByteSpan ct, ByteSpan aad) {
    if (ct.size() < 16) return std::nullopt;
    const size_t ctlen = ct.size() - 16;
    Bytes out(ctlen);
    EVP_CIPHER_CTX* c = EVP_CIPHER_CTX_new();
    if (!c) return std::nullopt;
    int outl = 0;
    bool ok =
        EVP_DecryptInit_ex(c, EVP_chacha20_poly1305(), nullptr, nullptr, nullptr) > 0 &&
        EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_AEAD_SET_IVLEN, static_cast<int>(nonce12.size()), nullptr) >
            0 &&
        EVP_DecryptInit_ex(c, nullptr, nullptr, key32.data(), nonce12.data()) > 0;
    if (ok && !aad.empty()) {
        ok = EVP_DecryptUpdate(c, nullptr, &outl, aad.data(), static_cast<int>(aad.size())) > 0;
    }
    int total = 0;
    if (ok)
        ok = EVP_DecryptUpdate(c, out.data(), &outl, ct.data(), static_cast<int>(ctlen)) > 0;
    if (ok) {
        total = outl;
        ok = EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_AEAD_SET_TAG, 16,
                                 const_cast<uint8_t*>(ct.data() + ctlen)) > 0;
    }
    int final_ok = ok ? EVP_DecryptFinal_ex(c, out.data() + total, &outl) : 0;
    EVP_CIPHER_CTX_free(c);
    if (!ok || final_ok <= 0) return std::nullopt;  // authentication failed
    out.resize(static_cast<size_t>(total) + outl);
    return out;
}

}  // namespace spl::crypto
