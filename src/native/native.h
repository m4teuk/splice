// C++ view of the Rust shim's FFI surface (native/src/lib.rs).
//
// Hand-maintained (kept in sync with lib.rs) rather than using the
// cbindgen-generated spl_native.h, to avoid build-order coupling between the
// cargo build and C++ compilation. The surface is small and stable.
#pragma once

#include <cstddef>
#include <cstdint>

extern "C" {

// Phase 0 self-test / version.
int spl_native_selftest(int x);
int spl_native_version(unsigned char* buf, size_t len);

// CSPRNG: fill out[..len] with secure random bytes.
void spl_random_bytes(uint8_t* out, size_t len);

// Fresh X25519 keypair (clamped private + public), 32 bytes each.
void spl_wg_keypair(uint8_t out_priv[32], uint8_t out_pub[32]);

// Symmetric SPAKE2. start() returns an opaque state (or null) and writes the
// outbound message; finish() consumes the state and yields the shared key.
void* spl_spake2_start(const uint8_t* password, size_t password_len, uint8_t* out_msg,
                       size_t out_cap, size_t* out_len);
int spl_spake2_finish(void* state, const uint8_t* in_msg, size_t in_len, uint8_t* out_key,
                      size_t out_cap, size_t* out_len);
void spl_spake2_free(void* state);

// WireGuard (boringtun Tunn). op: 0 = Done, 1 = WriteToNetwork,
// 2 = WriteToTunnelV4, 3 = WriteToTunnelV6, -1 = Err. `len` is bytes written into
// dst (the relevant slice always starts at dst[0]). Layout matches Rust WgOut.
typedef struct SplWgOut {
    int32_t op;
    size_t len;
} SplWgOut;

void* spl_wg_new(const uint8_t* static_priv, const uint8_t* peer_pub, uint32_t index);
void spl_wg_free(void* t);
SplWgOut spl_wg_encapsulate(void* t, const uint8_t* src, size_t src_len, uint8_t* dst,
                            size_t dst_cap);
SplWgOut spl_wg_decapsulate(void* t, const uint8_t* dg, size_t dg_len, uint8_t* dst,
                            size_t dst_cap);
SplWgOut spl_wg_tick(void* t, uint8_t* dst, size_t dst_cap);

}  // extern "C"
