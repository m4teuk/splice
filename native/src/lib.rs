//! `spl-native`: a small, stable C ABI shim that the C++ `spl` binary links against.
//!
//! This crate is the single home for the two security-critical primitives that
//! are not provided by the system OpenSSL:
//!   * WireGuard, via the `boringtun` crate's `noise::Tunn` API (added in Phase 4);
//!   * SPAKE2, via the `spake2` crate (added in Phase 3).
//!
//! Phase 0 exposes only a self-test, to prove the Rust <-> C++ static-link works
//! on this host before any real code depends on it.

use boringtun::noise::{Tunn, TunnResult};
use spake2::{Ed25519Group, Identity, Password, Spake2};
use std::os::raw::{c_int, c_void};
use std::ptr::{copy_nonoverlapping, null_mut};

/// Round-trips an integer across the FFI boundary: returns `x + 1`.
///
/// The C++ side calls this with 41 and expects 42, confirming the static library
/// links and the ABI matches.
#[no_mangle]
pub extern "C" fn spl_native_selftest(x: c_int) -> c_int {
    x + 1
}

/// Writes a NUL-terminated version string into `buf`.
///
/// Returns the number of bytes written (excluding the NUL), or -1 if `buf` is
/// null or too small to hold the string plus its terminator.
///
/// # Safety
/// `buf` must point to at least `len` writable bytes.
#[no_mangle]
pub unsafe extern "C" fn spl_native_version(buf: *mut u8, len: usize) -> c_int {
    const V: &str = concat!("spl-native ", env!("CARGO_PKG_VERSION"));
    let bytes = V.as_bytes();
    if buf.is_null() || len < bytes.len() + 1 {
        return -1;
    }
    std::ptr::copy_nonoverlapping(bytes.as_ptr(), buf, bytes.len());
    *buf.add(bytes.len()) = 0;
    bytes.len() as c_int
}

// ---- CSPRNG ----

/// Fills `out[..len]` with cryptographically secure random bytes.
///
/// # Safety
/// `out` must point to at least `len` writable bytes.
#[no_mangle]
pub unsafe extern "C" fn spl_random_bytes(out: *mut u8, len: usize) {
    if out.is_null() || len == 0 {
        return;
    }
    let buf = std::slice::from_raw_parts_mut(out, len);
    getrandom::getrandom(buf).expect("getrandom failed");
}

// ---- X25519 (WireGuard) keypair ----

/// Generates a fresh X25519 keypair (clamped private + public), 32 bytes each.
/// A new keypair is used per pairing so the server cannot correlate peers.
///
/// # Safety
/// `out_priv` and `out_pub` must each point to 32 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn spl_wg_keypair(out_priv: *mut u8, out_pub: *mut u8) {
    use x25519_dalek::{PublicKey, StaticSecret};
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed).expect("getrandom failed");
    let secret = StaticSecret::from(seed);
    let public = PublicKey::from(&secret);
    copy_nonoverlapping(secret.to_bytes().as_ptr(), out_priv, 32);
    copy_nonoverlapping(public.as_bytes().as_ptr(), out_pub, 32);
}

// ---- SPAKE2 (symmetric) ----
//
// Both peers run the symmetric variant with the same 6-digit password and the
// same identity, so neither needs a role. start -> exchange msgs -> finish gives
// each side the same shared key iff the passwords matched.

const SPAKE2_IDENTITY: &[u8] = b"splice-pair-v1";

/// Starts a symmetric SPAKE2 exchange with `password`, writing the outbound
/// message into `out_msg` (its length into `out_len`). Returns an opaque state
/// pointer to pass to spl_spake2_finish, or null on error (e.g. buffer too small).
///
/// # Safety
/// Pointers must be valid; `out_msg` must have `out_cap` writable bytes.
#[no_mangle]
pub unsafe extern "C" fn spl_spake2_start(password: *const u8, password_len: usize,
                                          out_msg: *mut u8, out_cap: usize,
                                          out_len: *mut usize) -> *mut c_void {
    if password.is_null() || out_msg.is_null() || out_len.is_null() {
        return null_mut();
    }
    let pw = std::slice::from_raw_parts(password, password_len);
    let (state, outbound) = Spake2::<Ed25519Group>::start_symmetric(
        &Password::new(pw), &Identity::new(SPAKE2_IDENTITY));
    if outbound.len() > out_cap {
        return null_mut();
    }
    copy_nonoverlapping(outbound.as_ptr(), out_msg, outbound.len());
    *out_len = outbound.len();
    Box::into_raw(Box::new(state)) as *mut c_void
}

/// Finishes the exchange with the peer's `in_msg`, writing the shared key into
/// `out_key` (length into `out_len`). Consumes and frees `state`. Returns 0 on
/// success; negative on error (null args, buffer too small, or a bad message).
///
/// # Safety
/// `state` must come from spl_spake2_start and not be reused after this call.
#[no_mangle]
pub unsafe extern "C" fn spl_spake2_finish(state: *mut c_void, in_msg: *const u8, in_len: usize,
                                           out_key: *mut u8, out_cap: usize,
                                           out_len: *mut usize) -> c_int {
    if state.is_null() || in_msg.is_null() || out_key.is_null() || out_len.is_null() {
        return -1;
    }
    let state = Box::from_raw(state as *mut Spake2<Ed25519Group>);
    let inbound = std::slice::from_raw_parts(in_msg, in_len);
    match state.finish(inbound) {
        Ok(key) => {
            if key.len() > out_cap {
                return -2;
            }
            copy_nonoverlapping(key.as_ptr(), out_key, key.len());
            *out_len = key.len();
            0
        }
        Err(_) => -3,
    }
}

/// Frees a SPAKE2 state without finishing (abort paths).
///
/// # Safety
/// `state` must come from spl_spake2_start and not be used afterward.
#[no_mangle]
pub unsafe extern "C" fn spl_spake2_free(state: *mut c_void) {
    if !state.is_null() {
        drop(Box::from_raw(state as *mut Spake2<Ed25519Group>));
    }
}

// ---- WireGuard (boringtun Tunn) ----
//
// The path manager owns the UDP socket; boringtun only transforms bytes and
// tells us what to do next. The result codes mirror boringtun::noise::TunnResult.

/// op: 0 = Done, 1 = WriteToNetwork, 2 = WriteToTunnelV4, 3 = WriteToTunnelV6,
/// -1 = Err. `len` is the number of bytes written into the caller's dst buffer
/// (the relevant slice always starts at dst[0]).
#[repr(C)]
pub struct WgOut {
    pub op: i32,
    pub len: usize,
}

fn classify(r: TunnResult<'_>) -> WgOut {
    match r {
        TunnResult::Done => WgOut { op: 0, len: 0 },
        TunnResult::Err(_) => WgOut { op: -1, len: 0 },
        TunnResult::WriteToNetwork(b) => WgOut { op: 1, len: b.len() },
        TunnResult::WriteToTunnelV4(b, _) => WgOut { op: 2, len: b.len() },
        TunnResult::WriteToTunnelV6(b, _) => WgOut { op: 3, len: b.len() },
    }
}

/// Creates a WireGuard tunnel for (our private key, peer's public key). `index`
/// is a local session index. Returns null on error.
///
/// # Safety
/// `static_priv` and `peer_pub` must each point to 32 readable bytes.
#[no_mangle]
pub unsafe extern "C" fn spl_wg_new(static_priv: *const u8, peer_pub: *const u8,
                                    index: u32) -> *mut c_void {
    use boringtun::x25519::{PublicKey, StaticSecret};
    let mut sp = [0u8; 32];
    let mut pp = [0u8; 32];
    copy_nonoverlapping(static_priv, sp.as_mut_ptr(), 32);
    copy_nonoverlapping(peer_pub, pp.as_mut_ptr(), 32);
    let secret = StaticSecret::from(sp);
    let public = PublicKey::from(pp);
    let tunn = Tunn::new(secret, public, None, Some(25), index, None);
    Box::into_raw(Box::new(tunn)) as *mut c_void
}

/// # Safety
/// `t` must come from spl_wg_new.
#[no_mangle]
pub unsafe extern "C" fn spl_wg_free(t: *mut c_void) {
    if !t.is_null() {
        drop(Box::from_raw(t as *mut Tunn));
    }
}

/// Encapsulates a plaintext IP packet `src` into a WireGuard datagram in `dst`.
///
/// # Safety
/// `t` must be valid; `src`/`dst` must point to the given lengths.
#[no_mangle]
pub unsafe extern "C" fn spl_wg_encapsulate(t: *mut c_void, src: *const u8, src_len: usize,
                                            dst: *mut u8, dst_cap: usize) -> WgOut {
    let tunn = &mut *(t as *mut Tunn);
    let s = std::slice::from_raw_parts(src, src_len);
    let d = std::slice::from_raw_parts_mut(dst, dst_cap);
    classify(tunn.encapsulate(s, d))
}

/// Decapsulates a WireGuard datagram. Pass dg_len == 0 to drain queued packets:
/// after a WriteToNetwork result, call again with an empty datagram until Done.
///
/// # Safety
/// `t` must be valid; `dg`/`dst` must point to the given lengths.
#[no_mangle]
pub unsafe extern "C" fn spl_wg_decapsulate(t: *mut c_void, dg: *const u8, dg_len: usize,
                                            dst: *mut u8, dst_cap: usize) -> WgOut {
    let tunn = &mut *(t as *mut Tunn);
    let s: &[u8] = if dg_len == 0 { &[] } else { std::slice::from_raw_parts(dg, dg_len) };
    let d = std::slice::from_raw_parts_mut(dst, dst_cap);
    classify(tunn.decapsulate(None, s, d))
}

/// Drives WireGuard timers (handshakes, keepalives). Call ~every 100-250ms.
///
/// # Safety
/// `t` must be valid; `dst` must point to `dst_cap` writable bytes.
#[no_mangle]
pub unsafe extern "C" fn spl_wg_tick(t: *mut c_void, dst: *mut u8, dst_cap: usize) -> WgOut {
    let tunn = &mut *(t as *mut Tunn);
    let d = std::slice::from_raw_parts_mut(dst, dst_cap);
    classify(tunn.update_timers(d))
}
