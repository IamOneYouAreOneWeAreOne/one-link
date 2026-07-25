//! One Link browser Ed25519 WebAssembly fallback.
//!
//! Browsers that do not expose Ed25519 through Web Crypto still need the same
//! identity and signed-wire semantics as the desktop daemon. This small,
//! integrity-pinned module provides only public-key derivation, deterministic
//! Ed25519 signing, and strict verification. JavaScript owns randomness and
//! supplies a 32-byte seed; no RNG or ambient host import exists in this ABI.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use zeroize::{Zeroize, Zeroizing};

/// ABI version consumed by `peer.html`.
pub const ABI_VERSION: u32 = 1;
/// Ed25519 private seed length.
pub const SEED_LEN: usize = 32;
/// Ed25519 public key length.
pub const PUBLIC_KEY_LEN: usize = 32;
/// Ed25519 signature length.
pub const SIGNATURE_LEN: usize = 64;
/// Maximum signed or verified message accepted at this boundary.
pub const MAX_MESSAGE_LEN: usize = 1024 * 1024;
const MAX_ABI_ALLOCATION: usize = MAX_MESSAGE_LEN;

const OK: i32 = 0;
const ERR_POINTER: i32 = 1;
const ERR_LENGTH: i32 = 2;
const ERR_OVERLAP: i32 = 3;
const ERR_PUBLIC_KEY: i32 = 4;
const ERR_SIGNATURE: i32 = 5;

fn ranges_overlap(left: *const u8, left_len: usize, right: *const u8, right_len: usize) -> bool {
    let left_start = left as usize;
    let right_start = right as usize;
    let Some(left_end) = left_start.checked_add(left_len) else {
        return true;
    };
    let Some(right_end) = right_start.checked_add(right_len) else {
        return true;
    };
    left_start < right_end && right_start < left_end
}

/// Return the exact ABI version expected by the browser loader.
#[no_mangle]
pub extern "C" fn ol_ed25519_abi_version() -> u32 {
    ABI_VERSION
}

/// Allocate one bounded bridge buffer in module memory.
#[no_mangle]
pub extern "C" fn ol_ed25519_alloc(len: usize) -> *mut u8 {
    if len == 0 || len > MAX_ABI_ALLOCATION {
        return core::ptr::null_mut();
    }
    let buffer = vec![0_u8; len].into_boxed_slice();
    Box::into_raw(buffer).cast::<u8>()
}

/// Zero and release a buffer previously returned by [`ol_ed25519_alloc`].
///
/// # Safety
///
/// `ptr` and `len` must be the exact live allocation returned by the allocator
/// and must be released exactly once.
#[no_mangle]
pub unsafe extern "C" fn ol_ed25519_zero_and_free(ptr: *mut u8, len: usize) -> i32 {
    if ptr.is_null() || len == 0 || len > MAX_ABI_ALLOCATION {
        return ERR_POINTER;
    }
    // SAFETY: upheld by the caller contract above; the slice is reconstructed
    // with the exact original length before converting back to its boxed form.
    let raw_slice = core::ptr::slice_from_raw_parts_mut(ptr, len);
    // SAFETY: `raw_slice` came from `Box::into_raw` in `ol_ed25519_alloc`.
    let mut buffer = unsafe { Box::from_raw(raw_slice) };
    buffer.zeroize();
    drop(buffer);
    OK
}

/// Derive an Ed25519 public key from one 32-byte private seed.
///
/// # Safety
///
/// Every pointer must reference the declared number of live bytes. Input and
/// output ranges must be disjoint.
#[no_mangle]
pub unsafe extern "C" fn ol_ed25519_public_from_seed(
    seed_ptr: *const u8,
    seed_len: usize,
    public_ptr: *mut u8,
    public_len: usize,
) -> i32 {
    if seed_ptr.is_null() || public_ptr.is_null() {
        return ERR_POINTER;
    }
    if seed_len != SEED_LEN || public_len != PUBLIC_KEY_LEN {
        return ERR_LENGTH;
    }
    if ranges_overlap(seed_ptr, seed_len, public_ptr, public_len) {
        return ERR_OVERLAP;
    }
    // SAFETY: pointer validity and exact lengths are the function contract.
    let seed_slice = unsafe { core::slice::from_raw_parts(seed_ptr, SEED_LEN) };
    let mut seed = Zeroizing::new([0_u8; SEED_LEN]);
    seed.copy_from_slice(seed_slice);
    let signing_key = SigningKey::from_bytes(&seed);
    let public = signing_key.verifying_key().to_bytes();
    // SAFETY: `public_ptr` names a live 32-byte output range by contract.
    unsafe { core::ptr::copy_nonoverlapping(public.as_ptr(), public_ptr, PUBLIC_KEY_LEN) };
    OK
}

/// Validate that 32 bytes encode a usable Ed25519 verifying key.
///
/// # Safety
///
/// `public_ptr` must reference exactly `public_len` live bytes.
#[no_mangle]
pub unsafe extern "C" fn ol_ed25519_validate_public(
    public_ptr: *const u8,
    public_len: usize,
) -> i32 {
    if public_ptr.is_null() {
        return ERR_POINTER;
    }
    if public_len != PUBLIC_KEY_LEN {
        return ERR_LENGTH;
    }
    // SAFETY: pointer validity and exact length are the function contract.
    let public_slice = unsafe { core::slice::from_raw_parts(public_ptr, PUBLIC_KEY_LEN) };
    let Ok(public_bytes) = <[u8; PUBLIC_KEY_LEN]>::try_from(public_slice) else {
        return ERR_LENGTH;
    };
    if VerifyingKey::from_bytes(&public_bytes).is_ok_and(|key| !key.is_weak()) {
        OK
    } else {
        ERR_PUBLIC_KEY
    }
}

/// Sign one bounded message with a 32-byte Ed25519 seed.
///
/// # Safety
///
/// Every pointer must reference the declared number of live bytes. All three
/// ranges must be disjoint.
#[no_mangle]
pub unsafe extern "C" fn ol_ed25519_sign(
    seed_ptr: *const u8,
    seed_len: usize,
    message_ptr: *const u8,
    message_len: usize,
    signature_ptr: *mut u8,
    signature_len: usize,
) -> i32 {
    if seed_ptr.is_null() || message_ptr.is_null() || signature_ptr.is_null() {
        return ERR_POINTER;
    }
    if seed_len != SEED_LEN || signature_len != SIGNATURE_LEN || message_len > MAX_MESSAGE_LEN {
        return ERR_LENGTH;
    }
    if ranges_overlap(seed_ptr, seed_len, message_ptr, message_len)
        || ranges_overlap(seed_ptr, seed_len, signature_ptr, signature_len)
        || ranges_overlap(message_ptr, message_len, signature_ptr, signature_len)
    {
        return ERR_OVERLAP;
    }
    // SAFETY: pointer validity and lengths are the function contract.
    let seed_slice = unsafe { core::slice::from_raw_parts(seed_ptr, SEED_LEN) };
    // SAFETY: a zero-length message still carries a live non-null allocation.
    let message = unsafe { core::slice::from_raw_parts(message_ptr, message_len) };
    let mut seed = Zeroizing::new([0_u8; SEED_LEN]);
    seed.copy_from_slice(seed_slice);
    let signature = SigningKey::from_bytes(&seed).sign(message).to_bytes();
    // SAFETY: `signature_ptr` names a live 64-byte output range by contract.
    unsafe {
        core::ptr::copy_nonoverlapping(signature.as_ptr(), signature_ptr, SIGNATURE_LEN);
    }
    OK
}

/// Strictly verify one bounded Ed25519 signature.
///
/// Returns zero only for a valid signature. Malformed points, non-canonical
/// scalars, and weak-key edge cases are rejected by `verify_strict`.
///
/// # Safety
///
/// Every pointer must reference the declared number of live bytes.
#[no_mangle]
pub unsafe extern "C" fn ol_ed25519_verify(
    public_ptr: *const u8,
    public_len: usize,
    message_ptr: *const u8,
    message_len: usize,
    signature_ptr: *const u8,
    signature_len: usize,
) -> i32 {
    if public_ptr.is_null() || message_ptr.is_null() || signature_ptr.is_null() {
        return ERR_POINTER;
    }
    if public_len != PUBLIC_KEY_LEN
        || signature_len != SIGNATURE_LEN
        || message_len > MAX_MESSAGE_LEN
    {
        return ERR_LENGTH;
    }
    // SAFETY: pointer validity and exact lengths are the function contract.
    let public_slice = unsafe { core::slice::from_raw_parts(public_ptr, PUBLIC_KEY_LEN) };
    // SAFETY: pointer validity and bounded message length are the contract.
    let message = unsafe { core::slice::from_raw_parts(message_ptr, message_len) };
    // SAFETY: pointer validity and exact lengths are the function contract.
    let signature_slice = unsafe { core::slice::from_raw_parts(signature_ptr, SIGNATURE_LEN) };
    let Ok(public_bytes) = <[u8; PUBLIC_KEY_LEN]>::try_from(public_slice) else {
        return ERR_LENGTH;
    };
    let Ok(verifying_key) = VerifyingKey::from_bytes(&public_bytes) else {
        return ERR_PUBLIC_KEY;
    };
    let signature = Signature::from_bytes(
        <&[u8; SIGNATURE_LEN]>::try_from(signature_slice).expect("length checked"),
    );
    if verifying_key.verify_strict(message, &signature).is_ok() {
        OK
    } else {
        ERR_SIGNATURE
    }
}

/// Execute RFC 8032 test vector 1 entirely inside the module.
#[no_mangle]
pub extern "C" fn ol_ed25519_self_test() -> i32 {
    let mut seed = Zeroizing::new([
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c,
        0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae,
        0x7f, 0x60,
    ]);
    let expected_public = [
        0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07,
        0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07,
        0x51, 0x1a,
    ];
    let expected_signature = [
        0xe5, 0x56, 0x43, 0x00, 0xc3, 0x60, 0xac, 0x72, 0x90, 0x86, 0xe2, 0xcc, 0x80, 0x6e, 0x82,
        0x8a, 0x84, 0x87, 0x7f, 0x1e, 0xb8, 0xe5, 0xd9, 0x74, 0xd8, 0x73, 0xe0, 0x65, 0x22, 0x49,
        0x01, 0x55, 0x5f, 0xb8, 0x82, 0x15, 0x90, 0xa3, 0x3b, 0xac, 0xc6, 0x1e, 0x39, 0x70, 0x1c,
        0xf9, 0xb4, 0x6b, 0xd2, 0x5b, 0xf5, 0xf0, 0x59, 0x5b, 0xbe, 0x24, 0x65, 0x51, 0x41, 0x43,
        0x8e, 0x7a, 0x10, 0x0b,
    ];
    let signing_key = SigningKey::from_bytes(&seed);
    let signature = signing_key.sign(&[]);
    let valid = signing_key.verifying_key().to_bytes() == expected_public
        && signature.to_bytes() == expected_signature
        && signing_key
            .verifying_key()
            .verify_strict(&[], &signature)
            .is_ok();
    seed.zeroize();
    if valid {
        OK
    } else {
        ERR_SIGNATURE
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc_8032_known_answer_vector_matches() {
        assert_eq!(ol_ed25519_self_test(), OK);
    }

    #[test]
    fn sign_verify_and_tamper_are_strict() {
        let mut seed = [7_u8; SEED_LEN];
        let message = b"one-link-ed25519-wasm-boundary";
        let mut public = [0_u8; PUBLIC_KEY_LEN];
        let mut signature = [0_u8; SIGNATURE_LEN];
        // SAFETY: local input/output arrays are live and disjoint.
        assert_eq!(
            unsafe {
                ol_ed25519_public_from_seed(
                    seed.as_ptr(),
                    seed.len(),
                    public.as_mut_ptr(),
                    public.len(),
                )
            },
            OK
        );
        // SAFETY: local input/output arrays are live and disjoint.
        assert_eq!(
            unsafe {
                ol_ed25519_sign(
                    seed.as_ptr(),
                    seed.len(),
                    message.as_ptr(),
                    message.len(),
                    signature.as_mut_ptr(),
                    signature.len(),
                )
            },
            OK
        );
        // SAFETY: local input arrays are live for their declared lengths.
        assert_eq!(
            unsafe {
                ol_ed25519_verify(
                    public.as_ptr(),
                    public.len(),
                    message.as_ptr(),
                    message.len(),
                    signature.as_ptr(),
                    signature.len(),
                )
            },
            OK
        );
        signature[0] ^= 1;
        // SAFETY: local input arrays are live for their declared lengths.
        assert_eq!(
            unsafe {
                ol_ed25519_verify(
                    public.as_ptr(),
                    public.len(),
                    message.as_ptr(),
                    message.len(),
                    signature.as_ptr(),
                    signature.len(),
                )
            },
            ERR_SIGNATURE
        );
        seed.zeroize();
    }

    #[test]
    fn allocator_and_lengths_are_bounded() {
        assert!(ol_ed25519_alloc(0).is_null());
        assert!(ol_ed25519_alloc(MAX_ABI_ALLOCATION + 1).is_null());
        let seed = [0_u8; SEED_LEN];
        let mut public = [0_u8; PUBLIC_KEY_LEN];
        // SAFETY: both arrays are live and disjoint; the deliberately wrong
        // length must be rejected before cryptographic processing.
        assert_eq!(
            unsafe {
                ol_ed25519_public_from_seed(
                    seed.as_ptr(),
                    SEED_LEN - 1,
                    public.as_mut_ptr(),
                    public.len(),
                )
            },
            ERR_LENGTH
        );
        // SAFETY: the public array is live for its declared length.
        assert_eq!(
            unsafe { ol_ed25519_validate_public(public.as_ptr(), PUBLIC_KEY_LEN - 1) },
            ERR_LENGTH
        );
    }
}
