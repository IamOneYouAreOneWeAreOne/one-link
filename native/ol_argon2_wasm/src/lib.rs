//! One Link browser-identity Argon2id WebAssembly boundary.
//!
//! The exported ABI deliberately exposes one production profile only:
//! Argon2id v=19, 256 MiB, three passes, one lane, and a 32-byte output. This
//! prevents an attacker-controlled envelope from selecting a downgrade or an
//! unbounded allocation. JavaScript runs the module in a one-shot Worker and
//! terminates it after importing the result into a non-extractable AES key.

use argon2::{Algorithm, Argon2, Block, Params, Version};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

/// WebAssembly ABI version consumed by `argon2id-worker.js`.
pub const ABI_VERSION: u32 = 1;
/// Production memory cost in KiB (256 MiB).
pub const MEMORY_KIB: u32 = 256 * 1024;
/// Production Argon2 time cost.
pub const TIME_COST: u32 = 3;
/// Production lane count.
pub const PARALLELISM: u32 = 1;
/// AES-256 key length.
pub const OUTPUT_LEN: usize = 32;
/// Bound encoded passphrases before any KDF allocation.
pub const MAX_PASSWORD_LEN: usize = 1024;
/// Current envelope salt length.
pub const SALT_LEN: usize = 16;
const MAX_ABI_ALLOCATION: usize = 2048;

const OK: i32 = 0;
const ERR_POINTER: i32 = 1;
const ERR_LENGTH: i32 = 2;
const ERR_PROFILE: i32 = 3;
const ERR_OVERLAP: i32 = 4;
const ERR_DERIVE: i32 = 5;

fn derive_with_profile(
    password: &[u8],
    salt: &[u8],
    output: &mut [u8],
    memory_kib: u32,
    time_cost: u32,
    parallelism: u32,
) -> Result<(), argon2::Error> {
    let params = Params::new(memory_kib, time_cost, parallelism, Some(output.len()))?;
    let block_count = params.block_count();
    let context = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    // RustCrypto's convenience allocator does not zero the matrix itself.
    // Own it explicitly in a Zeroizing guard so success and every error path
    // scrub the full memory-hard work area before the Worker is terminated.
    let mut blocks = Zeroizing::new(vec![Block::default(); block_count]);
    context.hash_password_into_with_memory(password, salt, output, &mut *blocks)
}

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

/// Return the exact ABI version expected by the Worker.
#[no_mangle]
pub extern "C" fn ol_argon2id_abi_version() -> u32 {
    ABI_VERSION
}

/// Allocate a small input/output bridge buffer in module memory.
///
/// The memory-hard matrix is never allocated through this interface and the
/// strict ceiling prevents arbitrary page-driven allocations.
#[no_mangle]
pub extern "C" fn ol_argon2id_alloc(len: usize) -> *mut u8 {
    if len == 0 || len > MAX_ABI_ALLOCATION {
        return core::ptr::null_mut();
    }
    let boxed = vec![0_u8; len].into_boxed_slice();
    Box::into_raw(boxed).cast::<u8>()
}

/// Zero and release a bridge buffer allocated by [`ol_argon2id_alloc`].
///
/// # Safety
///
/// `ptr` and `len` must identify one live allocation returned by this module.
#[no_mangle]
pub unsafe extern "C" fn ol_argon2id_free(ptr: *mut u8, len: usize) {
    if ptr.is_null() || len == 0 || len > MAX_ABI_ALLOCATION {
        return;
    }
    let raw = core::ptr::slice_from_raw_parts_mut(ptr, len);
    // SAFETY: the caller contract requires the exact live allocation and len.
    let mut boxed = unsafe { Box::from_raw(raw) };
    boxed.zeroize();
}

/// Zero a live bridge buffer without releasing it.
///
/// # Safety
///
/// `ptr..ptr+len` must be a live writable module-memory range.
#[no_mangle]
pub unsafe extern "C" fn ol_argon2id_zero(ptr: *mut u8, len: usize) -> i32 {
    if ptr.is_null() || len == 0 || len > MAX_ABI_ALLOCATION {
        return ERR_POINTER;
    }
    // SAFETY: validated by the exported ABI's caller contract.
    let bytes = unsafe { core::slice::from_raw_parts_mut(ptr, len) };
    bytes.zeroize();
    OK
}

/// Derive a browser identity wrapping key using the sole production profile.
///
/// Parameters are explicit so the Worker can prove what it requested, but
/// every value is equality-checked before allocating the Argon2 matrix.
///
/// # Safety
///
/// All pointers must name disjoint live module-memory buffers of the supplied
/// lengths. The password and salt buffers are scrubbed before return.
#[no_mangle]
pub unsafe extern "C" fn ol_argon2id_derive(
    password_ptr: *mut u8,
    password_len: usize,
    salt_ptr: *mut u8,
    salt_len: usize,
    output_ptr: *mut u8,
    output_len: usize,
    memory_kib: u32,
    time_cost: u32,
    parallelism: u32,
) -> i32 {
    if password_ptr.is_null() || salt_ptr.is_null() || output_ptr.is_null() {
        return ERR_POINTER;
    }
    if password_len == 0
        || password_len > MAX_PASSWORD_LEN
        || salt_len != SALT_LEN
        || output_len != OUTPUT_LEN
    {
        return ERR_LENGTH;
    }
    if memory_kib != MEMORY_KIB || time_cost != TIME_COST || parallelism != PARALLELISM {
        return ERR_PROFILE;
    }
    if ranges_overlap(password_ptr, password_len, salt_ptr, salt_len)
        || ranges_overlap(password_ptr, password_len, output_ptr, output_len)
        || ranges_overlap(salt_ptr, salt_len, output_ptr, output_len)
    {
        return ERR_OVERLAP;
    }

    // SAFETY: null, length, and overlap checks above establish independent
    // live slices under the exported ABI contract.
    let password = unsafe { core::slice::from_raw_parts_mut(password_ptr, password_len) };
    // SAFETY: same argument as above.
    let salt = unsafe { core::slice::from_raw_parts_mut(salt_ptr, salt_len) };
    // SAFETY: same argument as above.
    let output = unsafe { core::slice::from_raw_parts_mut(output_ptr, output_len) };

    let result = derive_with_profile(password, salt, output, memory_kib, time_cost, parallelism);
    password.zeroize();
    salt.zeroize();
    if result.is_err() {
        output.zeroize();
        return ERR_DERIVE;
    }
    OK
}

/// Execute a small RFC-compatible known-answer self-test before accepting any
/// production derivation. The production profile remains enforced separately.
#[no_mangle]
pub extern "C" fn ol_argon2id_self_test() -> i32 {
    const EXPECTED: [u8; OUTPUT_LEN] = [
        0x76, 0x2b, 0xab, 0x41, 0xe2, 0x37, 0xc0, 0x12, 0xe8, 0x67, 0xb6, 0xa8, 0xee, 0x11, 0xb4,
        0x55, 0xd6, 0x22, 0xd6, 0x5a, 0x39, 0xa5, 0x6a, 0x8c, 0xf2, 0xca, 0x84, 0x29, 0x11, 0xf7,
        0x91, 0x62,
    ];
    let mut password = *b"one-link-argon2id-self-test";
    let mut salt = *b"0123456789abcdef";
    let mut output = [0_u8; OUTPUT_LEN];
    let result = derive_with_profile(&password, &salt, &mut output, 32, 3, 1);
    password.zeroize();
    salt.zeroize();
    let valid = result.is_ok() && bool::from(output.ct_eq(&EXPECTED));
    output.zeroize();
    if valid {
        OK
    } else {
        ERR_DERIVE
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn independent_known_answer_vector_matches() {
        assert_eq!(ol_argon2id_self_test(), OK);
    }

    #[test]
    fn rejects_every_profile_downgrade_before_derivation() {
        let mut password = *b"correct horse battery staple";
        let mut salt = *b"0123456789abcdef";
        let mut output = [0_u8; OUTPUT_LEN];
        // SAFETY: the three local arrays are live, writable, and disjoint.
        let result = unsafe {
            ol_argon2id_derive(
                password.as_mut_ptr(),
                password.len(),
                salt.as_mut_ptr(),
                salt.len(),
                output.as_mut_ptr(),
                output.len(),
                MEMORY_KIB - 1,
                TIME_COST,
                PARALLELISM,
            )
        };
        assert_eq!(result, ERR_PROFILE);
    }

    #[test]
    fn allocator_rejects_unbounded_requests() {
        assert!(ol_argon2id_alloc(0).is_null());
        assert!(ol_argon2id_alloc(MAX_ABI_ALLOCATION + 1).is_null());
    }
}
