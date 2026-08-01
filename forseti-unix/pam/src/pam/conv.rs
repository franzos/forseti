//! PAM conversation channel. The `PamConv` struct and the `conv` callback
//! signature are the Linux-PAM ABI (see `pam_conv(3)`) — the pointer layouts are
//! kanidm's `conv.rs` so the C-ABI is correct. A wrong layout here is UB inside
//! sshd, so do NOT "simplify" the pointer/`extern "C"` shapes. The response
//! zeroize + free in `send` is ours; kanidm's version leaks both allocations.

use std::ffi::{CStr, CString};
use std::ptr;

use libc::{c_char, c_int, c_void};

use crate::pam::constants::{AlwaysZero, PamMessageStyle, PamResultCode};
use crate::pam::module::{PAM_CONV, PamItem, PamItemType, PamResult};

// Opaque FFI type (see `PamHandle` in module.rs), only ever handled by pointer.
#[repr(C)]
pub struct AppDataPtr {
    _data: [u8; 0],
    _marker: core::marker::PhantomData<(*mut u8, core::marker::PhantomPinned)>,
}

#[repr(C)]
struct PamMessage {
    msg_style: PamMessageStyle,
    msg: *const c_char,
}

#[repr(C)]
struct PamResponse {
    resp: *const c_char,
    resp_retcode: AlwaysZero,
}

/// Number of messages `send` passes per conversation call, and therefore the
/// number of `PamResponse` entries the client allocates for us to free.
const NUM_MSG: c_int = 1;

/// Overwrite a C string's bytes (up to its NUL) so a reply holding a passphrase
/// doesn't linger in freed heap memory.
///
/// # Safety
/// `s` must be a valid, writable, NUL-terminated C string we own.
unsafe fn zeroize_cstr(s: *const c_char) {
    unsafe {
        let len = CStr::from_ptr(s).to_bytes().len();
        let s = s.cast_mut();
        for i in 0..len {
            ptr::write_volatile(s.add(i), 0);
        }
    }
}

/// `PamConv` acts as a channel for communicating with the user. Messages sent
/// are relayed to the user by the PAM client (sshd/login); responses come back.
#[repr(C)]
pub struct PamConv {
    conv: extern "C" fn(
        num_msg: c_int,
        pam_message: &&PamMessage,
        pam_response: &mut *const PamResponse,
        appdata_ptr: *const AppDataPtr,
    ) -> PamResultCode,
    appdata_ptr: *const AppDataPtr,
}

impl PamConv {
    /// Send a single message to the PAM client. For prompt styles the user's
    /// reply is returned (`Some`); info/error styles return `None`. A failed
    /// conversation yields the client's `PamResultCode` as `Err`.
    pub fn send(&self, style: PamMessageStyle, msg: &str) -> PamResult<Option<String>> {
        let mut resp_ptr: *const PamResponse = ptr::null();
        let msg_cstr = CString::new(msg).map_err(|_| PamResultCode::PAM_CONV_ERR)?;
        let msg = PamMessage {
            msg_style: style,
            msg: msg_cstr.as_ptr(),
        };

        let ret = (self.conv)(NUM_MSG, &&msg, &mut resp_ptr, self.appdata_ptr);

        // On failure the client allocated nothing we may free (pam_conv(3)).
        if PamResultCode::PAM_SUCCESS != ret {
            return Err(ret);
        }
        // resp is null for styles that don't return user input (TEXT_INFO/ERROR_MSG).
        if resp_ptr.is_null() {
            return Ok(None);
        }

        // SAFETY: on PAM_SUCCESS with a non-null resp_ptr the client gave us an
        // array of `NUM_MSG` PamResponse; `.resp` is either null or a
        // NUL-terminated C string. Both were malloc(3)'d by libpam and ownership
        // passes to the module, so we free them here exactly once.
        let reply = unsafe {
            let first = (*resp_ptr).resp;
            let reply = if first.is_null() {
                None
            } else {
                String::from_utf8(CStr::from_ptr(first).to_bytes().to_vec()).ok()
            };

            for i in 0..NUM_MSG as usize {
                let resp = (*resp_ptr.add(i)).resp;
                if !resp.is_null() {
                    zeroize_cstr(resp);
                    libc::free(resp.cast_mut().cast::<c_void>());
                }
            }
            libc::free(resp_ptr.cast_mut().cast::<c_void>());

            reply
        };

        Ok(reply)
    }
}

impl PamItem for PamConv {
    fn item_type() -> PamItemType {
        PAM_CONV
    }
}
