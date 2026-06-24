//! PAM conversation channel. The `PamConv` struct and the `conv` callback
//! signature are the Linux-PAM ABI (see `pam_conv(3)`) — copied verbatim from
//! kanidm's `conv.rs` so the C-ABI is correct. A wrong layout here is UB inside
//! sshd, so do NOT "simplify" the pointer/`extern "C"` shapes.

use std::ffi::{CStr, CString};
use std::ptr;

use libc::{c_char, c_int};

use crate::pam::constants::{AlwaysZero, PamMessageStyle, PamResultCode};
use crate::pam::module::{PamItem, PamItemType, PamResult, PAM_CONV};

#[allow(missing_copy_implementations)]
pub enum AppDataPtr {}

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

        let ret = (self.conv)(1, &&msg, &mut resp_ptr, self.appdata_ptr);

        if PamResultCode::PAM_SUCCESS == ret {
            // resp is null for styles that don't return user input (TEXT_INFO/ERROR_MSG).
            if resp_ptr.is_null() {
                return Ok(None);
            }
            // SAFETY: on PAM_SUCCESS with a non-null resp_ptr, the client gave us
            // an array of `num_msg` (here 1) PamResponse; `.resp` is either null
            // or a NUL-terminated C string it allocated for this reply.
            let response = unsafe { (*resp_ptr).resp };
            if response.is_null() {
                Ok(None)
            } else {
                // SAFETY: `response` is a NUL-terminated C string per the contract above.
                let bytes = unsafe { CStr::from_ptr(response).to_bytes() };
                Ok(String::from_utf8(bytes.to_vec()).ok())
            }
        } else {
            Err(ret)
        }
    }
}

impl PamItem for PamConv {
    fn item_type() -> PamItemType {
        PAM_CONV
    }
}
