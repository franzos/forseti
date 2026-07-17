//! Minimal hand-vendored PAM module interface (no bindgen). Only the bits the
//! Forseti device-auth hooks need: `pam_get_item`, `pam_get_user`, the
//! `PamHandle` opaque type, and a `PamHooks` trait with `PAM_IGNORE` defaults.

use std::ffi::CStr;
use std::ptr;

use libc::c_char;

use crate::pam::constants::{PamFlag, PamResultCode, PAM_TTY};
use crate::pam::conv::PamConv;

pub use crate::pam::constants::{PamItemType, PAM_CONV};

/// Opaque PAM handle. Passed to every `pam_sm_*` entrypoint and threaded back
/// into the PAM API calls. Nomicon-style opaque FFI type: an empty enum is
/// uninhabited, so `&PamHandle` would be instant UB.
#[repr(C)]
pub struct PamHandle {
    _data: [u8; 0],
    _marker: core::marker::PhantomData<(*mut u8, core::marker::PhantomPinned)>,
}

#[repr(C)]
struct PamItemT {
    _data: [u8; 0],
    _marker: core::marker::PhantomData<(*mut u8, core::marker::PhantomPinned)>,
}

// No `#[link(name = "pam")]`: a PAM module must NOT link libpam at build time.
// PAM dlopens this .so into a process that already has libpam mapped, so these
// symbols resolve lazily from the host's loaded libpam at runtime. Linking it
// would add a NEEDED libpam.so and force a build-time -lpam (and a store
// RUNPATH), which we deliberately avoid — matching every stock pam_*.so.
extern "C" {
    fn pam_get_item(
        pamh: *const PamHandle,
        item_type: PamItemType,
        item: &mut *const PamItemT,
    ) -> PamResultCode;

    fn pam_get_user(
        pamh: *const PamHandle,
        user: &mut *const c_char,
        prompt: *const c_char,
    ) -> PamResultCode;
}

pub type PamResult<T> = Result<T, PamResultCode>;

/// Type-level mapping for `pam_get_item`: a Rust type maps to its PAM item
/// constant (e.g. `PamConv` → `PAM_CONV`).
pub trait PamItem {
    fn item_type() -> PamItemType;
}

impl PamHandle {
    /// Typed `pam_get_item` for items the client returns by pointer-to-struct
    /// (only `PamConv` here).
    fn get_item<'a, T: PamItem>(&self) -> PamResult<&'a T> {
        let mut ptr: *const PamItemT = ptr::null();
        let res = unsafe { pam_get_item(self, T::item_type(), &mut ptr) };
        if PamResultCode::PAM_SUCCESS != res {
            return Err(res);
        }
        if ptr.is_null() {
            return Err(PamResultCode::PAM_BAD_ITEM);
        }
        // SAFETY: on PAM_SUCCESS the client guarantees `ptr` points at a `T`
        // matching `T::item_type()` (the PAM item-type contract), valid for the
        // lifetime of this PAM cycle.
        let typed = unsafe { &*(ptr as *const T) };
        Ok(typed)
    }

    /// `pam_get_item` for string items (e.g. `PAM_TTY`). `Ok(None)` when the
    /// item is unset (null) — the no-tty case the auth hook fast-fails on.
    fn get_item_string(&self, item_type: PamItemType) -> PamResult<Option<String>> {
        let mut ptr: *const PamItemT = ptr::null();
        let res = unsafe { pam_get_item(self, item_type, &mut ptr) };
        if PamResultCode::PAM_SUCCESS != res {
            return Err(res);
        }
        if ptr.is_null() {
            return Ok(None);
        }
        // SAFETY: a non-null string item is a NUL-terminated C string owned by PAM.
        let s = unsafe { CStr::from_ptr(ptr as *const c_char) }
            .to_string_lossy()
            .into_owned();
        Ok(Some(s))
    }

    /// The target username (`PAM_USER`), prompting via the conversation if PAM
    /// hasn't captured it yet.
    pub fn get_user(&self) -> PamResult<String> {
        let mut ptr: *const c_char = ptr::null();
        let res = unsafe { pam_get_user(self, &mut ptr, ptr::null()) };
        if PamResultCode::PAM_SUCCESS != res {
            return Err(res);
        }
        if ptr.is_null() {
            return Err(PamResultCode::PAM_AUTHINFO_UNAVAIL);
        }
        // SAFETY: on PAM_SUCCESS with non-null ptr, PAM gives a NUL-terminated string.
        let bytes = unsafe { CStr::from_ptr(ptr) }.to_bytes();
        String::from_utf8(bytes.to_vec()).map_err(|_| PamResultCode::PAM_CONV_ERR)
    }

    /// The controlling tty (`PAM_TTY`), if any. `Ok(None)` ⇒ non-interactive
    /// caller; the auth hook returns `PAM_IGNORE` without starting a device flow.
    pub fn get_tty(&self) -> PamResult<Option<String>> {
        self.get_item_string(PAM_TTY)
    }

    /// The conversation handle, for sending prompts/info to the user.
    pub fn get_conv(&self) -> PamResult<&PamConv> {
        self.get_item::<PamConv>()
    }
}

/// Hooks invoked by the `pam_hooks!`-generated entrypoints. Every default is
/// `PAM_IGNORE` so an unimplemented hook is transparent to the PAM stack.
#[allow(unused_variables)]
pub trait PamHooks {
    fn acct_mgmt(pamh: &PamHandle, args: Vec<&CStr>, flags: PamFlag) -> PamResultCode {
        PamResultCode::PAM_IGNORE
    }

    fn sm_authenticate(pamh: &PamHandle, args: Vec<&CStr>, flags: PamFlag) -> PamResultCode {
        PamResultCode::PAM_IGNORE
    }

    fn sm_chauthtok(pamh: &PamHandle, args: Vec<&CStr>, flags: PamFlag) -> PamResultCode {
        PamResultCode::PAM_IGNORE
    }

    fn sm_close_session(pamh: &PamHandle, args: Vec<&CStr>, flags: PamFlag) -> PamResultCode {
        PamResultCode::PAM_IGNORE
    }

    fn sm_open_session(pamh: &PamHandle, args: Vec<&CStr>, flags: PamFlag) -> PamResultCode {
        PamResultCode::PAM_IGNORE
    }

    fn sm_setcred(pamh: &PamHandle, args: Vec<&CStr>, flags: PamFlag) -> PamResultCode {
        PamResultCode::PAM_IGNORE
    }
}
