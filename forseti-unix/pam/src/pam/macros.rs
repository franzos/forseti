//! `pam_hooks!` — generates the six `extern "C" pam_sm_*` entrypoints PAM
//! dlopens, dispatching to a type implementing `PamHooks`. Copied in shape from
//! kanidm's `macros.rs`; the `extern "C"` signatures are the PAM ABI.

#[macro_export]
macro_rules! pam_hooks {
    ($ident:ident) => {
        pub use self::pam_hooks_scope::*;
        mod pam_hooks_scope {
            use std::os::raw::{c_char, c_int};

            use $crate::pam::constants::{PamFlag, PamResultCode};
            use $crate::pam::module::{PamHandle, PamHooks};

            // Null-check the handle, then run the hook behind a panic guard — a
            // panic unwinding across the C ABI is UB that could crash the host
            // process (sshd/login/sudo). Args are unused by every hook, so we pass
            // an empty Vec rather than walking the raw argv (which may be null).
            #[inline]
            fn guarded(
                pamh: *const PamHandle,
                hook: impl FnOnce(&PamHandle) -> PamResultCode,
            ) -> PamResultCode {
                if pamh.is_null() {
                    return PamResultCode::PAM_SERVICE_ERR;
                }
                let pamh: &PamHandle = unsafe { &*pamh };
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| hook(pamh)))
                    .unwrap_or(PamResultCode::PAM_AUTHINFO_UNAVAIL)
            }

            #[no_mangle]
            pub extern "C" fn pam_sm_acct_mgmt(
                pamh: *const PamHandle,
                flags: PamFlag,
                _argc: c_int,
                _argv: *const *const c_char,
            ) -> PamResultCode {
                guarded(pamh, |pamh| super::$ident::acct_mgmt(pamh, Vec::new(), flags))
            }

            #[no_mangle]
            pub extern "C" fn pam_sm_authenticate(
                pamh: *const PamHandle,
                flags: PamFlag,
                _argc: c_int,
                _argv: *const *const c_char,
            ) -> PamResultCode {
                guarded(pamh, |pamh| super::$ident::sm_authenticate(pamh, Vec::new(), flags))
            }

            #[no_mangle]
            pub extern "C" fn pam_sm_chauthtok(
                pamh: *const PamHandle,
                flags: PamFlag,
                _argc: c_int,
                _argv: *const *const c_char,
            ) -> PamResultCode {
                guarded(pamh, |pamh| super::$ident::sm_chauthtok(pamh, Vec::new(), flags))
            }

            #[no_mangle]
            pub extern "C" fn pam_sm_close_session(
                pamh: *const PamHandle,
                flags: PamFlag,
                _argc: c_int,
                _argv: *const *const c_char,
            ) -> PamResultCode {
                guarded(pamh, |pamh| super::$ident::sm_close_session(pamh, Vec::new(), flags))
            }

            #[no_mangle]
            pub extern "C" fn pam_sm_open_session(
                pamh: *const PamHandle,
                flags: PamFlag,
                _argc: c_int,
                _argv: *const *const c_char,
            ) -> PamResultCode {
                guarded(pamh, |pamh| super::$ident::sm_open_session(pamh, Vec::new(), flags))
            }

            #[no_mangle]
            pub extern "C" fn pam_sm_setcred(
                pamh: *const PamHandle,
                flags: PamFlag,
                _argc: c_int,
                _argv: *const *const c_char,
            ) -> PamResultCode {
                guarded(pamh, |pamh| super::$ident::sm_setcred(pamh, Vec::new(), flags))
            }
        }
    };
}
