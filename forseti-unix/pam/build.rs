// PAM dlopens modules by plain filename (`pam_forseti.so`). Stamp DT_SONAME so
// the raw build artifact carries the right name; the Guix package (Part E)
// installs it under that name regardless, but a matching soname keeps the build
// artifact directly usable. Mirrors the NSS module's build.rs.
fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("linux") {
        println!("cargo:rustc-link-arg=-Wl,-soname,pam_forseti.so");
    }
}
