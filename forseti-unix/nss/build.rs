// glibc dlopens NSS modules by versioned soname (`libnss_<svc>.so.2`). Stamp the
// built artifact's DT_SONAME so it's correct on its own; the Guix package (Part E)
// installs it under that name regardless, but a matching soname keeps the raw
// build artifact directly usable.
fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("linux") {
        println!("cargo:rustc-link-arg=-Wl,-soname,libnss_forseti.so.2");
    }
}
