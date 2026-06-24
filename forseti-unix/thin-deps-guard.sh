#!/bin/sh
# Thin-`.so` dependency-graph guard (M1 E1 Step 2, extended for M2 Part D).
#
# `ldd`/`objdump` can NOT catch a stray heavy dep — Rust statically links it, so
# only libc/libgcc_s/libm/ld show as DT_NEEDED. We enforce thinness at the
# crate-graph level instead: each shim that libc/PAM dlopens into setuid
# sshd/sudo/login must carry NO async runtime, HTTP client, DB, TLS or bindgen.
#
# Run from the forseti-unix workspace root (wrap in `guix shell -m manifest.scm`
# off Guix-with-cargo). Exits non-zero on the first banned dep in any shim.
set -eu

# Crates dlopened into host processes — must stay thin.
SHIMS="libnss_forseti forseti-ssh-authorizedkeys pam_forseti"

# Substrings that must never appear in a shim's normal dep graph.
BANNED="tokio reqwest rusqlite hyper rustls openssl-sys ring bindgen pam-sys pamsm jsonwebtoken"

fail=0
for crate in $SHIMS; do
    tree=$(cargo tree -p "$crate" -e normal)
    for dep in $BANNED; do
        if printf '%s\n' "$tree" | grep -q "[ |─]$dep v"; then
            echo "THIN-GUARD FAIL: '$crate' pulls in banned dep '$dep'" >&2
            fail=1
        fi
    done
done

if [ "$fail" -ne 0 ]; then
    echo "Thin-deps guard failed: a host-loaded shim gained a heavy dependency." >&2
    exit 1
fi
echo "thin-deps guard OK: $SHIMS carry no banned deps"
