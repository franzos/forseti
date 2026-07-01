(use-modules (guix packages)
             (guix search-paths)
             (gnu packages rust)
             (gnu packages commencement)
             (gnu packages databases)
             (gnu packages linux)
             (gnu packages tls)
             (gnu packages base))

(define openssl-with-dir
  (package
    (inherit openssl)
    (native-search-paths
     (cons (search-path-specification
            (variable "OPENSSL_DIR")
            (files '("."))
            (file-type 'directory)
            (separator #f))
           (package-native-search-paths openssl)))))

(define gcc-toolchain-with-cc
  (package
    (inherit gcc-toolchain)
    (native-search-paths
     (cons (search-path-specification
            (variable "CC")
            (files '("bin/gcc"))
            (file-type 'regular)
            (separator #f))
           (package-native-search-paths gcc-toolchain)))))

(packages->manifest
 (list rust
       (list rust "cargo")
       rust-analyzer
       gcc-toolchain-with-cc
       openssl-with-dir
       ;; libpam: link target for the pam_forseti.so cdylib (-lpam).
       linux-pam
       ;; libpq: link target for diesel's postgres feature (-lpq).
       postgresql))
