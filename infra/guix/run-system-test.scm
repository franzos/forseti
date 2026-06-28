;; Build + run the forseti-unix system test via the store monad.
;; Run with: guix repl -L <panther> -L <this dir> infra/guix/run-system-test.scm
;; The module exports a <system-test> (not a package); its `value' is a
;; monadic derivation, so we run-with-store to realise + build it. The
;; build SUCCEEDS only if every SRFI-64 assertion in the VM passes.
(use-modules (gnu tests)
             (forseti-unix-system-test)
             (guix)
             (guix store)
             (guix derivations))

(with-store store
  (let ((drv (run-with-store store (system-test-value %test-forseti-unix))))
    (build-derivations store (list drv))
    (format #t "SYSTEM-TEST-BUILT: ~a~%" (derivation->output-path drv))))
