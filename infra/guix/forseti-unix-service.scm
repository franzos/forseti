;;; forseti-unix-service.scm --- Guix System service for forseti-unix
;;;
;;; Part E2 of the Linux-auth plan.  Wires the forseti-unix client workspace
;;; (forseti-unixd daemon + libnss_forseti.so.2 + forseti_ssh_authorizedkeys)
;;; into a Guix System.  Modeled on the nslcd / nss-pam-ldapd service in
;;; gnu/services/authentication.scm, which is the in-tree precedent for an NSS
;;; module that is dlopened by nscd plus a backing daemon plus PAM glue.
;;;
;;; The service-type wires FIVE extensions, each via the mechanism the Guix
;;; System actually honours:
;;;
;;;   1. nscd-service-type    -- adds the forseti-unix package to nscd's
;;;                              `name-services'.  On Guix it is NSCD that
;;;                              dlopens the NSS module (nscd runs the lookups
;;;                              and has the module on its LD_LIBRARY_PATH);
;;;                              listing `forseti' in name-service-switch alone
;;;                              is NOT enough -- the module must reach nscd's
;;;                              load path, which is exactly what this does.
;;;   2. account-service-type -- the dedicated unprivileged forseti user/group
;;;                              (the daemon REFUSES to run as root).
;;;   3. activation-service-type -- create /run/forseti (forseti:forseti 0755),
;;;                              /var/cache/forseti (forseti:forseti 0700) and the
;;;                              offline-auth credentials dir (default
;;;                              /var/lib/forseti, forseti:forseti 0700) so the
;;;                              unprivileged daemon can bind its socket, open its
;;;                              cache DB, and write its 0600 offline keystore.
;;;   4. shepherd-root-service-type -- run forseti-unixd as forseti:forseti.
;;;   5. pam-root-service-type -- wire pam_forseti.so into login/sshd/gdm:
;;;                              an explicit `account' control map on all targets
;;;                              that is the SOLE arbiter for Forseti users and
;;;                              fails CLOSED on daemon-down (M4), `auth'
;;;                              device-grant on login+sshd only (R6), plus an
;;;                              `optional' pam_mkhomedir.so on `session' so a
;;;                              resolved user gets a home dir on first login.
;;;
;;; The SIXTH piece, the system-wide name-service-switch, is NOT a service
;;; extension -- it is the operating-system `name-service-switch' field.  This
;;; module exports a ready-made `%forseti-name-service-switch' the operator
;;; drops into their operating-system (see README-linux-auth.md / E3).
;;;
;;; ---------------------------------------------------------------------------
;;; E3 -- DEFERRED LAYER-5 VM SMOKE TEST (cannot run in CI / sandbox)
;;; ---------------------------------------------------------------------------
;;; End-to-end verification (getent / id / ssh landing in a pam_mkhomedir home)
;;; needs a full Guix System VM and a live Forseti server with an enrolled
;;; host.  The procedure is documented in infra/guix/README-linux-auth.md.  In
;;; brief:
;;;
;;;   (operating-system
;;;     ...
;;;     ;; REQUIRED: chain `forseti' after `files' for passwd/group.
;;;     (name-service-switch %forseti-name-service-switch)
;;;     (services
;;;      (cons*
;;;       (service forseti-unix-service-type
;;;                (forseti-unix-configuration
;;;                 (server-url "https://id.example.com")
;;;                 (host-id "host-abc")
;;;                 (host-secret "REDACTED")))
;;;       (service openssh-service-type
;;;                (openssh-configuration
;;;                 ;; HARD PRECONDITION: pam_mkhomedir runs only under PAM.
;;;                 ;; Without `use-pam? #t' sshd never invokes the session
;;;                 ;; stack and no home directory is created.
;;;                 (use-pam? #t)
;;;                 (authorized-keys-command
;;;                  (file-append forseti-unix
;;;                               "/bin/forseti_ssh_authorizedkeys"))
;;;                 (authorized-keys-command-user "forseti")))
;;;       ;; Lower nscd passwd/group positive TTL so it does not shadow the
;;;       ;; daemon's TTL with a long stale window (see %forseti-nscd-caches).
;;;       (modify-services %base-services
;;;         (nscd-service-type config =>
;;;           (nscd-configuration
;;;            (inherit config)
;;;            (caches %forseti-nscd-caches))))
;;;       ...)))
;;;
;;; Smoke steps on the booted VM:
;;;   - getent passwd <user>   resolves via forseti
;;;   - id <user>              shows forseti-supplied groups
;;;   - ssh -i key <user>@vm   key comes from AuthorizedKeysCommand; login
;;;                            lands in a pam_mkhomedir-created $HOME
;;;   - sshd -T | grep -i usepam   ==> "usepam yes"
;;;   Teardown: revoke the host / delete the identity in Forseti admin, then
;;;   `nscd -i passwd && nscd -i group' -- resolution stops.
;;; ---------------------------------------------------------------------------

(define-module (forseti-unix-service)
  ;; The real package (full crate closure) lives in panther's
  ;; (px packages authentication).  This couples the service to the panther
  ;; channel, which is acceptable: panther is the deployment channel and both
  ;; trees are loaded via -L anyway.
  #:use-module ((px packages authentication)
                #:select (forseti-unix))
  #:use-module (gnu services)
  #:use-module (gnu services base)
  #:use-module (gnu services shepherd)
  #:use-module (gnu system nss)
  #:use-module (gnu system pam)
  #:use-module (gnu system shadow)
  #:use-module (gnu packages admin) ;shadow (nologin)
  #:use-module (gnu packages linux) ;linux-pam (pam_mkhomedir.so)
  #:use-module (guix gexp)
  #:use-module (guix records)
  #:use-module (guix modules)
  #:use-module (srfi srfi-1)
  #:export (forseti-unix-configuration forseti-unix-configuration?
                                       forseti-unix-configuration-package
                                       forseti-unix-configuration-server-url
                                       forseti-unix-configuration-host-id
                                       forseti-unix-configuration-host-secret
                                       forseti-unix-configuration-socket-path
                                       forseti-unix-configuration-cache-db
                                       forseti-unix-configuration-cache-ttl
                                       forseti-unix-configuration-credentials-db
                                       forseti-unix-configuration-offline-poll-secs
                                       forseti-unix-service-type

                                       %forseti-name-service-switch
                                       %forseti-nscd-caches))

;;;
;;; Configuration record.
;;;

(define-record-type* <forseti-unix-configuration> forseti-unix-configuration
                     make-forseti-unix-configuration
  forseti-unix-configuration?
  (package
    forseti-unix-configuration-package
    (default forseti-unix))
  (server-url forseti-unix-configuration-server-url) ;string (required)
  (host-id forseti-unix-configuration-host-id) ;string (required)
  (host-secret forseti-unix-configuration-host-secret) ;string (required)
  (socket-path forseti-unix-configuration-socket-path
               (default "/run/forseti/unixd.sock"))
  (cache-db forseti-unix-configuration-cache-db
            (default "/var/cache/forseti/unixd.db"))
  (cache-ttl forseti-unix-configuration-cache-ttl
             (default 3600)) ;seconds
  ;; M3a offline-auth keystore (forseti-unixd-owned 0600).  Its parent dir is
  ;; provisioned forseti:forseti 0700 by the activation gexp; the daemon's
  ;; check_credentials_dir rejects a group/world-writable or wrong-owner parent
  ;; (mirrors check_socket_dir).  Default matches the daemon's compiled-in path.
  (credentials-db forseti-unix-configuration-credentials-db
                  (default "/var/lib/forseti/credentials.db"))
  ;; How often the daemon polls /posix/v1/offline_verifiers (and flushes the
  ;; offline-audit queue).  Daemon default is 300s; templated so a deployment (or
  ;; the VM test) can tighten the provisioning window.
  (offline-poll-secs forseti-unix-configuration-offline-poll-secs
                     (default 300)))

;;;
;;; /etc/forseti/unixd.toml -- rendered from the record.
;;;
;;; The daemon reads FORSETI_UNIXD_CONFIG, else /etc/forseti/unixd.toml.  We
;;; place the file there via etc-service-type.  host-secret is a credential, so
;;; the activation gexp tightens its mode to 0600 (the etc-service-type can't
;;; set file modes -- same caveat the nslcd service notes).
;;;

(define (forseti-unix-config-file config)
  (plain-file "unixd.toml"
              (string-append
               "# Generated by forseti-unix-service-type -- do not edit.
"
               "server_url = \""
               (forseti-unix-configuration-server-url config)
               "\"\n"
               "host_id = \""
               (forseti-unix-configuration-host-id config)
               "\"\n"
               "host_secret = \""
               (forseti-unix-configuration-host-secret config)
               "\"\n"
               "socket_path = \""
               (forseti-unix-configuration-socket-path config)
               "\"\n"
               "cache_db = \""
               (forseti-unix-configuration-cache-db config)
               "\"\n"
               "cache_ttl_secs = "
               (number->string (forseti-unix-configuration-cache-ttl config))
               "\n"
               "credentials_db = \""
               (forseti-unix-configuration-credentials-db config)
               "\"\n"
               "offline_poll_secs = "
               (number->string
                (forseti-unix-configuration-offline-poll-secs config))
               "\n")))

(define (forseti-unix-etc-service config)
  `(("forseti/unixd.toml" ,(forseti-unix-config-file config))))

;;;
;;; (1) Account: dedicated unprivileged forseti user/group.
;;; The daemon bails out if it finds itself running as root (it holds the
;;; host secret and talks to the network), so it MUST have its own account.
;;;

(define %forseti-accounts
  (list (user-group
          (name "forseti")
          (system? #t))
        (user-account
          (name "forseti")
          (group "forseti")
          (comment "forseti-unixd service account")
          (home-directory "/var/empty")
          (shell (file-append shadow "/sbin/nologin"))
          (system? #t))))

;;;
;;; (2) Activation: runtime/cache/credentials directories owned by
;;; forseti:forseti.  NOT root:root -- the unprivileged daemon must create its
;;; socket under /run/forseti, its SQLite cache under /var/cache/forseti, and its
;;; offline-auth keystore under the credentials-db parent (default
;;; /var/lib/forseti).  The daemon refuses to start if any of these parent dirs
;;; is group/world-writable or wrong-owner (check_socket_dir / check_credentials_dir),
;;; hence 0755 on /run/forseti and 0700 on the cache + credentials dirs.  The
;;; credentials dir is forseti:forseti 0700, NEVER root:root: the daemon is
;;; non-root and opens the DB 0600, so a root-owned dir would be unwritable.
;;; Pattern copied from %nslcd-activation (getpwnam + mkdir-p/perms).
;;;

(define (forseti-unix-activation config)
  (define creds-db
    (forseti-unix-configuration-credentials-db config))
  ;; The keystore's parent dir; default /var/lib/forseti for the default db
  ;; path.  dirname keeps it correct if the operator retargets credentials-db.
  (define creds-dir
    (dirname creds-db))
  (with-imported-modules (source-module-closure '((gnu build activation)))
                         #~(begin
                             (use-modules (gnu build activation))
                             (let ((user (getpwnam "forseti")))
                               (mkdir-p/perms "/run/forseti" user 493)
                               (mkdir-p/perms "/var/cache/forseti" user 448)
                               ;; Offline-auth keystore dir: forseti:forseti 0700
                               ;; (448).  check_credentials_dir rejects anything
                               ;; group/world-writable or not owned by the daemon.
                               (mkdir-p/perms #$creds-dir user 448)
                               (when (file-exists? "/etc/forseti/unixd.toml")
                                 ;; host_secret lives here -- keep it off other users.
                                 (chmod "/etc/forseti/unixd.toml" #o600)
                                 (chown "/etc/forseti/unixd.toml"
                                        (passwd:uid user)
                                        (passwd:gid user)))))))

;;;
;;; (3) Shepherd: run forseti-unixd as forseti:forseti.
;;;

(define (forseti-unix-shepherd-service config)
  (let ((package
          (forseti-unix-configuration-package config)))
    (list (shepherd-service (documentation
                             "Run forseti-unixd, the Forseti NSS/SSH daemon.")
                            (provision '(forseti-unixd))
                            ;; Needs the network to reach the Forseti server, and its runtime
                            ;; dir (created by the activation gexp at boot) to bind the socket.
                            (requirement '(networking user-processes))
                            (start #~(make-forkexec-constructor (list #$(file-append
                                                                         package
                                                                         "/sbin/forseti-unixd"))
                                      ;; Drop privileges to the dedicated account; the daemon aborts
                                      ;; if it sees uid 0.
                                      #:user "forseti"
                                      #:group "forseti"
                                      #:environment-variables (list
                                                               "FORSETI_UNIXD_CONFIG=/etc/forseti/unixd.toml")
                                      #:log-file "/var/log/forseti-unixd.log"))
                            (stop #~(make-kill-destructor))))))

;;;
;;; (4) PAM: the real M2 device-auth + account glue, plus pam_mkhomedir on the
;;; session stack.  Three stacks are touched, on two different target sets:
;;;
;;;   account + session  ->  %forseti-pam-targets (login sshd gdm gdm-password
;;;                          greetd): NSS-resolved Forseti users must clear
;;;                          account management and get a home dir wherever they
;;;                          can log in.
;;;   auth               ->  %forseti-pam-auth-targets (login + sshd ONLY; R6):
;;;                          interactive device-auth.  NOT sudo (the recovery
;;;                          tool) and NOT gdm (no tty for the poll loop).
;;;
;;; ACCOUNT (M4 -- fail closed).  M1 prepended a `sufficient' pam_succeed_if.so
;;; gated on `uid >= 1000'.  M2 used a bare `account sufficient pam_forseti.so'
;;; and leaned on the inherited `required pam_unix.so' to deny the shadow-less
;;; NSS user when the daemon was down.  That assumption is FALSE: pam_unix's
;;; acct_mgmt returns PAM_SUCCESS for a user whose passwd field is not a shadow
;;; placeholder (it never consults shadow), so a Forseti user could clear the
;;; account stack with the daemon down -- a fail-open.  Also, a bare
;;; `sufficient' never terminates on PAM_PERM_DENIED, so a daemon-DENIED user
;;; would have fallen through too.
;;;
;;; M4 makes pam_forseti the SOLE arbiter via an explicit control map:
;;;
;;;     account [success=done perm_denied=die authinfo_unavail=die default=ignore] pam_forseti.so
;;;
;;; pam_forseti's acct_mgmt returns PAM_SUCCESS for a known+allowed Forseti
;;; account (-> done), PAM_PERM_DENIED for a known+denied account (-> die),
;;; PAM_AUTHINFO_UNAVAIL when the daemon is unreachable (-> die, FAIL CLOSED),
;;; and PAM_IGNORE only when the daemon is up and the user is NOT a Forseti
;;; account (-> ignore, falls through to pam_unix so local users are unaffected).
;;; The daemon-down/local-login interaction is resolved module-side (the module
;;; self-classifies a local user before failing closed), not in this stack.
;;;
;;; AUTH (new, R5/R6).  Control string is emitted VERBATIM by Guix, so it is the
;;; full action map, NOT a bare `sufficient':
;;;
;;;     auth [success=done new_authtok_reqd=done default=ignore] pam_forseti.so
;;;
;;; `default=ignore' is the lockout-critical bit: PAM_AUTHINFO_UNAVAIL (daemon
;;; down), PAM_IGNORE (non-Forseti user / no tty) and PAM_AUTH_ERR all map to
;;; `ignore', so the auth stack simply continues to the inherited modules --
;;; pam_forseti can never wedge or hard-deny the auth phase.  `success=done'
;;; short-circuits the rest of the auth stack once device-auth approves.
;;;
;;; AFTER-ROOTOK PLACEMENT.  The entry is APPENDED to the auth list, never
;;; prepended.  For `sudo'/`su' Guix puts `auth sufficient pam_rootok.so' first
;;; (its no-auth root-recovery path); prepending pam_forseti would shadow it and
;;; could lock root out.  Those targets are out of scope here anyway, but the
;;; append discipline is kept so that if the target set ever grows to a
;;; rootok-bearing service, pam_forseti stays strictly after pam_rootok.  For
;;; sshd/login (no rootok in the base auth stack) appending also keeps
;;; pam_forseti behind the normal password/key path, so a local user
;;; authenticating normally is never delayed or intercepted.
;;;
;;; The daemon socket is /run/forseti/unixd.sock -- the pam module's compiled-in
;;; default (FORSETI_UNIXD_SOCKET), matching the service's socket-path -- so no
;;; environment needs to be threaded into the PAM stack.
;;;
;;; HARD PRECONDITION (E3): pam_mkhomedir only runs when the entry point uses
;;; PAM.  For sshd that means openssh-configuration's (use-pam? #t).
;;;

(define %forseti-pam-targets
  ;; PAM service names whose account + session stacks get the Forseti glue.
  '("login" "sshd" "gdm" "gdm-password" "greetd"))

(define %forseti-pam-auth-targets
  ;; Interactive device-auth goes on AUTH for these ONLY (R6): a real tty and
  ;; never the recovery path.  sudo/su excluded (recovery); gdm excluded (the
  ;; poll loop needs a tty; pam_forseti fast-fails no-tty to PAM_IGNORE anyway).
  '("login" "sshd"))

(define (forseti-pam-extension config)
  (define package
    (forseti-unix-configuration-package config))
  (define pam-mkhomedir
    (pam-entry (control "optional")
               (module (file-append linux-pam "/lib/security/pam_mkhomedir.so"))
               ;; Create $HOME from /etc/skel with a sane umask, quietly.
               (arguments '("skel=/etc/skel" "umask=0022" "silent"))))
  (define pam-account
    ;; M2/M4: the real account module, as the SOLE arbiter for Forseti users.
    ;; The control map is emitted verbatim by Guix:
    ;;   success=done           allowed Forseti user clears account management
    ;;   perm_denied=die        denied Forseti user is hard-denied here (a bare
    ;;                          `sufficient' would NOT terminate on deny)
    ;;   authinfo_unavail=die   daemon unreachable -> FAIL CLOSED (the inherited
    ;;                          `required pam_unix.so' does NOT reliably deny an
    ;;                          NSS-only user: pam_unix returns PAM_SUCCESS when
    ;;                          the passwd field is not a shadow placeholder)
    ;;   default=ignore         PAM_IGNORE (daemon up, NOT a Forseti user) falls
    ;;                          through to pam_unix so local users are unaffected
    ;; Requires pam_forseti to emit PAM_AUTHINFO_UNAVAIL (not PAM_IGNORE) on a
    ;; daemon-down AccountAllowed, and to self-classify local users so a local
    ;; login during an outage is not caught by authinfo_unavail=die (M4 Rust).
    (pam-entry (control
                "[success=done perm_denied=die authinfo_unavail=die default=ignore]")
               (module (file-append package "/lib/security/pam_forseti.so"))))
  (define pam-auth
    ;; M2: interactive device-auth.  Control is the verbatim action map (R5),
    ;; with default=ignore so it can never wedge or hard-deny the auth phase.
    (pam-entry (control "[success=done new_authtok_reqd=done default=ignore]")
               (module (file-append package "/lib/security/pam_forseti.so"))))
  (define (transform pam)
    (let ((name (pam-service-name pam))
          (acct/sess? (lambda (n)
                        (member n %forseti-pam-targets)))
          (auth? (lambda (n)
                   (member n %forseti-pam-auth-targets))))
      (if (or (acct/sess? name)
              (auth? name))
          (pam-service (inherit pam)
                       ;; account control-map pam_forseti.so (prepend, ahead of
                       ;; the inherited required pam_unix.so; pam_forseti is the
                       ;; sole arbiter for Forseti users and fails closed -- M4).
                       (account (if (acct/sess? name)
                                    (cons pam-account
                                          (pam-service-account pam))
                                    (pam-service-account pam)))
                       ;; APPEND after any pam_rootok; never prepend (R5).
                       (auth (if (auth? name)
                                 (append (pam-service-auth pam)
                                         (list pam-auth))
                                 (pam-service-auth pam)))
                       ;; pam_mkhomedir on session (append, optional).
                       (session (if (acct/sess? name)
                                    (append (pam-service-session pam)
                                            (list pam-mkhomedir))
                                    (pam-service-session pam)))) pam)))
  (pam-extension (transformer transform)))

(define (forseti-pam-services config)
  (list (forseti-pam-extension config)))

;;;
;;; The service-type: the five extensions.
;;;

(define forseti-unix-service-type
  (service-type (name 'forseti-unix)
                (description
                 "Run the forseti-unixd daemon and wire its NSS module into nscd so that
@code{passwd}/@code{group} lookups and sshd authorized keys resolve from a
Forseti server, plus a @code{pam_mkhomedir} session entry so resolved users
get a home directory on first login.")
                (extensions (list
                             ;; (1) THE mechanism that makes nscd dlopen the module on Guix: hand the
                             ;; forseti-unix package to nscd's name-services.  Listing `forseti' in
                             ;; name-service-switch alone does not put the .so on nscd's load path.
                             (service-extension nscd-service-type
                                                (lambda (config)
                                                  (list (forseti-unix-configuration-package
                                                         config))))
                             ;; (2) unprivileged account
                             (service-extension account-service-type
                                                (const %forseti-accounts))
                             ;; (3) /etc/forseti/unixd.toml
                             (service-extension etc-service-type
                                                forseti-unix-etc-service)
                             ;; (4) /run/forseti + /var/cache/forseti + the
                             ;; offline-auth credentials dir, all owned by
                             ;; forseti:forseti (the credentials dir 0700).
                             (service-extension activation-service-type
                                                forseti-unix-activation)
                             ;; (5) pam_mkhomedir on login/sshd/gdm session stacks
                             (service-extension pam-root-service-type
                                                forseti-pam-services)
                             ;; the daemon itself
                             (service-extension shepherd-root-service-type
                                                forseti-unix-shepherd-service)))
                (default-value #f)))
;server-url/host-id/host-secret are required

;;;
;;; name-service-switch value for the operating-system `name-service-switch'
;;; field (E2 point 2).  Inherits %mdns-host-lookup-nss for host resolution
;;; and overrides passwd/group to chain `files' then the forseti module.
;;; `files' first so local /etc/passwd accounts always win.
;;;

(define %forseti-name-service-switch
  (name-service-switch (inherit %mdns-host-lookup-nss)
                       (password (list %files
                                       (name-service (name "forseti"))))
                       (group (list %files
                                    (name-service (name "forseti"))))))

;;;
;;; nscd cache override for the operator's nscd-service-type (E2 point 1, TTL).
;;; nscd's stock passwd/group positive TTL is 600s; we drop it to 60s so nscd
;;; does not shadow forseti-unixd's own cache TTL with a long stale window.
;;; The operator splices this into their nscd-configuration's `caches' field
;;; (the nscd-service-type extend mechanism only appends name-services, it
;;; cannot override caches -- so this stays an operator-side value).
;;;

(define %forseti-nscd-caches
  (list (nscd-cache (database 'hosts)
                    (positive-time-to-live (* 3600 12))
                    (negative-time-to-live 20)
                    (persistent? #t))
        (nscd-cache (database 'services)
                    (positive-time-to-live (* 3600 24))
                    (negative-time-to-live 3600)
                    (check-files? #t)
                    (persistent? #t))
        ;; Short positive TTL: let forseti-unixd own the staleness window.
        (nscd-cache (database 'passwd)
                    (positive-time-to-live 60)
                    (negative-time-to-live 20)
                    (check-files? #t)
                    (persistent? #f))
        (nscd-cache (database 'group)
                    (positive-time-to-live 60)
                    (negative-time-to-live 20)
                    (check-files? #t)
                    (persistent? #f))))
