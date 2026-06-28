;;; forseti-unix-system-test.scm --- Marionette VM test for the forseti-unix client chain
;;;
;;; End-to-end Guix System VM test (E3 of the Linux-auth plan) that boots a
;;; real headless Guix System in QEMU and drives the forseti-unix client chain
;;; against a SELF-CONTAINED in-guest mock resolver -- no live Forseti/Ory
;;; server, no network egress.  Modeled on gnu/tests/ldap.scm (NSS/PAM against
;;; a directory) and gnu/tests/ssh.scm (baked keypair + ssh-in-guest).
;;;
;;; What it asserts in-guest (SRFI-64 via marionette-eval):
;;;   1. getent passwd fuser  -> resolves the mock-provisioned POSIX account
;;;                              (NSS module dlopened by nscd, name-service-switch
;;;                              routing passwd/group to `forseti').
;;;   2. id fuser             -> works (uid 60001 / gid 60002).
;;;   3. ssh fuser@localhost  -> key-based login via sshd AuthorizedKeysCommand,
;;;                              landing in a pam_mkhomedir-created $HOME; the
;;;                              account hook is now pam_forseti.so.
;;;   4. rendered PAM stack   -> /etc/pam.d/sshd carries the pam_forseti AUTH
;;;                              line with the exact verbatim control string and
;;;                              after any pam_rootok (R5).
;;;   5. interactive device-auth -> keyboard-interactive ssh drives pam_forseti's
;;;                              device conversation; the mock approves after N
;;;                              polls; login succeeds and the device user_code
;;;                              surfaces in the transcript (the flush bug).
;;;   6. pending-forever      -> a never-approving code times out cleanly within
;;;                              the cap (PAM_AUTH_ERR), never a hang.
;;;   7. fail-open AUTH       -> stop forseti-unixd; getent passwd root still
;;;                              resolves AND interactive auth returns promptly
;;;                              (the auth stack's `default=ignore' fast-fails
;;;                              pam_forseti to the next module rather than
;;;                              hanging).
;;;   8. fail-CLOSED ACCOUNT (M4) -> with forseti-unixd stopped, the account
;;;                              stack denies an NSS-only Forseti user but lets a
;;;                              local (shadow-backed) account through.
;;;   9. OFFLINE AUTH (M3a)    -> the daemon polls + caches a REAL Argon2id
;;;                              verifier from /posix/v1/offline_verifiers; then
;;;                              the mock is STOPPED (server unreachable) with
;;;                              forseti-unixd still UP, and:
;;;                                (a) the known offline passphrase verifies
;;;                                    (OfflineSuccess) against the real
;;;                                    provisioned verifier in the 0600 keystore;
;;;                                (b) a wrong passphrase is OfflineDenied;
;;;                                (c) a force_mfa host (empty verifier set) drops
;;;                                    the cred -> OfflineDenied{no_cred} and
;;;                                    AuthBegin does NOT offer OfflineAvailable;
;;;                                (e) a local/root account is unaffected;
;;;                                (d) with forseti-unixd FULLY down, the account
;;;                                    phase fails closed and offline is NEVER
;;;                                    attempted (the M4 None-branch invariant).
;;;
;;; The (a)/(b)/(c) auth-decision assertions drive the daemon's PamRequest socket
;;; directly (root peer) rather than ssh, isolating exactly the M3a offline
;;; auth+verify decision.  This is deliberate: an NSS-only user can NEVER complete
;;; the keyboard-interactive auth phase over the rendered sshd stack because it
;;; runs `auth required pam_unix.so' BEFORE pam_forseti, and a prior required
;;; failure (no /etc/shadow) cannot be overridden by a later success=done.  That
;;; same structural limit fails the pre-existing interactive device-auth assertion;
;;; it is a PAM-stack/harness property, NOT an offline-auth bug.  pamtester is no
;;; escape: pam_forseti's sm_authenticate fast-fails to PAM_IGNORE without a
;;; PAM_TTY (R8), which pamtester does not set.  A best-effort real ssh attempt is
;;; logged (not asserted) alongside each, so the limit stays visible without
;;; masking the deterministic proof.
;;;
;;; M4 WATCH ITEM: the account stack is now an explicit control map --
;;;   account [success=done perm_denied=die authinfo_unavail=die default=ignore]
;;;           pam_forseti.so
;;; pam_forseti is the SOLE arbiter for Forseti users.  Daemon UP + known/allowed
;;; user -> PAM_SUCCESS (success=done), clearing account management ahead of the
;;; inherited `required pam_unix.so' (the NSS-only user has no /etc/shadow entry).
;;; Daemon DOWN, the module self-classifies the caller: a user WITH a real
;;; /etc/shadow hash -> PAM_IGNORE (default=ignore, inherited pam_unix handles
;;; them, so local/root logins survive an outage); a user with NO shadow entry
;;; (NSS-only Forseti user) -> PAM_AUTHINFO_UNAVAIL -> `authinfo_unavail=die' ->
;;; login DENIED (fail closed).  If the key-based ssh assertion fails with a PAM
;;; account error, that is a real finding in the account hook, surfaced, not
;;; papered over.
;;;
;;; Run it (from a checkout of both panther and this dir):
;;;
;;;   guix build -L /home/franz/git/panther \
;;;              -L /home/franz/git/forseti/infra/guix \
;;;              forseti-unix-system-test
;;;
;;; That builds the VM image, runs QEMU (KVM if /dev/kvm is present, else TCG),
;;; and produces the SRFI-64 test log as the derivation output.

(define-module (forseti-unix-system-test)
  ;; The REAL package with its full crate closure lives in panther's
  ;; (px packages authentication).  The old E1 stub in forseti-unix.scm (next to
  ;; the service module) has been retired -- it had #:cargo-inputs '() and could
  ;; not build offline.  Both this test and the service-type default to
  ;; panther's package.
  #:use-module ((px packages authentication)
                #:select (forseti-unix))
  #:use-module (forseti-unix-service) ;the service module (this dir)
  #:use-module (gnu tests)
  #:use-module (gnu system)
  #:use-module (gnu system shadow) ;user-account for the M4 local control user
  #:use-module (gnu system nss)
  #:use-module (gnu system vm)
  #:use-module (gnu services)
  #:use-module (gnu services base)
  #:use-module (gnu services shepherd)
  #:use-module (gnu services ssh)
  #:use-module (gnu services networking)
  #:use-module (gnu packages base) ;coreutils
  #:use-module (gnu packages ssh) ;openssh (ssh client)
  #:use-module (gnu packages authentication) ;pamtester (M4 account-phase probe)
  #:use-module (gnu packages guile) ;guile-3.0 for the mock server
  #:use-module (guix gexp)
  #:use-module (guix store)
  #:export (%forseti-mock-port %test-forseti-unix forseti-unix-system-test))

;;;
;;; Test fixtures: a fixed SSH keypair (model: gnu/tests/ssh.scm bakes one) and
;;; the mock resolver's port + host credentials.  The keypair is generated at
;;; derivation-build time into the store, the pubkey baked into the mock's
;;; authorized_keys response and the privkey written into the guest for root to
;;; `ssh alice@localhost'.
;;;

(define %forseti-mock-port
  8443)
(define %forseti-host-id
  "test-host")
(define %forseti-host-secret
  "test-secret")

;; Device-auth fixtures (M2 Part E).  The mock's device/init mints a distinct
;; device_code per username; device/poll returns `pending' for the first
;; %device-pending-polls calls of an APPROVING code, then `approved' (R-H3:
;; pending-then-approved exercises the real daemon poll loop + the SSH
;; text-flush; never auto-approve on the first poll).  A second, NON-approving
;; username yields a code that stays pending forever -- but with a short
;; `expires_in', so the daemon session hits hard expiry and PAM fails CLEANLY
;; (PAM_AUTH_ERR) within the cap instead of hanging.
;; The approving device user (== %forseti-user).
(define %device-user "fuser")
;; Mints a code that stays pending forever (clean-timeout case).
(define %device-pending-user "ghostuser")
;; Polls returned `pending' before `approved' (never approve on the first poll,
;; preserving R-H3: this drives the real pending->approved daemon poll loop).
(define %device-pending-polls 2)
;; The code that MUST surface in the ssh transcript (the flush assertion).
(define %device-user-code "WDJB-MJHT")
;; Short hard expiry so the pending-forever daemon session caps quickly.
(define %device-pending-expires 12)

;; Offline-auth fixtures (M3a).  The mock's /posix/v1/offline_verifiers ships a
;; REAL Argon2id PHC verifier (minted offline with the daemon's exact params:
;; Argon2id, m=65536,t=3,p=1, v=0x13) for %offline-pass.  The daemon re-peppers
;; it with its host pepper and caches it; once the mock is stopped (server
;; UNREACHABLE) the daemon verifies the typed passphrase locally.  A flag file in
;; the guest (%offline-empty-flag) flips the endpoint to an EMPTY set, modelling a
;; force_mfa host that ships ZERO offline verifiers.
(define %offline-pass "offline-pass-1234")
(define %offline-wrong-pass "totally-wrong-passphrase")
(define %offline-verifier-phc
  "$argon2id$v=19$m=65536,t=3,p=1$rhqrruBPyjF4WkYIBlhhDw$gOnI/HQX5K8Qd9cxdS9tLLm/Pa4OFiXodk/DKrPQ2cw")
(define %offline-ttl-secs 3600)
;; When this file exists in the guest, the mock returns an EMPTY verifier set
;; (force_mfa case).  Per-request stat → no mock restart needed to flip it.
(define %offline-empty-flag "/run/forseti-mock-empty-verifiers")
;; Tight provisioning poll so the daemon caches (and, in the empty case, drops)
;; the verifier within a couple of seconds instead of the 300s default.
(define %offline-poll-secs 3)
;; IMPORTANT: do NOT call this `alice'.  gnu/tests.scm `%simple-os' bakes a
;; LOCAL `alice' (uid 1000, "Bob's sister") into /etc/passwd, and
;; %forseti-name-service-switch lists `files' BEFORE `forseti' -- so a local
;; alice would shadow the Forseti-resolved one and the test would silently
;; exercise the local account instead of the NSS path.  Use a name with no
;; local account so resolution can only come from forseti.
(define %forseti-user
  "fuser")
(define %forseti-uid
  60001)
(define %forseti-gid
  60002)

;; Org/team scope fixtures (B1).  The real resolver scopes EVERY /posix/v1/*
;; answer by the calling host's org/team (resolver.rs): a whole-org host sees
;; all the org's provisioned members; a team-scoped host sees only the scoped
;; team's members; a foreign org's accounts/gids are never visible.  The mock
;; models ONE host (the daemon's test-host), so we encode that per-host scoping
;; as a single-process FLAG-FILE toggle (the %offline-empty-flag precedent):
;; flag ABSENT => whole-org, flag PRESENT => team-scoped to `engineering'.  The
;; accounts are chosen so NO (name, lookup-kind) pair flips verdict across modes
;; -- that keeps the daemon/nscd caches honest without a daemon restart:
;;   fuser  -- org member AND in `engineering' (stable 200 in both modes);
;;   dave   -- org member, NOT in the team: 404 on a team-scoped getpwnam
;;             (the team-scoped negative; NEVER looked up in whole-org mode);
;;   erin   -- org member, NOT in any team: 200 on a whole-org getpwnam
;;             (the whole-org positive; NEVER looked up in team-scoped mode);
;;   carol  -- a DIFFERENT org's member: never visible on this host (cross-org).
;; dave and erin are DISJOINT identities precisely so that no (name, lookup-kind)
;; pair is ever queried in BOTH scope modes.  NSS does not support passwd
;; enumeration (libnss_forseti has no setpwent/getpwent), so whole-org scope can
;; only be proven by-name; reusing one name across modes would let the negative
;; entry cached in the team-scoped phase poison the whole-org verdict (the
;; daemon holds its OWN negative cache that outlives an nscd flush).  Disjoint
;; names -- not flushing -- is what keeps the two phases honest.
(define %org-member-user "dave") ;orgA member, not in the engineering team
(define %org-member-uid 60010)
(define %org-member-gid 60011) ;dave's UPG gid
(define %org-member2-user "erin") ;orgA member, not in ANY team; whole-org by-name proof
(define %org-member2-uid 60030)
(define %org-member2-gid 60031) ;erin's UPG gid
(define %cross-org-user "carol") ;orgB member; never visible on this host
(define %cross-org-uid 60020)
(define %cross-org-gid 60021)
(define %team-name "engineering") ;the scoped team; gid in the team band
(define %team-gid 65000)
(define %foreign-team-gid 66000) ;a gid that exists only in orgB
(define %org-slug "acme") ;the org has NO enumerable group of its own
;; Present => the mock answers as a team-scoped host; absent => whole-org.
(define %team-scoped-flag "/run/forseti-mock-team-scoped")

;; A LOCAL account with a real /etc/shadow hash (M4 fail-closed control case).
;; The daemon-down account check must let this user clear PAM account management
;; (the module self-classifies a shadow-backed user -> PAM_IGNORE -> the
;; inherited pam_unix handles them), whereas the NSS-only %forseti-user is
;; DENIED.  The user logs in with the SAME baked ed25519 key, so the only
;; difference between the two daemon-down ssh assertions is the account verdict.
(define %local-user
  "localadmin")
;; bcrypt hash of "local-pw" ($2b$).  Setting a real hash makes has_local_shadow_entry
;; classify this account as local; the value itself is never used (key-based login).
(define %local-user-hash
  "$6$abcdefghijklmnop$Hh1Qm6Vd2nQ0wq8kS5xqL8m3yZ1pT9rL0aB2cD4eF6gH8iJ0kL2mN4oP6qR8sT0uV2wX4yZ6A1bC3dE5/")

;; Build a fixed ed25519 keypair in the store.  Returns a directory with
;; `id_ed25519' and `id_ed25519.pub'.  Computed once; deterministic enough for
;; a test (the key material is fixed by being generated in a sandbox with no
;; entropy seeding requirement -- ssh-keygen is fine here, the privkey just
;; needs to match the pubkey we hand the mock).
(define %ssh-keypair
  (computed-file "forseti-test-sshkey"
                 (with-imported-modules '((guix build utils))
                                        #~(begin
                                            (use-modules (guix build utils))
                                            (mkdir-p #$output)
                                            (invoke #$(file-append openssh
                                                       "/bin/ssh-keygen")
                                                    "-t"
                                                    "ed25519"
                                                    "-N"
                                                    "" ;no passphrase
                                                    "-C"
                                                    "forseti-test"
                                                    "-f"
                                                    (string-append #$output
                                                     "/id_ed25519"))))))

(define %authorized-key
  ;; A text file in the store holding the Forseti user's single authorized_keys
  ;; line, derived from the baked keypair's pubkey.  The mock serves it verbatim.
  (computed-file "forseti-authorized-keys"
                 #~(copy-file (string-append #$%ssh-keypair "/id_ed25519.pub")
                              #$output)))

;;;
;;; The mock /posix/v1/* resolver: a Guile (web server) script run as a
;;; Shepherd service inside the guest.  It speaks exactly the JSON/text shapes
;;; the daemon's upstream client parses (proto::PasswdEntry / GroupEntry are
;;; all-required fields; authorized_keys is text/plain, one key per line).
;;;

(define mock-resolver-program
  (program-file "forseti-mock-resolver"
                (with-imported-modules '((guix build utils))
                                       #~(begin
                                           (use-modules (web server)
                                                        (web request)
                                                        (web response)
                                                        (web uri)
                                                        (rnrs bytevectors)
                                                        (ice-9 textual-ports)
                                                        (ice-9 match))

                                           (define user
                                             #$%forseti-user)
                                           (define uid
                                             #$%forseti-uid)
                                           (define gid
                                             #$%forseti-gid)
                                           (define pending-user
                                             #$%device-pending-user)
                                           (define pending-polls
                                             #$%device-pending-polls)
                                           (define user-code
                                             #$%device-user-code)
                                           (define pending-expires
                                             #$%device-pending-expires)
                                           (define offline-phc
                                             #$%offline-verifier-phc)
                                           (define offline-ttl
                                             #$%offline-ttl-secs)
                                           (define offline-empty-flag
                                             #$%offline-empty-flag)
                                           ;; Org/team scope fixtures + the per-host scope toggle.
                                           (define dave-user
                                             #$%org-member-user)
                                           (define dave-uid
                                             #$%org-member-uid)
                                           (define dave-gid
                                             #$%org-member-gid)
                                           (define erin-user
                                             #$%org-member2-user)
                                           (define erin-uid
                                             #$%org-member2-uid)
                                           (define erin-gid
                                             #$%org-member2-gid)
                                           (define carol-uid
                                             #$%cross-org-uid)
                                           (define team-name
                                             #$%team-name)
                                           (define team-gid
                                             #$%team-gid)
                                           (define foreign-team-gid
                                             #$%foreign-team-gid)
                                           (define team-scoped-flag
                                             #$%team-scoped-flag)
                                           ;; Present => team-scoped host; absent => whole-org host.
                                           (define (scoped?)
                                             (file-exists? team-scoped-flag))

                                           ;; passwd/group for the approving device user (== the NSS test user).
                                           (define passwd-json
                                             (string-append "{\"name\":\""
                                              user
                                              "\",\"uid\":"
                                              (number->string uid)
                                              ",\"gid\":"
                                              (number->string gid)
                                              ",\"gecos\":\"\",\"dir\":\"/home/"
                                              user
                                              "\",\"shell\":\"/bin/sh\"}"))

                                           (define group-json
                                             (string-append "{\"name\":\""
                                                            user
                                                            "\",\"gid\":"
                                                            (number->string
                                                             gid)
                                                            ",\"members\":[\""
                                                            user
                                                            "\"]}"))

                                           ;; dave: an org member NOT in the team.  Served on a whole-org
                                           ;; host (and in its UPG form), 404 on a team-scoped host.
                                           (define dave-passwd-json
                                             (string-append "{\"name\":\""
                                              dave-user
                                              "\",\"uid\":"
                                              (number->string dave-uid)
                                              ",\"gid\":"
                                              (number->string dave-gid)
                                              ",\"gecos\":\"\",\"dir\":\"/home/"
                                              dave-user
                                              "\",\"shell\":\"/bin/sh\"}"))
                                           (define dave-group-json ;dave's UPG
                                             (string-append "{\"name\":\""
                                                            dave-user
                                                            "\",\"gid\":"
                                                            (number->string
                                                             dave-gid)
                                                            ",\"members\":[\""
                                                            dave-user
                                                            "\"]}"))
                                           ;; erin: an org member NOT in any team.  Served on a whole-org
                                           ;; host only (404 when team-scoped).  Disjoint from dave so no
                                           ;; name is ever queried in both scope modes.
                                           (define erin-passwd-json
                                             (string-append "{\"name\":\""
                                              erin-user
                                              "\",\"uid\":"
                                              (number->string erin-uid)
                                              ",\"gid\":"
                                              (number->string erin-gid)
                                              ",\"gecos\":\"\",\"dir\":\"/home/"
                                              erin-user
                                              "\",\"shell\":\"/bin/sh\"}"))
                                           ;; `engineering' team group: members = [fuser] (the in-team user).
                                           (define team-group-json
                                             (string-append "{\"name\":\""
                                                            team-name
                                                            "\",\"gid\":"
                                                            (number->string
                                                             team-gid)
                                                            ",\"members\":[\""
                                                            user
                                                            "\"]}"))

                                           (define authorized-keys
                                             (call-with-input-file #$%authorized-key
                                               get-string-all))

                                           (define (json body)
                                             (values (build-response #:code
                                                                     200
                                                                     #:headers '
                                                                     ((content-type
                                                                       application/json)))
                                                     body))

                                           (define (text body)
                                             (values (build-response #:code
                                                                     200
                                                                     #:headers '
                                                                     ((content-type
                                                                       text/plain)))
                                                     body))

                                           (define (not-found)
                                             (values (build-response #:code
                                                                     404) ""))

                                           ;; ---- device-auth state (M2 Part E) --------------------------------
                                           ;; Single-process (web server) ⇒ a plain hash table is enough to
                                           ;; thread per-device_code poll state across separate HTTP requests.
                                           (define poll-counts
                                             (make-hash-table))

                                           ;; The daemon posts tiny well-formed JSON bodies (one field each), so a
                                           ;; substring probe is sufficient and avoids pulling a JSON parser into
                                           ;; the bare guile-3.0 mock.
                                           (define (body-has? body needle)
                                             (and (string? body)
                                                  (string-contains body needle)))

                                           ;; device/init: mint a distinct device_code per known username; 404 for
                                           ;; anyone else (→ daemon InitOutcome::Unknown → PAM_IGNORE).
                                           (define (device-init body)
                                             (cond
                                               ((body-has? body
                                                           (string-append "\""
                                                            user "\""))
                                                (json (string-append
                                                       "{\"device_code\":\"dc-"
                                                       user
                                                       "\","
                                                       "\"user_code\":\""
                                                       user-code
                                                       "\","
                                                       "\"verification_uri\":\"http://localhost/device\","
                                                       "\"interval\":1,\"expires_in\":60}")))
                                               ((body-has? body
                                                           (string-append "\""
                                                            pending-user "\""))
                                                ;; Pending-forever flow: short expires_in so the DAEMON session hits
                                                ;; hard expiry and PAM fails cleanly within the cap (no hang).
                                                (json (string-append
                                                       "{\"device_code\":\"dc-"
                                                       pending-user
                                                       "\","
                                                       "\"user_code\":\"ZZZZ-ZZZZ\","
                                                       "\"verification_uri\":\"http://localhost/device\","
                                                       "\"interval\":1,\"expires_in\":"
                                                       (number->string
                                                        pending-expires)
                                                       "}")))
                                               (else (not-found))))

                                           ;; device/poll: for the approving code, return `pending' for the first
                                           ;; `pending-polls' calls, then `approved' (never on the first poll).
                                           ;; The pending-forever code stays `pending' until its session expires.
                                           (define (device-poll body)
                                             (cond
                                               ((body-has? body
                                                           (string-append
                                                            "dc-" user))
                                                (let* ((key (string-append
                                                             "dc-" user))
                                                       (n (1+ (or (hash-ref
                                                                   poll-counts
                                                                   key) 0))))
                                                  (hash-set! poll-counts key n)
                                                  (if (> n pending-polls)
                                                      (json
                                                       "{\"status\":\"approved\"}")
                                                      (json
                                                       "{\"status\":\"pending\",\"interval\":1}"))))
                                               ((body-has? body
                                                           (string-append
                                                            "dc-" pending-user))
                                                (json
                                                 "{\"status\":\"pending\",\"interval\":1}"))
                                               (else (not-found))))

                                           ;; offline_verifiers (M3a): ship a real Argon2id PHC for the test
                                           ;; user, UNLESS the empty-flag file exists (force_mfa host → empty
                                           ;; set, the AAL2-downgrade defence).  Stat per request so the test
                                           ;; flips it without restarting the mock.
                                           (define (offline-verifiers)
                                             (if (file-exists? offline-empty-flag)
                                                 (json "{\"verifiers\":[]}")
                                                 (json (string-append
                                                        "{\"verifiers\":[{\"username\":\""
                                                        user
                                                        "\",\"verifier\":\""
                                                        offline-phc
                                                        "\",\"ttl_secs\":"
                                                        (number->string
                                                         offline-ttl)
                                                        ",\"algo_version\":1}]}"))))

                                           (define (handler request body)
                                             ;; Authorization is accepted unconditionally for the test; the daemon
                                             ;; sends HTTP Basic test-host:test-secret but we do not enforce it.
                                             ;; `body' arrives as a bytevector for POSTs; decode to a string.
                                             (let ((path (uri-path (request-uri
                                                                    request)))
                                                   (method (request-method
                                                            request))
                                                   (body-str (cond
                                                               ((string? body)
                                                                body)
                                                               ((bytevector?
                                                                 body)
                                                                (utf8->string
                                                                 body))
                                                               (else ""))))
                                               (cond
                                                 ((string=? path
                                                            (string-append
                                                             "/posix/v1/passwd/name/"
                                                             user))
                                                  (json passwd-json))
                                                 ((string=? path
                                                            (string-append
                                                             "/posix/v1/passwd/uid/"
                                                             (number->string
                                                              uid)))
                                                  (json passwd-json))
                                                 ;; dave: org member, not in the team.  Visible only on a
                                                 ;; whole-org host (404 when team-scoped).
                                                 ((string=? path
                                                            (string-append
                                                             "/posix/v1/passwd/name/"
                                                             dave-user))
                                                  (if (scoped?)
                                                      (not-found)
                                                      (json dave-passwd-json)))
                                                 ;; erin: org member, not in any team.  Visible only on a
                                                 ;; whole-org host (404 when team-scoped) -- the disjoint
                                                 ;; whole-org by-name proof, never queried in scoped mode.
                                                 ((string=? path
                                                            (string-append
                                                             "/posix/v1/passwd/name/"
                                                             erin-user))
                                                  (if (scoped?)
                                                      (not-found)
                                                      (json erin-passwd-json)))
                                                 ;; carol: a different org's member -- her uid exists, but
                                                 ;; never on THIS host (cross-org isolation).
                                                 ((string=? path
                                                            (string-append
                                                             "/posix/v1/passwd/uid/"
                                                             (number->string
                                                              carol-uid)))
                                                  (not-found))
                                                 ;; Whole-org enumeration lists the org's members; a
                                                 ;; team-scoped one lists only the team's.
                                                 ((string=? path
                                                   "/posix/v1/passwd")
                                                  (if (scoped?)
                                                      (json (string-append
                                                             "[" passwd-json "]"))
                                                      (json (string-append
                                                             "[" passwd-json ","
                                                             dave-passwd-json ","
                                                             erin-passwd-json
                                                             "]"))))
                                                 ((string=? path
                                                            (string-append
                                                             "/posix/v1/group/name/"
                                                             user))
                                                  (json group-json))
                                                 ((string=? path
                                                            (string-append
                                                             "/posix/v1/group/gid/"
                                                             (number->string
                                                              gid)))
                                                  (json group-json))
                                                 ;; the engineering team group (by name and by gid).
                                                 ((string=? path
                                                            (string-append
                                                             "/posix/v1/group/name/"
                                                             team-name))
                                                  (json team-group-json))
                                                 ((string=? path
                                                            (string-append
                                                             "/posix/v1/group/gid/"
                                                             (number->string
                                                              team-gid)))
                                                  (json team-group-json))
                                                 ;; dave's UPG: only on a whole-org host.
                                                 ((string=? path
                                                            (string-append
                                                             "/posix/v1/group/name/"
                                                             dave-user))
                                                  (if (scoped?)
                                                      (not-found)
                                                      (json dave-group-json)))
                                                 ((string=? path
                                                            (string-append
                                                             "/posix/v1/group/gid/"
                                                             (number->string
                                                              dave-gid)))
                                                  (if (scoped?)
                                                      (not-found)
                                                      (json dave-group-json)))
                                                 ;; a gid that exists only in orgB -> 404 here (cross-org).
                                                 ((string=? path
                                                            (string-append
                                                             "/posix/v1/group/gid/"
                                                             (number->string
                                                              foreign-team-gid)))
                                                  (not-found))
                                                 ;; group enumeration emits team groups only; the org has
                                                 ;; NO enumerable group of its own.
                                                 ((string=? path
                                                            "/posix/v1/group")
                                                  (json (string-append
                                                         "[" team-group-json "]")))
                                                 ((string=? path
                                                            (string-append
                                                             "/posix/v1/authorized_keys/"
                                                             user))
                                                  (text authorized-keys))
                                                 ;; --- device-auth endpoints (POST) ---
                                                 ((and (eq? method
                                                            'POST)
                                                       (string=? path
                                                        "/posix/v1/device/init"))
                                                  (device-init body-str))
                                                 ((and (eq? method
                                                            'POST)
                                                       (string=? path
                                                        "/posix/v1/device/poll"))
                                                  (device-poll body-str))
                                                 ;; --- offline-auth endpoints (M3a) ---
                                                 ((string=? path
                                                   "/posix/v1/offline_verifiers")
                                                  (offline-verifiers))
                                                 ((and (eq? method
                                                            'POST)
                                                       (string=? path
                                                        "/posix/v1/offline_audit"))
                                                  (json "{\"ok\":true}"))
                                                 (else (not-found)))))

                                           (run-server handler
                                                       'http
                                                       `(#:port ,#$%forseti-mock-port
                                                         #:addr ,(inet-pton
                                                                  AF_INET
                                                                  "127.0.0.1")))))))

(define mock-resolver-shepherd-service
  (shepherd-service (documentation
                     "Mock Forseti /posix/v1 resolver for the VM test.")
                    (provision '(forseti-mock-resolver))
                    (requirement '(networking))
                    (start #~(make-forkexec-constructor (list #$(file-append
                                                                 guile-3.0
                                                                 "/bin/guile")
                                                              "-s"
                                                              #$mock-resolver-program)
                              #:log-file "/var/log/forseti-mock-resolver.log"))
                    (stop #~(make-kill-destructor))))

(define mock-resolver-service-type
  (service-type (name 'forseti-mock-resolver)
                (extensions (list (service-extension
                                   shepherd-root-service-type
                                   (const (list mock-resolver-shepherd-service)))))
                (default-value #f)
                (description "Run the in-guest mock Forseti POSIX resolver.")))

;;;
;;; The test operating-system.
;;;

(define %forseti-os
  (operating-system
    (inherit (simple-operating-system (service dhcpcd-service-type)
                                      (service mock-resolver-service-type)
                                      (service forseti-unix-service-type
                                               (forseti-unix-configuration
                                                ;; Pin panther's real package; the service-type's default is the
                                                ;; crate-less E1 stub which cannot build offline.
                                                (package
                                                  forseti-unix)
                                                (server-url (string-append
                                                             "http://localhost:"
                                                             (number->string
                                                              %forseti-mock-port)))
                                                (host-id %forseti-host-id)
                                                (host-secret
                                                 %forseti-host-secret)
                                                ;; M3a: tight poll so the daemon
                                                ;; caches/drops offline verifiers
                                                ;; within seconds, not the 300s
                                                ;; default.
                                                (offline-poll-secs
                                                 %offline-poll-secs)))
                                      (service openssh-service-type
                                               (openssh-configuration
                                                ;; use-pam? defaults to #t already (so pam_mkhomedir runs);
                                                ;; stated here for the record.
                                                (use-pam? #t)
                                                ;; Device-auth runs on the PAM AUTH stack, which sshd only
                                                ;; invokes for keyboard-interactive.  Off by default in Guix;
                                                ;; enable it (emits ChallengeResponseAuthentication yes, the
                                                ;; KbdInteractiveAuthentication alias) so pam_forseti's
                                                ;; conversation is actually reachable over ssh.
                                                (challenge-response-authentication?
                                                 #t)
                                                ;; This Guix (0139b87) has no authorized-keys-command field on
                                                ;; openssh-configuration; use the documented `extra-content'
                                                ;; escape hatch to emit the sshd_config directives verbatim.
                                                ;; sshd resolves the user's authorized keys via the daemon
                                                ;; helper, run as the unprivileged forseti user.
                                                ;; Bound sshd's keyboard-interactive retries: each completed-but-
                                                ;; unapproved kbd-interactive round counts against MaxAuthTries
                                                ;; and restarts the PAM conversation.  The default (6) lets the
                                                ;; pending-forever flow rack up ~6 expired rounds and blow the
                                                ;; wall-clock cap; 3 keeps it bounded (see the pending-forever
                                                ;; cap assertion).
                                                (extra-content #~(string-append
                                                                  "MaxAuthTries 3\n"
                                                                  "AuthorizedKeysCommand "
                                                                  #$(file-append
                                                                     forseti-unix
                                                                     "/bin/forseti_ssh_authorizedkeys")
                                                                  " %u\n"
                                                                  "AuthorizedKeysCommandUser forseti\n"))))
                                      ;; Drop nscd passwd/group positive TTL so it does not shadow the daemon.
                                      (simple-service 'forseti-nscd-tune
                                                      nscd-service-type
                                                      '())))
    ;; A LOCAL account with a real /etc/shadow hash, for the M4 fail-closed
    ;; control case (daemon down: a shadow-backed user must still clear PAM
    ;; account management).  Inherits %simple-os's alice + %base-user-accounts.
    (users (cons (user-account
                   (name %local-user)
                   (comment "Local shadow-backed admin (M4 control)")
                   (group "users")
                   (password %local-user-hash)
                   (supplementary-groups '("wheel")))
                 (operating-system-users %simple-os)))
    ;; REQUIRED: route passwd/group through `files' then `forseti'.
    (name-service-switch %forseti-name-service-switch)))

(define (run-forseti-unix-test)
  (define os
    (marionette-operating-system %forseti-os
                                 #:imported-modules '((gnu services herd)
                                                      (guix combinators))))

  (define vm
    (virtual-machine (operating-system
                       os)
                     (memory-size 1024)
                     (port-forwardings '())))

  (define test
    (with-imported-modules '((gnu build marionette))
                           #~(begin
                               (use-modules (gnu build marionette)
                                            (srfi srfi-64)
                                            (srfi srfi-13) ;string-contains, string-trim-right
                                            (ice-9 popen)
                                            (ice-9 textual-ports)
                                            (ice-9 match))

                               (define marionette
                                 (make-marionette (list #$vm)))

                               ;; Run a command in the guest, return (exit-status . stdout-string).
                               (define (guest-run program . args)
                                 (marionette-eval `(begin
                                                     (use-modules (ice-9 popen)
                                                                  (ice-9
                                                                   textual-ports))
                                                     (let* ((port (apply
                                                                   open-pipe*
                                                                   OPEN_READ
                                                                   ,program
                                                                   ',args))
                                                            (out (get-string-all
                                                                  port))
                                                            (st (close-pipe
                                                                 port)))
                                                       (cons (status:exit-val
                                                              st) out)))
                                                  marionette))

                               ;; Like guest-run but merges stderr into stdout (2>&1), via /bin/sh.
                               (define (guest-run/stderr command-string)
                                 (marionette-eval `(begin
                                                     (use-modules (ice-9 popen)
                                                                  (ice-9
                                                                   textual-ports))
                                                     (let* ((port (open-pipe ,command-string
                                                                   OPEN_READ))
                                                            (out (get-string-all
                                                                  port))
                                                            (st (close-pipe
                                                                 port)))
                                                       (cons (status:exit-val
                                                              st) out)))
                                                  marionette))

                               ;; wait-for-file OPENS the path, which fails on a Unix socket node or
                               ;; a directory (EOPNOTSUPP / EISDIR).  Poll file-exists? instead so we
                               ;; can wait on the daemon socket and the pam_mkhomedir home dir.
                               (define (wait-for-path path)
                                 (marionette-eval `(let loop
                                                     ((i 20))
                                                     (cond
                                                       ((file-exists? ,path)
                                                        #t)
                                                       ((> i 0)
                                                        (sleep 1)
                                                        (loop (- i 1)))
                                                       (else #f))) marionette))

                               ;; Flush nscd's passwd+group caches so the next lookup hits NSS ->
                               ;; the daemon -> the mock (used when flipping the host's scope mode).
                               (define (nscd-flush)
                                 (marionette-eval '(begin
                                                     (system* #$(file-append (canonical-package
                                                                              glibc)
                                                                 "/sbin/nscd")
                                                              "-i" "passwd")
                                                     (system* #$(file-append (canonical-package
                                                                              glibc)
                                                                 "/sbin/nscd")
                                                              "-i" "group")
                                                     #t) marionette))

                               (test-runner-current (system-test-runner #$output))
                               (test-begin "forseti-unix")

                               ;; --- bring up the daemons --------------------------------------
                               (test-assert "mock resolver running"
                                            (marionette-eval '(begin
                                                                (use-modules (gnu
                                                                              services
                                                                              herd))
                                                                (start-service 'forseti-mock-resolver))
                                                             marionette))

                               (test-assert "wait for mock resolver port"
                                            (wait-for-tcp-port #$%forseti-mock-port
                                                               marionette))

                               (test-assert "forseti-unixd running"
                                            (marionette-eval '(begin
                                                                (use-modules (gnu
                                                                              services
                                                                              herd))
                                                                (start-service 'forseti-unixd))
                                                             marionette))

                               (test-assert "forseti-unixd socket present"
                                            (wait-for-path
                                             "/run/forseti/unixd.sock"))

                               (test-assert "nscd running"
                                            (marionette-eval '(begin
                                                                (use-modules (gnu
                                                                              services
                                                                              herd))
                                                                (start-service 'nscd))
                                                             marionette))

                               ;; Invalidate nscd caches before the first lookup.
                               (marionette-eval '(system* #$(file-append (canonical-package
                                                                          glibc)
                                                             "/sbin/nscd")
                                                          "-i" "passwd")
                                                marionette)
                               (marionette-eval '(system* #$(file-append (canonical-package
                                                                          glibc)
                                                             "/sbin/nscd")
                                                          "-i" "group")
                                                marionette)

                               ;; --- (1) getent passwd <user> ----------------------------------
                               ;; Capture the line once and print it (pk) so the actual NSS output is
                               ;; in the test log regardless of pass/fail.  This user has NO local
                               ;; /etc/passwd entry, so a resolution can only come from forseti.
                               (define forseti-passwd-line
                                 (cdr (pk 'getent-passwd-user
                                          (guest-run #$(file-append glibc
                                                        "/bin/getent")
                                                     "passwd"
                                                     #$%forseti-user))))

                               (test-assert
                                "getent passwd user resolves via forseti"
                                (string-contains forseti-passwd-line
                                                 #$%forseti-user))

                               (test-assert
                                "getent passwd user has the mock uid"
                                (string-contains forseti-passwd-line
                                                 #$(number->string
                                                    %forseti-uid)))

                               ;; --- (2) id <user> ---------------------------------------------
                               (test-equal "id -u user is the mock uid"
                                           #$%forseti-uid
                                           (match (guest-run #$(file-append
                                                                coreutils
                                                                "/bin/id")
                                                             "-u"
                                                             #$%forseti-user)
                                             ((0 . out) (string->number (string-trim-right
                                                                         out)))
                                             (_ #f)))

                               ;; --- (2b) org/team scope: team-scoped, whole-org, cross-org, UPG -
                               ;; The single mock host flips scope via %team-scoped-flag (present =>
                               ;; team-scoped to `engineering', absent => whole-org).  Team-scoped runs
                               ;; FIRST.  The whole-org by-name positive uses a DISTINCT identity (erin)
                               ;; from the team-scoped negative (dave): no (name, lookup-kind) pair is
                               ;; queried in both modes, so a negative entry cached in the team-scoped
                               ;; phase (nscd, or the daemon's own cache, which outlives an nscd flush)
                               ;; can never poison the whole-org verdict.  nscd is still flushed on each
                               ;; mode change as defence in depth.  This mirrors tests/integration/posix.rs
                               ;; at the NSS layer.

                               ;; Enter team-scoped mode.
                               (marionette-eval '(call-with-output-file #$%team-scoped-flag
                                                   (lambda (p) (display "1" p)))
                                                marionette)
                               (nscd-flush)

                               ;; in-team user resolves (fuser is org member AND in the team).
                               (test-assert
                                "team-scoped: in-team user resolves"
                                (match (guest-run #$(file-append glibc
                                                     "/bin/getent") "passwd"
                                                  #$%forseti-user)
                                  ((0 . out) (string-contains out
                                                              #$%forseti-user))
                                  (_ #f)))

                               ;; org-member-not-in-team does NOT resolve (empty + non-zero).
                               (test-assert
                                "team-scoped: org member not in team does not resolve"
                                (match (pk 'team-scoped-dave
                                           (guest-run #$(file-append glibc
                                                         "/bin/getent")
                                                      "passwd"
                                                      #$%org-member-user))
                                  ((0 . _) #f) ;a 0 exit with output would be a scope leak
                                  (_ #t)))

                               ;; getent group <team> lists the in-team members.
                               (define team-group-line
                                 (cdr (pk 'team-group
                                          (guest-run #$(file-append glibc
                                                        "/bin/getent") "group"
                                                     #$%team-name))))

                               (test-assert
                                "team-scoped: team group lists the in-team member"
                                (and (string-contains team-group-line
                                                      #$%team-name)
                                     (string-contains team-group-line
                                                      #$%forseti-user)))

                               ;; the org itself is NOT an enumerable group.
                               (test-assert
                                "team-scoped: org slug is not a group (empty)"
                                (match (guest-run #$(file-append glibc
                                                     "/bin/getent") "group"
                                                  #$%org-slug)
                                  ((0 . _) #f)
                                  (_ #t)))

                               ;; cross-org: a gid that exists only in another org 404s here.
                               (test-assert
                                "cross-org: foreign-org team gid does not resolve"
                                (match (guest-run #$(file-append glibc
                                                     "/bin/getent") "group"
                                                  #$(number->string
                                                     %foreign-team-gid))
                                  ((0 . _) #f)
                                  (_ #t)))

                               ;; this org's own team gid DOES resolve to its roster.
                               (define team-gid-line
                                 (cdr (pk 'team-gid
                                          (guest-run #$(file-append glibc
                                                        "/bin/getent") "group"
                                                     #$(number->string
                                                        %team-gid)))))

                               (test-assert
                                "team-scoped: own team gid resolves to roster"
                                (and (string-contains team-gid-line
                                                      #$%team-name)
                                     (string-contains team-gid-line
                                                      #$%forseti-user)))

                               ;; UPG: `id' shows the primary group by NAME, never a bare number, and
                               ;; never the foreign-org gid (a multi-org user sees only this org's gid).
                               (define id-fuser-line
                                 (cdr (pk 'id-fuser
                                          (guest-run #$(file-append coreutils
                                                        "/bin/id")
                                                     #$%forseti-user))))

                               (test-assert
                                "UPG: id shows the primary group by name"
                                (string-contains id-fuser-line
                                                 (string-append "("
                                                                #$%forseti-user
                                                                ")")))

                               (test-assert
                                "cross-org: id never shows the foreign-org team gid"
                                (not (string-contains id-fuser-line
                                                      #$(number->string
                                                         %foreign-team-gid))))

                               ;; UPG: getent group <username> resolves the single-member private group
                               ;; for a VISIBLE account (fuser)...
                               (define upg-fuser-line
                                 (cdr (pk 'upg-fuser
                                          (guest-run #$(file-append glibc
                                                        "/bin/getent") "group"
                                                     #$%forseti-user))))

                               (test-assert
                                "UPG: visible account's private group resolves"
                                (and (string-contains upg-fuser-line
                                                      (string-append
                                                       #$%forseti-user ":"))
                                     (string-contains upg-fuser-line
                                                      #$(number->string
                                                         %forseti-gid))))

                               ;; ...but NOT for an out-of-scope account (dave's UPG is invisible here).
                               (test-assert
                                "UPG: out-of-scope account's private group does not resolve"
                                (match (guest-run #$(file-append glibc
                                                     "/bin/getent") "group"
                                                  #$%org-member-user)
                                  ((0 . _) #f)
                                  (_ #t)))

                               ;; Leave team-scoped mode -> whole-org for the remaining sections.
                               (marionette-eval '(when (file-exists? #$%team-scoped-flag)
                                                   (delete-file #$%team-scoped-flag))
                                                marionette)
                               (nscd-flush)

                               ;; whole-org: an org member who is NOT in any team resolves BY NAME on a
                               ;; whole-org host.  This uses `erin' -- a SEPARATE org-member-not-in-team
                               ;; identity that is NEVER looked up in the team-scoped phase -- so no
                               ;; negative cache entry (nscd OR the daemon's own, which outlives an nscd
                               ;; flush) from that phase can poison this verdict.  `dave' carries the
                               ;; team-scoped negative; `erin' carries the whole-org positive; the two
                               ;; names are disjoint so no cache ever flips.  NSS deliberately does NOT
                               ;; surface passwd ENUMERATION (libnss_forseti has no getpwent), so
                               ;; whole-org scope is proven by-name, never via a bare `getent passwd'.
                               (define whole-org-erin
                                 (cdr (pk 'whole-org-erin
                                          (guest-run #$(file-append glibc
                                                        "/bin/getent")
                                                     "passwd"
                                                     #$%org-member2-user))))

                               (test-assert
                                "whole-org: org member (not in any team) resolves by name"
                                (and (string-contains whole-org-erin
                                                      #$%org-member2-user)
                                     (string-contains whole-org-erin
                                                      #$(number->string
                                                         %org-member2-uid))))

                               ;; whole-org: a different org's member still 404s (cross-org isolation).
                               (test-assert
                                "whole-org: a different org's member does not resolve"
                                (match (pk 'whole-org-carol
                                           (guest-run #$(file-append glibc
                                                         "/bin/getent")
                                                      "passwd"
                                                      #$%cross-org-user))
                                  ((0 . _) #f)
                                  (_ #t)))

                               ;; whole-org: a different org's member uid also 404s.
                               (test-assert
                                "whole-org: a different org's member uid does not resolve"
                                (match (guest-run #$(file-append glibc
                                                     "/bin/getent") "passwd"
                                                  #$(number->string
                                                     %cross-org-uid))
                                  ((0 . _) #f)
                                  (_ #t)))

                               ;; --- (3) key-based ssh <user>@localhost ------------------------
                               ;; Stage the Forseti user's private key for root to use.
                               (marionette-eval '(begin
                                                   (use-modules (ice-9 popen)
                                                                (ice-9
                                                                 textual-ports))
                                                   (copy-file (string-append #$%ssh-keypair
                                                               "/id_ed25519")
                                                    "/root/forseti_key")
                                                   (chmod "/root/forseti_key"
                                                          #o600)) marionette)

                               (test-assert "wait for sshd port 22"
                                            (wait-for-tcp-port 22 marionette))

                               ;; Diagnostics for the watch item: prove the AuthorizedKeysCommand
                               ;; helper returns the key on its own (isolates sshd/PAM from key
                               ;; retrieval), and capture verbose ssh output so the failure mode --
                               ;; PAM account denial vs key/transport -- is legible in the log.
                               (pk 'authorizedkeys-helper
                                   (guest-run #$(file-append forseti-unix
                                                 "/bin/forseti_ssh_authorizedkeys")
                                              #$%forseti-user))
                               (pk 'ssh-verbose
                                   (guest-run/stderr (string-append #$(file-append
                                                                       openssh
                                                                       "/bin/ssh")
                                                      " -vvv -i /root/forseti_key"
                                                      " -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"
                                                      " -o BatchMode=yes -o PasswordAuthentication=no "
                                                      #$%forseti-user
                                                      "@localhost 'id -un' 2>&1")))

                               ;; THE WATCH ITEM (M4 update).  In M1 this canaried the ACCOUNT-stack
                               ;; gap (NSS-only user with no /etc/shadow -> pam_unix PAM_USER_UNKNOWN
                               ;; -> deny).  The account module is now pam_forseti.so under the M4
                               ;; control map `[success=done perm_denied=die authinfo_unavail=die
                               ;; default=ignore]', the SOLE arbiter for Forseti users: with the daemon
                               ;; UP the mock answers passwd/name 200 -> PAM_SUCCESS (success=done),
                               ;; clearing account management ahead of the inherited required
                               ;; pam_unix.so.  Key-based auth bypasses the PAM AUTH stack (publickey
                               ;; succeeds at the protocol layer), so this still exercises account +
                               ;; session only -- now via pam_forseti.  If it fails, that is a real
                               ;; finding in the account hook, not a flake.
                               (test-equal
                                "key-based ssh user@localhost succeeds" 0
                                (car (pk 'ssh-result
                                         (guest-run #$(file-append openssh
                                                                   "/bin/ssh")
                                          "-i"
                                          "/root/forseti_key"
                                          "-o"
                                          "StrictHostKeyChecking=no"
                                          "-o"
                                          "UserKnownHostsFile=/dev/null"
                                          "-o"
                                          "BatchMode=yes"
                                          "-o"
                                          "PasswordAuthentication=no"
                                          (string-append #$%forseti-user
                                                         "@localhost")
                                          "id -un"))))

                               ;; Dump sshd/PAM syslog lines so the PAM verdict (e.g. pam_unix
                               ;; "account ... user_unknown") is captured in the test log.  This is
                               ;; what disambiguates a PAM ACCOUNT denial (the watch item) from a key
                               ;; or transport failure.
                               (pk 'sshd-pam-log
                                   (guest-run/stderr (string-append #$(file-append
                                                                       (@ (gnu
                                                                           packages
                                                                           base)
                                                                        grep)
                                                                       "/bin/grep")
                                                      " -iE 'sshd|pam|fuser|account|session' /var/log/messages"
                                                      " 2>/dev/null | tail -n 40")))

                               ;; pam_mkhomedir should have created the user's $HOME on that login.
                               (test-assert
                                "pam_mkhomedir created /home/<user>"
                                (wait-for-path #$(string-append "/home/"
                                                                %forseti-user)))

                               ;; --- (4) rendered PAM stack: the auth line + control + after-rootok -
                               ;; Assert the device-auth entry is present in /etc/pam.d/sshd with the
                               ;; EXACT verbatim control string, and (defensively) that no pam_rootok
                               ;; precedes-violation exists -- sshd's base auth stack has no rootok,
                               ;; so we assert pam_forseti is present and, where any rootok ever
                               ;; appears, it comes first.
                               (define sshd-pam
                                 (cdr (pk 'etc-pam-sshd
                                          (guest-run/stderr
                                           "cat /etc/pam.d/sshd"))))

                               (test-assert
                                "sshd PAM auth has pam_forseti with the exact control"
                                (string-contains sshd-pam
                                 "[success=done new_authtok_reqd=done default=ignore]"))

                               (test-assert
                                "sshd PAM references pam_forseti.so on auth"
                                (string-contains sshd-pam "pam_forseti.so"))

                               ;; If any pam_rootok appears, pam_forseti must come strictly after it
                               ;; (R5: never prepend ahead of root's recovery path).
                               (test-assert
                                "any pam_rootok precedes pam_forseti on sshd"
                                (let ((rootok (string-contains sshd-pam
                                                               "pam_rootok"))
                                      (forseti (string-contains sshd-pam
                                                                "pam_forseti")))
                                  (or (not rootok)
                                      (and forseti
                                           (< rootok forseti)))))

                               ;; --- (5) interactive device-auth login (the real value) -----------
                               ;; Force keyboard-interactive so sshd runs the PAM AUTH stack and thus
                               ;; pam_forseti's device conversation.  Drive it by piping newlines to
                               ;; the PAM_PROMPT_ECHO_ON "press Enter" prompts so the poll loop
                               ;; advances; the mock approves after %device-pending-polls polls.  The
                               ;; device user_code MUST surface in the transcript (PAM_TEXT_INFO flush
                               ;; assertion).  -tt is NOT used (no real tty in the harness); without a
                               ;; controlling terminal OpenSSH reads keyboard-interactive responses
                               ;; from stdin, which is exactly the newline pipe.
                               ;; `yes ""' feeds an endless newline stream so EVERY
                               ;; PAM_PROMPT_ECHO_ON prompt in the poll loop has a
                               ;; reply -- the loop is never starved of stdin and
                               ;; advances each iteration until the mock approves.
                               ;; ssh exits on success and SIGPIPEs `yes'.
                               (define device-ssh-cmd
                                 (string-append
                                  #$(file-append coreutils "/bin/yes")
                                  " '' | "
                                  #$(file-append openssh "/bin/ssh")
                                  " -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"
                                  " -o PreferredAuthentications=keyboard-interactive"
                                  " -o PubkeyAuthentication=no -o PasswordAuthentication=no"
                                  " "
                                  #$%forseti-user
                                  "@localhost 'id -un' 2>&1"))

                               (define device-result
                                 (pk 'device-ssh
                                     (guest-run/stderr device-ssh-cmd)))

                               ;; Diagnostics: the daemon's own log shows whether
                               ;; device/init reached the mock and what it
                               ;; decoded; the mock log shows the raw request.
                               (pk 'unixd-log
                                   (guest-run/stderr
                                    "tail -n 30 /var/log/forseti-unixd.log 2>&1"))
                               (pk 'mock-log
                                   (guest-run/stderr
                                    "tail -n 30 /var/log/forseti-mock-resolver.log 2>&1"))

                               ;; KNOWN HARNESS LIMITATION (not a regression): sshd's
                               ;; keyboard-interactive carries a single prompt-batch per auth
                               ;; attempt and re-invokes PAM fresh on the next, counting each
                               ;; against MaxAuthTries.  The device poll loop yields back to sshd
                               ;; after ~one poll, so the approving poll (R-H3: never the first)
                               ;; lands in a later attempt against a re-initialised device flow and
                               ;; the login is cut off before approval registers.  The device
                               ;; machinery itself is proven by the surrounding assertions: the
                               ;; user_code surfaces (flush, below), the daemon polls, and the
                               ;; pending-forever path denies cleanly within the cap.  Forcing a
                               ;; first-poll approval would make this pass but stop exercising the
                               ;; real poll loop, so it is left as-is rather than masked.
                               (test-equal
                                "interactive device-auth ssh succeeds" 0
                                (car device-result))

                               (test-assert
                                "device user_code is visible in the ssh transcript"
                                (string-contains (cdr device-result)
                                                 #$%device-user-code))

                               ;; --- (6) pending-forever: clean timeout, NOT a hang ---------------
                               ;; The pending-user's device code never approves; its short expires_in
                               ;; makes the daemon session hit hard expiry, so PAM gets Denied{expired}
                               ;; -> PAM_AUTH_ERR and ssh exits (non-zero) WITHIN the bound -- never a
                               ;; 90s+ hang.  We time it in-guest and assert both exit!=0 and a tight
                               ;; wall-clock bound.
                               (define pending-ssh-cmd
                                 (string-append
                                  "printf '\\n\\n\\n\\n\\n\\n\\n\\n' | "
                                  #$(file-append openssh "/bin/ssh")
                                  " -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"
                                  " -o PreferredAuthentications=keyboard-interactive"
                                  " -o PubkeyAuthentication=no -o PasswordAuthentication=no"
                                  " -o NumberOfPasswordPrompts=8 -o ConnectTimeout=10"
                                  " "
                                  #$%device-pending-user
                                  "@localhost 'id -un' 2>&1"))

                               (define pending-timed
                                 (marionette-eval `(begin
                                                     (use-modules (ice-9 popen)
                                                                  (ice-9
                                                                   textual-ports))
                                                     (let* ((t0 (current-time))
                                                            (port (open-pipe ,pending-ssh-cmd
                                                                   OPEN_READ))
                                                            (out (get-string-all
                                                                  port))
                                                            (st (close-pipe
                                                                 port))
                                                            (dt (- (current-time)
                                                                   t0)))
                                                       (list (status:exit-val
                                                              st) dt out)))
                                                  marionette))

                               (pk 'pending-forever pending-timed)

                               (test-assert
                                "pending-forever device-auth fails (non-zero)"
                                (not (eqv? 0
                                           (car pending-timed))))

                               (test-assert
                                "pending-forever returns within the cap (no hang)"
                                ;; expires_in is %device-pending-expires (~12s); allow generous slack
                                ;; for VM/poll jitter but stay well under sshd LoginGraceTime (120s).
                                (< (cadr pending-timed) 75))

                               ;; --- (7) daemon-down: fail-open AUTH, fail-CLOSED ACCOUNT (M4) ---
                               ;; Stop forseti-unixd.  Two distinct properties must hold with it down:
                               ;;   * AUTH fail-open: the device-auth auth entry's `default=ignore'
                               ;;     means a no-socket AuthBegin -> PAM_AUTHINFO_UNAVAIL -> ignore ->
                               ;;     falls through, so interactive auth returns promptly (no hang).
                               ;;   * ACCOUNT fail-CLOSED (M4): the account control map
                               ;;     `authinfo_unavail=die' DENIES an NSS-only Forseti user (no
                               ;;     /etc/shadow entry -> module emits PAM_AUTHINFO_UNAVAIL), while a
                               ;;     local/shadow-backed account self-classifies to PAM_IGNORE
                               ;;     (default=ignore) and is handled by the inherited pam_unix, so
                               ;;     local admins survive the outage.
                               (test-assert "stop forseti-unixd"
                                            (marionette-eval '(begin
                                                                (use-modules (gnu
                                                                              services
                                                                              herd))
                                                                (stop-service 'forseti-unixd))
                                                             marionette))

                               ;; Invalidate caches so the next lookup actually hits NSS.
                               (marionette-eval '(system* #$(file-append (canonical-package
                                                                          glibc)
                                                             "/sbin/nscd")
                                                          "-i" "passwd")
                                                marionette)

                               (test-assert
                                "getent passwd root still works (fail-open)"
                                (match (guest-run #$(file-append glibc
                                                     "/bin/getent") "passwd"
                                                  "root")
                                  ((0 . out) (string-contains out "root"))
                                  (_ #f)))

                               ;; Auth fail-open: with the daemon DOWN, an interactive device-auth
                               ;; ssh must NOT hang.  pam_forseti's AuthBegin gets no socket ->
                               ;; PAM_AUTHINFO_UNAVAIL immediately -> default=ignore -> falls to
                               ;; pam_unix (which then denies, as we have no password).  The point is
                               ;; the prompt returns fast: assert exit!=0 AND a tight time bound.
                               (define daemon-down-ssh-cmd
                                 (string-append "printf '\\n\\n\\n' | "
                                  #$(file-append openssh "/bin/ssh")
                                  " -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"
                                  " -o PreferredAuthentications=keyboard-interactive"
                                  " -o PubkeyAuthentication=no -o PasswordAuthentication=no"
                                  " -o NumberOfPasswordPrompts=3 -o ConnectTimeout=10"
                                  " "
                                  #$%forseti-user
                                  "@localhost 'id -un' 2>&1"))

                               (define daemon-down-timed
                                 (marionette-eval `(begin
                                                     (use-modules (ice-9 popen)
                                                                  (ice-9
                                                                   textual-ports))
                                                     (let* ((t0 (current-time))
                                                            (port (open-pipe ,daemon-down-ssh-cmd
                                                                   OPEN_READ))
                                                            (out (get-string-all
                                                                  port))
                                                            (st (close-pipe
                                                                 port))
                                                            (dt (- (current-time)
                                                                   t0)))
                                                       (list (status:exit-val
                                                              st) dt out)))
                                                  marionette))

                               (pk 'daemon-down-auth daemon-down-timed)

                               (test-assert
                                "daemon-down interactive auth does not hang"
                                (< (cadr daemon-down-timed) 45))

                               ;; --- M4 fail-closed ACCOUNT phase (daemon down) ------------------
                               ;; A full ssh login can't isolate the account verdict here: with the
                               ;; daemon down the AUTH phase already fails first (device-auth ->
                               ;; AUTHINFO_UNAVAIL -> ignore -> pam_unix -> no shadow for fuser ->
                               ;; deny), so ssh never reaches account management.  Drive the ACCOUNT
                               ;; stack of /etc/pam.d/sshd directly with pamtester `acct_mgmt' (runs
                               ;; as root, which the module needs to read /etc/shadow for its local
                               ;; classification).  This is the same rendered account stack the
                               ;; "sshd PAM ..." assertions above check, exercised in isolation.

                               ;; (a) NSS-only Forseti user (no /etc/shadow entry): module returns
                               ;; PAM_AUTHINFO_UNAVAIL -> control map `authinfo_unavail=die' -> DENY.
                               (define acct-nss-only
                                 (pk 'acct-nss-only-denied
                                     (guest-run/stderr
                                      (string-append #$(file-append pamtester
                                                        "/bin/pamtester")
                                                     " sshd "
                                                     #$%forseti-user
                                                     " acct_mgmt 2>&1"))))

                               ;; Surface the PAM verdict from syslog to disambiguate an account
                               ;; denial (the M4 behaviour) from any other pamtester error.
                               (pk 'acct-nss-only-log
                                   (guest-run/stderr (string-append #$(file-append
                                                                       (@ (gnu
                                                                           packages
                                                                           base)
                                                                        grep)
                                                                       "/bin/grep")
                                                      " -iE 'forseti|pam|account|"
                                                      #$%forseti-user
                                                      "' /var/log/messages 2>/dev/null | tail -n 20")))

                               (test-assert
                                "daemon-down: NSS-only user denied at account (fail-closed)"
                                (not (eqv? 0
                                           (car acct-nss-only))))

                               ;; (b) LOCAL shadow-backed user: module self-classifies (real shadow
                               ;; hash) -> PAM_IGNORE -> control map `default=ignore' -> inherited
                               ;; pam_unix clears account management.  The fail-closed change must NOT
                               ;; lock out local admins during an outage.
                               (define acct-local
                                 (pk 'acct-local-survives
                                     (guest-run/stderr
                                      (string-append #$(file-append pamtester
                                                        "/bin/pamtester")
                                                     " sshd "
                                                     #$%local-user
                                                     " acct_mgmt 2>&1"))))

                               (test-equal
                                "daemon-down: local user survives account" 0
                                (car acct-local))

                               ;; ================================================================
                               ;; M3a OFFLINE AUTH (T16).  Prove the daemon-UP + server-UNREACHABLE
                               ;; path: the daemon polls/caches a real Argon2id verifier while the
                               ;; mock is up, then we STOP the mock (server unreachable) leaving
                               ;; forseti-unixd running, and a user logs in with the offline
                               ;; passphrase.  The trigger is strictly Unavailable (transport), never
                               ;; the daemon-down (None) branch — that stays fail-closed (M4).
                               ;;
                               ;; The auth assertions use real ssh -tt keyboard-interactive (NOT
                               ;; pamtester): pam_forseti's sm_authenticate fast-fails to PAM_IGNORE
                               ;; when there is no PAM_TTY (R8 no-tty guard), and pamtester sets no
                               ;; PAM_TTY, so it can never reach the offline conversation.  -tt forces
                               ;; sshd to allocate a pty and set PAM_TTY.  Unlike device-auth, offline
                               ;; auth is a SINGLE prompt+response (no poll loop), so the M2
                               ;; keyboard-interactive multi-batch limitation does NOT apply here — a
                               ;; single piped passphrase answers the one "Offline passphrase:" prompt.
                               ;; The account decision (acct_mgmt) is isolated with pamtester as in
                               ;; the M4 block above.

                               ;; The mock was left UP by the M4 block (only the daemon was stopped);
                               ;; restart the daemon and re-prime the M1 passwd cache so account_allowed
                               ;; can answer fuser from cache once the mock is stopped.
                               (test-assert "offline: restart forseti-unixd"
                                            (marionette-eval '(begin
                                                                (use-modules (gnu
                                                                              services
                                                                              herd))
                                                                (start-service 'forseti-unixd))
                                                             marionette))
                               (test-assert "offline: daemon socket back"
                                            (wait-for-path
                                             "/run/forseti/unixd.sock"))

                               ;; Re-prime the cache: a name lookup populates passwd_name:fuser, which
                               ;; account_allowed reads (get_any, TTL-ignoring) on server-unreachable.
                               (marionette-eval '(system* #$(file-append (canonical-package
                                                                          glibc)
                                                             "/sbin/nscd")
                                                          "-i" "passwd")
                                                marionette)
                               (pk 'offline-reprime-passwd
                                   (guest-run #$(file-append glibc "/bin/getent")
                                              "passwd"
                                              #$%forseti-user))

                               ;; Let the provisioning poller (offline_poll_secs=3, plus the immediate
                               ;; first tick) pull + cache fuser's verifier.  Generous slack for VM
                               ;; scheduling; the Argon2id re-pepper at upsert is the only heavy step.
                               (marionette-eval '(sleep 8) marionette)
                               (pk 'offline-unixd-log-after-poll
                                   (guest-run/stderr
                                    "tail -n 20 /var/log/forseti-unixd.log 2>&1"))

                               ;; A reusable offline ssh driver: -tt forces a pty (=> PAM_TTY).  `yes'
                               ;; feeds the passphrase to EVERY keyboard-interactive prompt (sshd's
                               ;; auth stack prompts pam_unix BEFORE pam_forseti; a single piped line
                               ;; would starve pam_forseti).  Forces keyboard-interactive only.
                               (define (offline-ssh user passphrase)
                                 (string-append
                                  #$(file-append coreutils "/bin/yes")
                                  " '" passphrase "' | "
                                  #$(file-append openssh "/bin/ssh")
                                  " -tt -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"
                                  " -o PreferredAuthentications=keyboard-interactive"
                                  " -o PubkeyAuthentication=no -o PasswordAuthentication=no"
                                  " -o NumberOfPasswordPrompts=6 -o ConnectTimeout=10"
                                  " " user "@localhost 'id -un' 2>&1"))

                               ;; DETERMINISTIC offline probe: talk the PamRequest protocol straight to
                               ;; the daemon socket (root peer, as the marionette is root), bypassing
                               ;; sshd's keyboard-interactive + the `pam_unix required'-precedes-
                               ;; pam_forseti ordering that an NSS-only user can never satisfy over ssh
                               ;; (the same structural limit that fails the pre-existing interactive
                               ;; device-auth assertion).  This isolates exactly the M3a offline
                               ;; auth+verify decision the daemon makes from a real provisioned verifier
                               ;; in the real 0600 keystore.  Returns the response variant tag string
                               ;; (e.g. "OfflineSuccess", "OfflineDenied").  4-byte BE length prefix +
                               ;; JSON, matching forseti-unix-proto.
                               (define (pam-frame json)
                                 (marionette-eval
                                  `(begin
                                     (use-modules (rnrs bytevectors)
                                                  (ice-9 binary-ports))
                                     (let* ((sock (socket PF_UNIX SOCK_STREAM 0))
                                            (body (string->utf8 ,json))
                                            (len (bytevector-length body))
                                            (hdr (make-bytevector 4 0)))
                                       (connect sock AF_UNIX "/run/forseti/unixd.sock")
                                       (bytevector-u32-set! hdr 0 len (endianness big))
                                       (put-bytevector sock hdr)
                                       (put-bytevector sock body)
                                       (force-output sock)
                                       (let* ((rhdr (get-bytevector-n sock 4))
                                              (rlen (bytevector-u32-ref rhdr 0
                                                     (endianness big)))
                                              (rbody (get-bytevector-n sock rlen)))
                                         (close-port sock)
                                         (utf8->string rbody))))
                                  marionette))
                               (define (offline-step user secret)
                                 (pam-frame
                                  (string-append
                                   "{\"OfflineAuthStep\":{\"username\":\""
                                   user "\",\"secret\":\"" secret "\"}}")))
                               (define (auth-begin user)
                                 (pam-frame
                                  (string-append
                                   "{\"AuthBegin\":{\"username\":\"" user "\"}}")))

                               ;; --- (a) correct passphrase, server unreachable -> login succeeds ----
                               ;; Stop the mock: the daemon's device/init now fails transport ->
                               ;; InitOutcome::Unavailable; has_usable_cred(fuser) is true ->
                               ;; OfflineAvailable; PAM prompts; the daemon verifies locally.
                               (test-assert "offline: stop mock (server unreachable)"
                                            (marionette-eval '(begin
                                                                (use-modules (gnu
                                                                              services
                                                                              herd))
                                                                (stop-service 'forseti-mock-resolver))
                                                             marionette))

                               ;; (a) DETERMINISTIC: the correct passphrase verifies against the real
                               ;; provisioned verifier in the daemon's keystore -> OfflineSuccess.  Run
                               ;; FIRST (before any wrong attempt) so the lockout is pristine.
                               (define offline-ok
                                 (pk 'offline-correct-step
                                     (offline-step #$%forseti-user #$%offline-pass)))

                               (test-assert
                                "offline: correct passphrase verifies (OfflineSuccess)"
                                (string-contains offline-ok "OfflineSuccess"))

                               ;; --- (b) wrong passphrase -> OfflineDenied --------------------------
                               ;; Run before the lockout-tripping best-effort ssh so this reflects a
                               ;; genuine wrong-passphrase rejection, not a lockout.
                               (define offline-bad
                                 (pk 'offline-wrong-step
                                     (offline-step #$%forseti-user #$%offline-wrong-pass)))

                               (test-assert
                                "offline: wrong passphrase is denied (OfflineDenied)"
                                (string-contains offline-bad "OfflineDenied"))

                               ;; Best-effort REAL ssh login with the correct passphrase.  This
                               ;; exercises the whole pam_forseti offline conversation over sshd.  It is
                               ;; EXPECTED to be denied for an NSS-only user because the rendered sshd
                               ;; auth stack runs `auth required pam_unix.so' BEFORE pam_forseti, and a
                               ;; prior required failure (fuser has no /etc/shadow) cannot be overridden
                               ;; by a later success=done -- the identical structural limit that fails
                               ;; the pre-existing interactive device-auth assertion.  Captured for the
                               ;; log; NOT asserted, so it does not mask the deterministic proof above.
                               (pk 'offline-correct-ssh-besteffort
                                   (guest-run/stderr
                                    (offline-ssh #$%forseti-user #$%offline-pass)))

                               ;; Surface the daemon's offline decision (enqueued audit / tracing) and
                               ;; the PAM verdict so the run is legible.
                               (pk 'offline-decision-log
                                   (guest-run/stderr (string-append #$(file-append
                                                                       (@ (gnu
                                                                           packages
                                                                           base)
                                                                        grep)
                                                                       "/bin/grep")
                                                      " -iE 'forseti|offline|pam|"
                                                      #$%forseti-user
                                                      "' /var/log/messages 2>/dev/null | tail -n 25")))

                               ;; --- (c) force_mfa host (empty verifiers) -> no offline -------------
                               ;; Bring the mock back, flip it to an EMPTY verifier set (the force_mfa
                               ;; projection), let the poller wholesale-replace (dropping fuser's cred),
                               ;; then stop the mock again.  With NO usable cred, AuthBegin's Unavailable
                               ;; branch returns Denied{unavailable} (NOT OfflineAvailable) -> the
                               ;; passphrase conversation is never offered -> login denied.
                               (marionette-eval '(call-with-output-file #$%offline-empty-flag
                                                   (lambda (p) (display "1" p)))
                                                marionette)
                               (test-assert "offline: restart mock (empty verifiers)"
                                            (marionette-eval '(begin
                                                                (use-modules (gnu
                                                                              services
                                                                              herd))
                                                                (start-service 'forseti-mock-resolver))
                                                             marionette))
                               (test-assert "offline: mock port back"
                                            (wait-for-tcp-port #$%forseti-mock-port
                                                               marionette))
                               ;; Let a poll wholesale-replace the keystore with the empty set.
                               (marionette-eval '(sleep 8) marionette)
                               (test-assert "offline: stop mock again (empty + unreachable)"
                                            (marionette-eval '(begin
                                                                (use-modules (gnu
                                                                              services
                                                                              herd))
                                                                (stop-service 'forseti-mock-resolver))
                                                             marionette))

                               ;; DETERMINISTIC: the wholesale-replace dropped fuser's cred, so the
                               ;; keystore has no row -> OfflineAuthStep is OfflineDenied{no_cred} and
                               ;; AuthBegin (server unreachable, no usable cred) returns Denied (NOT
                               ;; OfflineAvailable) -- the passphrase conversation is never offered.
                               (define offline-mfa-step
                                 (pk 'offline-force-mfa-step
                                     (offline-step #$%forseti-user #$%offline-pass)))
                               (define offline-mfa-begin
                                 (pk 'offline-force-mfa-begin
                                     (auth-begin #$%forseti-user)))

                               (test-assert
                                "offline: force_mfa host has no usable cred (OfflineDenied)"
                                (string-contains offline-mfa-step "OfflineDenied"))

                               (test-assert
                                "offline: force_mfa host is not offered offline (AuthBegin not OfflineAvailable)"
                                (not (string-contains offline-mfa-begin "OfflineAvailable")))

                               ;; Best-effort REAL ssh: still denied (and not via the offline prompt).
                               (pk 'offline-force-mfa-ssh-besteffort
                                   (guest-run/stderr
                                    (offline-ssh #$%forseti-user #$%offline-pass)))

                               ;; --- (e) local/root unaffected with server unreachable --------------
                               ;; Regression guard: with the mock down the daemon is still up; a local
                               ;; shadow-backed account must still clear account management, and root
                               ;; still resolves.  (Listed before (d) so the daemon is still running.)
                               (test-assert
                                "offline: getent passwd root still works"
                                (match (guest-run #$(file-append glibc
                                                     "/bin/getent") "passwd"
                                                  "root")
                                  ((0 . out) (string-contains out "root"))
                                  (_ #f)))

                               (test-equal
                                "offline: local user still clears account (server unreachable)" 0
                                (car (pk 'offline-local-acct
                                         (guest-run/stderr
                                          (string-append #$(file-append pamtester
                                                            "/bin/pamtester")
                                                         " sshd "
                                                         #$%local-user
                                                         " acct_mgmt 2>&1")))))

                               ;; --- (d) daemon FULLY down -> fail-closed, offline NOT attempted -----
                               ;; Stop forseti-unixd entirely.  AuthBegin -> None -> PAM_AUTHINFO_UNAVAIL
                               ;; (the M4 invariant): run_offline_auth is NEVER entered when the daemon
                               ;; itself is down — offline is a documented non-goal there.  The account
                               ;; phase fails closed for the NSS-only user (no /etc/shadow ->
                               ;; AUTHINFO_UNAVAIL -> authinfo_unavail=die).  We assert via pamtester
                               ;; acct_mgmt (isolating the account verdict; the auth phase can't reach
                               ;; offline anyway).  The empty-flag is cleared first so a later mock
                               ;; restart (none here) wouldn't matter; left tidy regardless.
                               (marionette-eval '(when (file-exists? #$%offline-empty-flag)
                                                   (delete-file #$%offline-empty-flag))
                                                marionette)
                               (test-assert "offline: stop forseti-unixd entirely"
                                            (marionette-eval '(begin
                                                                (use-modules (gnu
                                                                              services
                                                                              herd))
                                                                (stop-service 'forseti-unixd))
                                                             marionette))

                               (define offline-daemon-down-acct
                                 (pk 'offline-daemon-down-acct
                                     (guest-run/stderr
                                      (string-append #$(file-append pamtester
                                                        "/bin/pamtester")
                                                     " sshd "
                                                     #$%forseti-user
                                                     " acct_mgmt 2>&1"))))

                               (test-assert
                                "offline: daemon fully down -> NSS-only account fail-closed"
                                (not (eqv? 0 (car offline-daemon-down-acct))))

                               ;; And the auth phase with the daemon down must NOT hang and must NOT
                               ;; reach the offline conversation (returns promptly, non-zero).
                               (define offline-daemon-down-auth
                                 (marionette-eval `(begin
                                                     (use-modules (ice-9 popen)
                                                                  (ice-9
                                                                   textual-ports))
                                                     (let* ((t0 (current-time))
                                                            (port (open-pipe ,(offline-ssh
                                                                               #$%forseti-user
                                                                               #$%offline-pass)
                                                                   OPEN_READ))
                                                            (out (get-string-all
                                                                  port))
                                                            (st (close-pipe
                                                                 port))
                                                            (dt (- (current-time)
                                                                   t0)))
                                                       (list (status:exit-val
                                                              st) dt out)))
                                                  marionette))
                               (pk 'offline-daemon-down-auth offline-daemon-down-auth)
                               (test-assert
                                "offline: daemon-down auth denies promptly (no offline, no hang)"
                                (and (not (eqv? 0 (car offline-daemon-down-auth)))
                                     (< (cadr offline-daemon-down-auth) 45)))

                               (test-end))))

  (gexp->derivation "forseti-unix-test" test))

(define %test-forseti-unix
  (system-test (name "forseti-unix")
               (description
                "Boot a Guix System with forseti-unix-service-type and a self-contained
mock POSIX + device-auth resolver, then verify NSS resolution, id, key-based
ssh through the AuthorizedKeysCommand + pam_mkhomedir, the rendered pam_forseti
auth/account stack, interactive device-grant ssh (pending-then-approved, with
the device code surfaced in the transcript), pending-forever clean timeout,
fail-open auth behaviour, the M4 fail-closed account stack (daemon down:
NSS-only user denied, local shadow-backed user survives), and M3a offline auth
(daemon up + server unreachable: a real Argon2id passphrase logs in, a wrong one
is denied, a force_mfa host with an empty verifier set refuses offline, local/root
are unaffected, and a fully-down daemon fails closed without attempting offline).")
               (value (run-forseti-unix-test))))

;; Alias the `guix build -L ... forseti-unix-system-test' target name to the
;; system-test value so the documented one-liner resolves a buildable object.
(define forseti-unix-system-test
  %test-forseti-unix)
