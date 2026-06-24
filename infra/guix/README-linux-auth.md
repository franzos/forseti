# Forseti Linux auth on Guix System

This directory packages the `forseti-unix` client workspace for GNU Guix and
provides the service that wires it into a Guix System.

- The `forseti-unix` package — builds the cargo workspace under
  `../../forseti-unix` into:
  - `sbin/forseti-unixd` — the daemon
  - `bin/forseti_ssh_authorizedkeys` — the sshd `AuthorizedKeysCommand` helper
  - `lib/libnss_forseti.so.2` — the NSS module (dlopened by nscd)

  It lives in the **panther** channel as `forseti-unix` in
  `(px packages authentication)` (the E1 stub that used to live in
  `forseti-unix.scm` here is gone — it had no vendored crates and could not
  build offline).
- `forseti-unix-service.scm` — `forseti-unix-service-type` (defaults to
  panther's `forseti-unix`), plus `%forseti-name-service-switch` and
  `%forseti-nscd-caches` for the `operating-system`.

## Build

```sh
# The service module imports the package from panther, so load both trees:
guix build -L ~/git/panther -L infra/guix forseti-unix
```

> **Dependency-graph note.** Under `cargo-build-system` the ~190-crate
> dependency graph must be supplied as `#:cargo-inputs` (one Guix package per
> crate, vendored offline). Panther's `forseti-unix` carries that generated
> crate set, so it builds offline. The retired E1 stub in this directory did
> not — it left `#:cargo-inputs` empty and stopped at cargo's offline crate
> resolution — which is why the package now lives in panther.

## The service, in one diagram

```
operating-system
├─ name-service-switch  = %forseti-name-service-switch   (files → forseti)
└─ services
   ├─ forseti-unix-service-type
   │   ├─ nscd-service-type        ← adds forseti-unix pkg to name-services
   │   │                             (THIS makes nscd dlopen the .so)
   │   ├─ account-service-type     ← forseti:forseti (unprivileged)
   │   ├─ etc-service-type         ← /etc/forseti/unixd.toml (0600)
   │   ├─ activation-service-type  ← /run/forseti 0755, /var/cache/forseti 0700
   │   │                             owned forseti:forseti
   │   ├─ pam-root-service-type    ← account control map (fails CLOSED on
   │   │                             daemon-down) + auth device-grant +
   │   │                             optional pam_mkhomedir.so on session stack
   │   └─ shepherd-root-service-type ← forseti-unixd as forseti:forseti
   ├─ openssh-service-type (use-pam? #t + AuthorizedKeysCommand)
   └─ nscd-service-type override (caches = %forseti-nscd-caches, TTL 60s)
```

## Account-stack invariant (fail-closed on daemon outage)

The service prepends `pam_forseti.so` onto each target's `account` stack with an
explicit control map and treats it as the **sole arbiter** for Forseti users:

```
account [success=done perm_denied=die authinfo_unavail=die default=ignore] pam_forseti.so
account required pam_unix.so   # inherited tail
```

- **Allowed** Forseti user → `PAM_SUCCESS` → `done` (clears).
- **Denied** Forseti user → `PAM_PERM_DENIED` → `die` (hard deny).
- **Daemon unreachable** → `PAM_AUTHINFO_UNAVAIL` → `die` (**fails closed** — a
  Forseti user cannot log in while `forseti-unixd` is down).
- **Not a Forseti user** (daemon up) → `PAM_IGNORE` → falls through to
  `pam_unix.so`, so **local accounts are unaffected**.

The service no longer relies on the inherited `required pam_unix.so` to deny the
shadow-less NSS-only user: `pam_unix`'s `acct_mgmt` returns `PAM_SUCCESS` when
the passwd field is not a shadow placeholder, which would let a Forseti user
clear the stack with the daemon down. The fail-closed decision is now enforced
by this service, not assumed of the base stack. You do **not** need to add any
trailing deny module of your own.

## Layer-5 VM smoke test (deferred — needs `guix system vm`)

Runtime verification — that `getent`, `id`, and a key-based `ssh` actually
resolve through Forseti and land in a `pam_mkhomedir`-created home — cannot run
in CI or the dev sandbox. It needs a booted Guix System VM and a live Forseti
server with an enrolled host. This is the deferred Layer-5 test.

### 1. A minimal `operating-system`

```scheme
(use-modules (gnu) (gnu services base) (gnu services ssh)
             (forseti-unix-service))
(use-service-modules base networking ssh)

(operating-system
  (host-name "forseti-vm")
  (timezone "Etc/UTC")
  (locale "en_US.utf8")
  (bootloader (bootloader-configuration (bootloader grub-bootloader)
                                        (targets '("/dev/vda"))))
  (file-systems (cons (file-system (mount-point "/")
                                   (device "/dev/vda1")
                                   (type "ext4"))
                      %base-file-systems))
  (users %base-user-accounts)

  ;; (E2 point 2) Chain `forseti' after `files' for passwd/group. REQUIRED:
  ;; nscd loading the module is inert unless nsswitch routes lookups to it.
  (name-service-switch %forseti-name-service-switch)

  (services
   (cons*
    (service forseti-unix-service-type
             (forseti-unix-configuration
              (server-url "https://id.example.com")
              (host-id "host-abc")
              (host-secret "REDACTED")
              (cache-ttl 300)))

    (service openssh-service-type
             (openssh-configuration
              ;; HARD PRECONDITION: pam_mkhomedir runs only under PAM. With
              ;; use-pam? #f the SSH session never enters the PAM session
              ;; stack and NO home directory is created — the user logs into a
              ;; missing $HOME. This must be #t.
              (use-pam? #t)
              (password-authentication? #f)
              (authorized-keys-command
               (file-append forseti-unix "/bin/forseti_ssh_authorizedkeys"))
              (authorized-keys-command-user "forseti")))

    ;; (E2 point 1, TTL) Lower nscd passwd/group positive TTL to 60s so nscd
    ;; doesn't shadow the daemon's TTL with a long stale window.
    (modify-services %base-services
      (nscd-service-type config =>
        (nscd-configuration (inherit config)
                            (caches %forseti-nscd-caches)))))))
```

Build and boot the VM:

```sh
guix system vm -L infra/guix /path/to/this-config.scm
# run the resulting script with a forwarded ssh port, e.g.
./$(guix system vm -L infra/guix config.scm) \
    -nic user,model=virtio-net-pci,hostfwd=tcp::10022-:22
```

### 2. Enroll + provision (Forseti side, on the server)

1. **Admin → Hosts → New**: enroll the VM as a host. Copy the one-time
   `host_id:secret` and write it into the config's `host-id` / `host-secret`,
   then rebuild the VM.
2. **Admin → POSIX**: provision a Kratos identity into a POSIX account
   (uid/gid/shell/home) and add an SSH public key for it.

### 3. Smoke steps (on the booted VM)

```sh
# NSS resolution via the daemon:
getent passwd <user>          # uid/gid/shell/home from Forseti
getent group  <group>
id <user>                     # Forseti-supplied group membership

# sshd: key comes from AuthorizedKeysCommand; session creates the home dir.
ssh -p 10022 -i <user-key> <user>@localhost
#   → first login lands in a pam_mkhomedir-created $HOME (from /etc/skel)

# PAM precondition assertion:
sshd -T | grep -i usepam      # MUST print: usepam yes
```

### 4. Teardown / negative check

```sh
# In Forseti admin: revoke the host OR delete/disable the identity.
# On the VM, drop the nscd cache so the change is visible immediately:
nscd -i passwd
nscd -i group
getent passwd <user>          # → no result; resolution has stopped
```

### Failure modes worth knowing

- `getent` empty but daemon up → check nsswitch lists `forseti`
  (`%forseti-name-service-switch`) AND that nscd has the module
  (`herd status nscd`; the package must be in nscd's `name-services`).
- `ssh` accepts the key but `$HOME` missing → `use-pam?` is not `#t`, so
  `pam_mkhomedir` never ran. `sshd -T | grep usepam` confirms.
- daemon won't start → it refuses to run as root and refuses a
  group/world-writable socket dir. `herd status forseti-unixd` and the log at
  `/var/log/forseti-unixd.log`; the activation gexp must have created
  `/run/forseti` as `forseti:forseti 0755`.
