# forseti_ssh_authorizedkeys

sshd `AuthorizedKeysCommand` helper. Given a username (sshd passes `%u`), it asks
`forseti-unixd` over its Unix socket for that user's authorized keys and prints
them one per line on stdout.

## Usage

```
forseti_ssh_authorizedkeys <username>
```

Socket path comes from `FORSETI_UNIXD_SOCKET`, defaulting to
`/run/forseti/unixd.sock`.

## sshd configuration

```
AuthorizedKeysCommand /path/to/forseti_ssh_authorizedkeys %u
AuthorizedKeysCommandUser forseti
```

### Requirements

- **Ownership/permissions:** sshd refuses to run the command unless the command
  itself *and every parent directory* are root-owned and not group/world-writable.
  A `/gnu/store/...` path satisfies this on Guix.
- **`AuthorizedKeysCommandUser`** must name a real, low-privilege account.
- **NSS resolution:** the user must already resolve via NSS (e.g. through the
  Forseti NSS module) for sshd to accept the keys returned here.

## Fail-open

The helper **always exits 0**. If the daemon is down, returns an unexpected
response, or the user has no Forseti keys, it prints nothing and lets sshd fall
through to other auth methods (`AuthorizedKeysFile`, etc.). Forseti keys are
simply unavailable when the daemon is down; other auth methods still apply.

A one-line note is written to stderr on the failure path; stderr does not affect
`AuthorizedKeysCommand` parsing.
