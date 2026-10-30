# Security audit: github-keygen v1.401

Audit date: 2026-10-30. Subject: the `release` branch at `37e3125` (Release v1.401),
in particular the fatpacked `github-keygen` script and `github-keygen.cmd`.

Focus: is it safe to run, and could it exfiltrate sensitive data (private keys,
passphrases, SSH config, environment)?

## Verdict

**Safe to run. No exfiltration path found.** The only network access is one
unauthenticated `curl` GET of `https://github.com/<user>.keys` per account,
which downloads *public* keys and sends nothing but the account name. Private
key material is never read by the script: `ssh-keygen` writes it and the script
only reads the `.pub` file. One local data-loss bug was found (see F1); it is
not a security issue but is worth fixing.

## Method

1. **Provenance of the main program.** Lines 9780–end of `github-keygen` (the
   part after the FatPacker `BEGIN` block) were diffed against
   `bin/github-keygen` in history: identical to the source at commit `b0cf43f`
   ("README: remove link on v1.401"), i.e. the release build contains exactly
   the reviewed source.
2. **Line-by-line review of the main program** (~870 lines) for network access,
   subprocesses, file reads/writes and environment use.
3. **Bundled CPAN modules** (lines 1–9778) compared with official CPAN
   releases — see [Bundled modules](#bundled-modules).
4. **Pinned GitHub host key** (the `__END__` data written to
   `~/.ssh/known_hosts_github`) checked against `https://api.github.com/meta`.
5. **Dynamic run** under `strace -f -e trace=execve,connect` with a throwaway
   `HOME`, creating a key for one account and checking it on GitHub.

## Findings on data flow

### Network

| What | Where | Data sent |
|---|---|---|
| `curl -s -f https://github.com/$user.keys` | line 10166 | the GitHub user name (in the URL) |

That is the only network access. `$user` must match `/^[a-z0-9_-]+$/`
(line 9884) and the command is run in list form (no shell), so the URL cannot
be injected into. `--offline` skips it entirely. Under strace, the only
non-local `connect()` was to GitHub (`140.82.116.3:443`); everything else was
the local nscd socket used for name lookup.

### Subprocesses (all observed under strace)

- `ssh-keygen -t … -b … -C … [-N passphrase] -f <keyfile>` — creates the key
  (list form, no shell).
- `ssh-keygen -l -f <keyfile>.pub` — fingerprint of the public key.
- `ssh -V`, `ssh -Q cipher|mac|kex` — capability detection; the `-Q`
  invocations go through `sh -c` but with constant arguments only.
- Old OpenSSH fallback only: `ssh -c|-m <algo> -o XXX=xxx` with constant
  algorithm names (not reached on a modern OpenSSH).
- `man -w ssh_config` and, for a gzipped page, `zgrep '\.It Cm' '<manfile>'`
  — reads the local man page to check option support.
- `xclip -selection clipboard` / `pbcopy` — receives **only the public key**
  (`type base64`, the comment is stripped at line 10616), and only when exactly
  one new or unregistered key exists.
- Windows (`github-keygen.cmd`): adds Git's `bin` directory to `PATH` and runs
  `perl` on the script; nothing else.

### Files

Read: `~/.ssh/config`, `~/.ssh/known_hosts_github` (size only), `*.pub` files
of the configured accounts, the `ssh_config(5)` man page.
**Private keys are never opened.**

Written (all under `~/.ssh`): `config` (only the delimited
`# -- github-keygen - begin/end --` section is regenerated; a unified diff is
printed), `known_hosts_github`, and new key pairs via `ssh-keygen`.
`~/.ssh` is created with mode 0700 if missing. No temp files are used.

Environment read: `HOME`/`USERPROFILE`, `PATH` (Windows only),
`XDG_RUNTIME_DIR` (for `ControlPath`), `DISPLAY`, `GITHUB_KEYGEN_DONWGRADE`.

### Generated SSH configuration

The generated section hardens connections to GitHub: `StrictHostKeyChecking
yes` with a dedicated `UserKnownHostsFile`, `PreferredAuthentications
publickey`, `IdentitiesOnly yes`, `ForwardAgent no`, `ForwardX11 no`,
`PermitLocalCommand no`, `HostKeyAlgorithms -ssh-rsa`, and modern
cipher/MAC/KEX lists filtered against what the local `ssh` supports. It only
applies to `github.com`, `gist.github.com`, `ssh.github.com`, `443.github.com`
and their `<user>.` aliases; other hosts are unaffected.

### Pinned host key

All three entries in the `__END__` block use the ed25519 key
`SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU`, which matches GitHub's
published fingerprint and key in `https://api.github.com/meta` (checked
2026-10-30). The 291-byte size check at line 10242 matches this data.

## Bundled modules

Each module was extracted from its heredoc (with FatPacker's 2-space indent
removed) and diffed against the official release. No POD or comments had been
stripped, so the comparison is exact. **All are byte-identical; nothing was
injected.**

| Module | Version | Upstream | Result |
|---|---|---|---|
| Algorithm::Diff | 1.201 | Algorithm-Diff-1.201 | identical |
| Pod::Escapes | 1.07 | Pod-Escapes-1.07 | identical |
| Pod::Simple (+ BlackBox, LinkSection, TiedOutFH) | 3.45 | Pod-Simple-3.45 | identical |
| Pod::Text | 5.01_02 | perl v5.40.0 core (`cpan/podlators/lib/Pod/Text.pm`) | identical |
| Pod::Usage | 2.03 | Pod-Usage-2.03 | identical |
| Text::Diff | 1.45 | Text-Diff-1.45 | identical |

Pod::Text 5.01_02 is the copy that ships with perl 5.40, not a CPAN release.
It differs from CPAN podlators-5.01 only by its version line and an added
`require PerlIO;`.

The loader code, from the `BEGIN` block to `# END OF FATPACK CODE`, is
standard App::FatPacker output. The bundled modules make no network access and
write no files. The only `system` calls, in Pod::Usage, run `perldoc` or a
pager for `-verbose 2` help output, which this script never requests. String
`eval`s only `require` module names or build regexes.

## Issues

### F1 — Unreadable `~/.ssh/config` is deleted or overwritten (data loss, medium)

If `~/.ssh/config` exists but cannot be opened (e.g. mode `0200`), the script
only warns (line 9947) and continues with an empty config, then:

- with no account arguments, it deletes the file (lines 10581–10589);
- with an account argument, it overwrites the file with only the
  github-keygen section, losing all other entries.

Reproduced in a throwaway `HOME`:

```
$ chmod 200 ~/.ssh/config; github-keygen
github-keygen: can't open …/.ssh/config
Removing ~/.ssh/config...
Done.
```

The permission check at line 9938 rejects `x` and group/other `w`, but not a
missing owner `r`. Suggested fix: make the open failure fatal (`die` instead of
`warn`). Unlikely in practice, but the outcome is destructive.

### F2 — `-p/--passphrase` is visible to other local users (low)

The passphrase is passed to `ssh-keygen` as `-N <passphrase>` (line 10133), so
other users of the machine can see it in the process list (`ps`,
`/proc/*/cmdline`) while `ssh-keygen` runs, and it is saved in shell history.
The option is optional and documented. Without `-p`, `ssh-keygen` prompts
interactively, which is the safer choice on shared machines.

### F3 — Host name in the key comment (informational)

The default key comment is `<hostname>/<user>@github.com` (line 10127). The
clipboard copy strips the comment, but if the user pastes the `.pub` file
manually, the machine's host name ends up on GitHub as part of the key. Use
`-C` to choose another comment.

### F4 — Minor robustness notes (informational, no security impact)

- `zgrep '\.It Cm' '$manfile'` (line 10467) builds a shell command from the
  man page path; a path containing `'` would break it. The path comes from
  `man -w` or a fixed path, so it cannot be controlled by an attacker.
- The `GITHUB_KEYGEN_DONWGRADE` environment variable (line 10060) is
  misspelled ("DONWGRADE"); harmless, but surprising if someone sets
  `…_DOWNGRADE`.
- `known_hosts_github` is created with the process umask (typically 0644). It
  only holds public host keys, and OpenSSH accepts this.
- `ControlMaster auto` creates connection sockets in `$XDG_RUNTIME_DIR` (or
  `~/.ssh`), which are private to the user.

### F5 — A failed man page check comments out the whole section (medium)

To check which `ssh_config` options the local OpenSSH supports, the script
reads the `ssh_config(5)` man page (lines 10448–10502). If the man page exists
but reading it produces nothing (for example `zgrep` is missing for a `.gz`
page, or the page can't be read), every option, including the `Host` lines,
is reported as "not available" and commented out with `##`. The GitHub section
then has no effect.

Cause: `%supported_options` is seeded with two entries (`useroaming`,
`protocol`) before the man page is parsed, so the sanity check
`scalar(keys %supported_options) > 1` passes even when parsing found nothing.
Suggested fix: count only the parsed entries, or check `> 3`.

Found while testing the sandboxed wrapper below, whose first version had no
`zgrep`. Rerunning github-keygen in a working environment regenerates the
section correctly.

## How to verify yourself

```sh
# main program == source at the release commit
sed -n '9780,$p' github-keygen | diff - <(git show b0cf43f:bin/github-keygen)
# pinned host key fingerprint
sed -n '10648,10650p' github-keygen | ssh-keygen -lf -
# observed subprocesses and connections, in a scratch HOME
mkdir -p /tmp/gk/.ssh && chmod 700 /tmp/gk/.ssh
env -i PATH="$PATH" HOME=/tmp/gk strace -f -e trace=execve,connect ./github-keygen <user>
```

## Sandboxed wrapper (`nix run`)

This branch adds a Nix flake that packages the audited script, unmodified,
behind `github-keygen-safe`. The wrapper confines it with Landlock (via
[landrun](https://github.com/Zouuup/landrun)) and bubblewrap:

```sh
nix run github:<owner>/github-keygen/<branch> -- alice            # offline (default)
nix run github:<owner>/github-keygen/<branch> -- --online alice   # also checks the key on GitHub
```

| | Offline (default) | `--online` |
|---|---|---|
| Executable/readable | the Nix closure of perl, curl, bash, cacert, the script and the fallback tools; plus, when the host has `ssh`: its directory, `/usr`, `/bin`, `/sbin`, `/lib*`, `/etc/ld.so.cache`, the man configuration, and `/nix/store` if that ssh is from Nix | same |
| Writable | `~/.ssh`, `/dev/null`, `/dev/tty` | same |
| Read-only extras | `/etc/passwd`, `/etc/group`, `/etc/nsswitch.conf`, `/dev/urandom` | + `/etc/resolv.conf`, `/etc/hosts`, `/etc/host.conf` |
| Network | none: empty network namespace, `--offline` passed to github-keygen | outbound TCP to port 443 only |
| Environment | `HOME`, `PATH`, `SSL_CERT_FILE`, `XDG_RUNTIME_DIR` | same |

The wrapper also:

- refuses to run if the kernel's Landlock ABI is below 3 (4 for `--online`),
  because `landrun --best-effort` would otherwise run the tool unconfined;
- refuses to run if `~/.ssh/config` exists but is unreadable (F1);
- replaces `/bin/sh` inside the sandbox with the shell from the closure, as
  github-keygen runs `ssh -Q` through it.

The generated config is read by the host's ssh, so the wrapper uses the
host's `ssh`, `ssh-keygen`, `man` and `zgrep` (found through the caller's
`PATH`). github-keygen then checks the version, algorithms and man page of the
ssh that will actually use the config. The bundled openssh, gzip and grep are
only used when the host has no ssh. `curl` always comes from the closure with
its own CA bundle. `xclip` and `pbcopy` are not available, so github-keygen
prints the `.pub` path instead of copying the key to the clipboard.

Remaining limits:

- `~/.ssh` is readable, including other private keys there. In offline mode
  nothing can leave the machine. In `--online` mode a malicious script could
  send them to any host on port 443, and over UDP on kernels with Landlock ABI
  below 10 (landrun 0.1.17 does not restrict UDP). Prefer offline mode and
  check the registration yourself with `curl https://github.com/<user>.keys`.
- Requires unprivileged user namespaces (for bubblewrap).

Tests: `nix flake check` runs these checks in the Nix build sandbox:

- `script-is-audited`: the packaged script's sha256 matches the audited release.
- `keygen-offline`: creates a key, the existing config is kept, the pinned
  host key is written, `ssh -Q` detection works, no warnings, and a rerun
  changes nothing.
- `fhs-host`: in a root with a distribution-like `/usr` (ssh and a gzipped
  `ssh_config.5`, no `man`), the man page check works and only the options
  modern OpenSSH removed (`Protocol`, `UseRoaming`) are commented out (F5).
- `remove-account`: `-r` removes the section and `known_hosts_github`.
- `unreadable-config-refused`: F1 is guarded.
- `confinement-offline` and `confinement-online`: a probe running in the same
  sandbox cannot read, create or truncate files outside `~/.ssh`, sees only the
  allowed environment variables (an injected `SECRET_TOKEN` is dropped), and
  can't reach the network (offline) or any TCP port other than 443 (online).
