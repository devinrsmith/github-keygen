{
  lib,
  runCommand,
  perl,
  openssh,
  bubblewrap,
  gzip,
  gnugrep,
  gk,
}:

let
  inherit (gk) github-keygen-safe;

  # sha256 of the github-keygen v1.401 release reviewed in AUDIT.md.
  # Update only after re-auditing a new release.
  auditedSha256 = "d3d97ba7a32ec7e0cc2426aac7e3ca28a7e38d919566b9a7d022789dfd270572";

  # The same sandbox as github-keygen-safe, running nix/probe.pl
  probe = gk.mkSandboxed {
    name = "sandbox-probe";
    command = [
      "${perl}/bin/perl"
      "${./probe.pl}"
    ];
    roots = [ ./probe.pl ];
  };

  # A /usr like a typical Linux distribution: ssh and the gzipped ssh_config(5)
  # man page, but no man command. github-keygen then reads the man page with
  # zgrep.
  fakeUsr = runCommand "fake-fhs-usr" { } ''
    mkdir -p $out/bin $out/share/man/man5
    ln -s ${openssh}/bin/ssh ${openssh}/bin/ssh-keygen ${gzip}/bin/zgrep ${gzip}/bin/gzip ${gnugrep}/bin/grep $out/bin/
    ln -s ${openssh.man}/share/man/man5/ssh_config.5.gz $out/share/man/man5/
  '';

  # Each test runs in a fresh, fake HOME with an existing ~/.ssh/config
  mkTest =
    name: script:
    runCommand "github-keygen-safe-test-${name}"
      {
        nativeBuildInputs = [
          github-keygen-safe
          probe
          perl
          openssh
          bubblewrap
        ];
      }
      ''
        set -euo pipefail
        export HOME=$TMPDIR/home
        mkdir -p "$HOME/.ssh"
        chmod 700 "$HOME/.ssh"
        printf 'Host example\n  HostName example.com\n' > "$HOME/.ssh/config"
        chmod 600 "$HOME/.ssh/config"

        fail() { echo "FAIL: $*" >&2; exit 1; }
        # expect LINE FILE: FILE has exactly LINE
        expect() { grep -qxF -- "$1" "$2" || { cat "$2" >&2; fail "expected '$1' in $2"; }; }

        ${script}

        touch "$out"
      '';

in
{
  script-is-audited = runCommand "github-keygen-script-is-audited" { } ''
    actual=$(sha256sum ${gk.script}/libexec/github-keygen | cut -d' ' -f1)
    if [[ $actual != "${auditedSha256}" ]]; then
      echo "github-keygen changed since the audit (sha256 $actual)." >&2
      echo "Re-audit it, then update auditedSha256 in nix/tests.nix." >&2
      exit 1
    fi
    touch "$out"
  '';

  keygen-offline = mkTest "keygen-offline" ''
    github-keygen-safe alice -p "" > out.txt 2>&1 || { cat out.txt; fail "github-keygen-safe failed"; }
    cat out.txt

    s=$HOME/.ssh
    [[ -f $s/id_alice@github && -f $s/id_alice@github.pub ]] || fail "key pair not created"
    [[ $(stat -c %a "$s/id_alice@github") == 600 ]] || fail "private key is not mode 600"
    ssh-keygen -l -f "$s/id_alice@github.pub" | grep -q ED25519 || fail "not an ed25519 key"

    # The existing configuration is kept and the GitHub section added
    expect 'Host example' "$s/config"
    expect 'Host alice.github.com alice.gist.github.com alice.ssh.github.com alice.443.github.com' "$s/config"
    expect 'IdentityFile ~/.ssh/id_alice@github' "$s/config"
    expect 'StrictHostKeyChecking yes' "$s/config"
    # Detected with "ssh -Q", run through /bin/sh inside the sandbox
    grep -q '^KexAlgorithms .*curve25519-sha256' "$s/config" || fail "KexAlgorithms not detected"
    grep -q '^Ciphers chacha20-poly1305@openssh.com' "$s/config" || fail "Ciphers not detected"
    # github-keygen prefixes its warnings with its name
    if grep '^github-keygen:' out.txt; then fail "github-keygen warned"; fi

    # Pinned GitHub host key
    [[ $(stat -c %s "$s/known_hosts_github") == 291 ]] || fail "unexpected known_hosts_github"
    ssh-keygen -l -f "$s/known_hosts_github" | grep -q 'SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU github.com' \
      || fail "unexpected GitHub host key"

    # Running again changes nothing
    cp "$s/config" config.before
    github-keygen-safe alice > out2.txt 2>&1 || { cat out2.txt; fail "second run failed"; }
    cmp "$s/config" config.before || fail "second run changed the config"
    grep -q 'No changes in ~/.ssh/config' out2.txt || fail "second run did not report 'No changes'"
    if grep '^github-keygen:' out2.txt; then fail "github-keygen warned"; fi
  '';

  # On a typical distribution github-keygen must use the host's ssh (the one
  # that will read the config) and its man page, and must not comment out
  # every option when the man page check fails.
  fhs-host = mkTest "fhs-host" ''
    # Run in a root made of the Nix sandbox's directories plus the fake /usr
    in_fhs() {
      bwrap --ro-bind /nix /nix --bind /build /build --ro-bind /etc /etc \
        --ro-bind /bin /bin --ro-bind ${fakeUsr} /usr --dev /dev --proc /proc \
        --tmpfs /tmp -- env PATH="/usr/bin:$PATH" "$@"
    }

    in_fhs github-keygen-safe alice -p "" > out.txt 2>&1 || { cat out.txt; fail "github-keygen-safe failed"; }
    cat out.txt

    s=$HOME/.ssh
    if grep -E '^github-keygen:|command not found' out.txt; then fail "unexpected warnings"; fi
    # Only the options that modern OpenSSH removed may be commented out
    if grep '^##' "$s/config" | grep -v -E '^##(Protocol|UseRoaming) '; then
      fail "options were commented out"
    fi
    expect '##Protocol 2' "$s/config"
    expect 'Host alice.github.com alice.gist.github.com alice.ssh.github.com alice.443.github.com' "$s/config"
    expect 'IdentityFile ~/.ssh/id_alice@github' "$s/config"
    grep -q '^KexAlgorithms .*curve25519-sha256' "$s/config" || fail "KexAlgorithms not detected"
  '';

  remove-account = mkTest "remove-account" ''
    github-keygen-safe alice -p "" > /dev/null 2>&1 || fail "keygen failed"
    github-keygen-safe alice -r > out.txt 2>&1 || { cat out.txt; fail "remove failed"; }
    cat out.txt

    s=$HOME/.ssh
    expect 'Host example' "$s/config"
    ! grep -q github "$s/config" || fail "GitHub section still present"
    [[ ! -e $s/known_hosts_github ]] || fail "known_hosts_github not removed"
    [[ -f $s/id_alice@github ]] || fail "the key itself must be kept"
  '';

  # F1 in AUDIT.md: an unreadable config must not be overwritten or deleted
  unreadable-config-refused = mkTest "unreadable-config-refused" ''
    chmod 200 "$HOME/.ssh/config"
    if github-keygen-safe alice -p "" > out.txt 2>&1; then
      fail "github-keygen-safe should have refused to run"
    fi
    cat out.txt
    grep -q 'is not readable; refusing to run' out.txt || fail "wrong error message"
    chmod 600 "$HOME/.ssh/config"
    expect 'Host example' "$HOME/.ssh/config"
    [[ ! -e $HOME/.ssh/id_alice@github ]] || fail "a key was created"
  '';

  confinement-offline = mkTest "confinement-offline" ''
    echo secret > "$HOME/secret"
    echo existing > "$HOME/.ssh/existing"
    echo outside > "$TMPDIR/outside"

    SECRET_TOKEN=hunter2 sandbox-probe \
      "$TMPDIR/outside" \
      tcp:1.1.1.1:443 udp:1.1.1.1:53 tcp:127.0.0.1:443 > out.txt 2>&1 \
      || { cat out.txt; fail "probe failed"; }
    cat out.txt

    expect 'read-home: denied' out.txt
    expect 'create-home: denied' out.txt
    expect 'truncate-home: denied' out.txt
    expect 'read-ssh: ok' out.txt
    expect 'create-ssh: ok' out.txt
    expect "read-$TMPDIR/outside: denied" out.txt
    # No network: TCP is blocked by Landlock (ABI 4+, no port granted) and
    # by the empty network namespace; UDP by the namespace only.
    grep -q '^connect-tcp:1.1.1.1:443: \(denied\|failed (Network is unreachable)\)$' out.txt \
      || fail "internet reachable over TCP"
    expect 'connect-udp:1.1.1.1:53: failed (Network is unreachable)' out.txt
    grep -q '^connect-tcp:127.0.0.1:443: \(denied\|failed (Network is unreachable)\)$' out.txt \
      || fail "loopback reachable"
    # Only the allowed variables are passed (no SECRET_TOKEN)
    expect 'env: HOME,PATH,SSL_CERT_FILE' out.txt
    [[ $(cat "$HOME/secret") == secret ]] || fail "secret was modified"
  '';

  confinement-online = mkTest "confinement-online" ''
    abi=$(perl -e 'print syscall(444, 0, 0, 1)')
    if ((abi < 4)); then
      echo "SKIPPED: kernel Landlock ABI $abi has no TCP restrictions"
    else
      echo secret > "$HOME/secret"

      # A listener the sandbox must not be able to reach (not port 443)
      perl -MSocket -e '
        socket(my $s, PF_INET, SOCK_STREAM, 0) or die $!;
        setsockopt($s, SOL_SOCKET, SO_REUSEADDR, 1);
        bind($s, pack_sockaddr_in(8080, inet_aton("127.0.0.1"))) or die $!;
        listen($s, 5) or die $!; sleep 60' &
      listener=$!
      sleep 1

      sandbox-probe --online tcp:127.0.0.1:8080 tcp:127.0.0.1:443 > out.txt 2>&1 \
        || { cat out.txt; fail "probe failed"; }
      kill $listener || true
      cat out.txt

      expect 'read-home: denied' out.txt
      expect 'create-home: denied' out.txt
      # Port 8080 is listening but Landlock forbids it
      expect 'connect-tcp:127.0.0.1:8080: denied' out.txt
      # Port 443 is allowed by Landlock (nothing is listening)
      expect 'connect-tcp:127.0.0.1:443: failed (Connection refused)' out.txt
      expect 'env: HOME,PATH,SSL_CERT_FILE' out.txt
    fi
  '';
}
