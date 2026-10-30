{
  lib,
  stdenvNoCC,
  writeShellApplication,
  closureInfo,
  bash,
  bubblewrap,
  cacert,
  curl,
  gnugrep,
  gzip,
  landrun,
  openssh,
  perl,
  src,
}:

let
  version = "1.401";

  # The release script, byte for byte (no shebang patching): it is always
  # run as "perl github-keygen".
  script = stdenvNoCC.mkDerivation {
    pname = "github-keygen-script";
    inherit version src;
    dontUnpack = true;
    dontPatchShebangs = true;
    installPhase = ''
      install -Dm555 "$src" "$out/libexec/github-keygen"
    '';
  };

  # Tools github-keygen runs. curl always comes from here (it uses the
  # bundled CA certificates). ssh, ssh-keygen and zgrep come from the host
  # when it has ssh (see sandbox.sh); these are the fallback. xclip and
  # pbcopy are left out on purpose: github-keygen then prints the .pub path.
  fallbackTools = [
    openssh
    gzip
    gnugrep
  ];

  # mkSandboxed: a wrapper that runs `command` confined (see sandbox.sh).
  # `roots` must contain every store path the confined command uses.
  mkSandboxed =
    {
      name,
      command,
      roots ? [ ],
      offlineArgs ? [ ],
      meta ? { },
    }:
    let
      closure = closureInfo {
        rootPaths =
          fallbackTools
          ++ [
            perl
            curl
            bash
            cacert
          ]
          ++ roots;
      };
    in
    writeShellApplication {
      inherit name meta;
      runtimeInputs = [ ];
      text = ''
        readonly CLOSURE=${closure}
        readonly TOOLS_PATH=${lib.makeBinPath [ curl ]}
        readonly FALLBACK_PATH=${lib.makeBinPath fallbackTools}
        readonly CACERT=${cacert}/etc/ssl/certs/ca-bundle.crt
        readonly SH_BIN=${bash}/bin/sh
        readonly PERL=${perl}/bin/perl
        readonly BWRAP=${bubblewrap}/bin/bwrap
        readonly LANDRUN=${landrun}/bin/landrun
        readonly COMMAND=(${lib.escapeShellArgs command})
        readonly OFFLINE_ARGS=(${lib.escapeShellArgs offlineArgs})

      ''
      + builtins.readFile ./sandbox.sh;
    };

  github-keygen-safe = mkSandboxed {
    name = "github-keygen-safe";
    command = [
      "${perl}/bin/perl"
      "${script}/libexec/github-keygen"
    ];
    roots = [ script ];
    offlineArgs = [ "--offline" ];
    meta = {
      description = "github-keygen confined by Landlock and bubblewrap";
      homepage = "https://github.com/dolmen/github-keygen";
      license = lib.licenses.gpl3Plus;
      platforms = lib.platforms.linux;
      mainProgram = "github-keygen-safe";
    };
  };

in
{
  inherit script mkSandboxed github-keygen-safe;
}
