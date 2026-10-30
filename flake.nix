{
  description = "github-keygen, confined by Landlock (landrun) and bubblewrap";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs =
    { self, nixpkgs }:
    let
      # Landlock and bubblewrap are Linux-only
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
      gkFor = pkgs: pkgs.callPackage ./nix/package.nix { src = ./github-keygen; };
    in
    {
      packages = forAllSystems (
        pkgs:
        let
          gk = gkFor pkgs;
        in
        {
          inherit (gk) github-keygen-safe;
          default = gk.github-keygen-safe;
        }
      );

      checks = forAllSystems (
        pkgs:
        pkgs.lib.filterAttrs (_: pkgs.lib.isDerivation) (
          pkgs.callPackage ./nix/tests.nix { gk = gkFor pkgs; }
        )
      );

      formatter = forAllSystems (pkgs: pkgs.nixfmt);
    };
}
