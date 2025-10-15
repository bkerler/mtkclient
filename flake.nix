{
  inputs = {
    # nixpkgs.url = "github:NixOS/nixpkgs?ref=nixpkgs-unstable";
    nixpkgs.url = "github:NixOS/nixpkgs?ref=refs/pull/432318/head";
    flake-compat.url = "https://flakehub.com/f/edolstra/flake-compat/1.tar.gz";
  };

  outputs = inputs: let
    inherit (inputs) self nixpkgs;
    forAllSystems = let
      inherit (nixpkgs.lib) genAttrs;
      supportedSystems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
    in
      f:
        genAttrs supportedSystems (system:
          f (import nixpkgs {
            inherit system;
            overlays = [
              (_: prev: {
                mtkclient = prev.mtkclient.overrideAttrs (_: {
                  version = "unstable";
                  src = self;
                });
              })
            ];
          }));
  in {
    devShells = forAllSystems (pkgs: {
      default = pkgs.mkShell {
        inputsFrom = [pkgs.mtkclient];
      };
    });

    packages = forAllSystems (pkgs: {
      inherit (pkgs) mtkclient;
      default = self.packages.${pkgs.system}.mtkclient;
    });

    overlays.default = _: prev: {
      inherit (self.packages.${prev.system}) mtkclient;
    };
  };
}
