{
  inputs = {
    # nixpkgs.url = "github:nixos/nixpkgs?ref=nixpkgs-unstable";
    nixpkgs.url = "github:NixOS/nixpkgs?ref=refs/pull/447819/head";
    flake-compat.url = "https://flakehub.com/f/edolstra/flake-compat/1.tar.gz";
  };

  outputs = inputs: let
    inherit (inputs) self nixpkgs;
    forAllSystems = function:
      nixpkgs.lib.genAttrs [
        "x86_64-linux"
        "aarch64-linux"
      ] (system:
        function (import nixpkgs {
          inherit system;
          overlays = [
            (_: prev: {
              mtkclient = prev.mtkclient.overrideAttrs (_: {
                version = "git";
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

    overlays.default = _final: prev: {
      inherit (self.packages.${prev.system}) mtkclient;
    };
  };
}
