{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };
  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
    }:
    let
      overlays.default = final: prev: {
        harbor-adapter = prev.callPackage ./package.nix { };
      };
      flake = flake-utils.lib.eachDefaultSystem (
        system:
        let
          pkgs = import nixpkgs {
            inherit system;
            config.allowUnfree = true;
            overlays = [ self.overlays.default ];
          };
        in
        {
          packages = with pkgs; {
            inherit harbor-adapter;
            harbor-adapter-docker = callPackage ./docker.nix { };
            default = harbor-adapter;
          };
          devShells.default =
            with pkgs;
            mkShell {
              packages = [
                # Add here dependencies for the project.
                ginkgo
                go
                gofumpt
                golangci-lint
                govulncheck
                just
                pre-commit
                sd
              ];

              inputsFrom = [
                harbor-adapter
              ];

              shellHook = ''
                pre-commit install
              '';
            };

          formatter = pkgs.nixfmt-rfc-style;
        }
      );
    in
    flake // { inherit overlays; };
}
