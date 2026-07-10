{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    # Pin harbor-cli: 0.0.23 (current unstable) breaks the e2e `harbor artifact
    # scan start` call with HTTP 405. This revision provides harbor-cli 0.0.18,
    # which the e2e suite is known to work against. Only harbor-cli is sourced
    # from here; everything else tracks nixpkgs-unstable.
    nixpkgs-harbor-cli.url = "github:NixOS/nixpkgs/0fd2db475afdde93c9e4b1625aafb8eb41b99807";
    flake-utils.url = "github:numtide/flake-utils";
  };
  outputs =
    {
      self,
      nixpkgs,
      nixpkgs-harbor-cli,
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
          harbor-cli = (import nixpkgs-harbor-cli { inherit system; }).harbor-cli;
        in
        {
          packages = with pkgs; {
            inherit harbor-adapter;
            harbor-adapter-docker = pkgsCross.gnu64.callPackage ./docker.nix { };
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
                gopls
                govulncheck
                harbor-cli
                just
                kubectl
                kubernetes-helm
                minikube
                pre-commit
                sd
                skopeo
                trivy
              ];

              inputsFrom = [
                harbor-adapter
              ];

              shellHook = ''
                pre-commit install
              '';
            };

          formatter = pkgs.nixfmt-tree;
        }
      );
    in
    flake // { inherit overlays; };
}
