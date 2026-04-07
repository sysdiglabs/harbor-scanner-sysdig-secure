{ buildGoModule }:
buildGoModule {
  pname = "harbor-scanner-sysdig-secure";
  version = "0.8.4";
  vendorHash = "sha256-xcdnL/1AUyQ0n3R5rLVxpv/Mk9cbJa5PWqnbYY2Q5iQ=";
  src = ./.;
  subPackages = [
    "cmd/harbor-scanner-sysdig-secure"
  ];
  ldflags = [
    "-w"
    "-s"
  ];
  doCheck = false;
  env.CGO_ENABLED = 0;
}
