{ buildGoLatestModule }:
buildGoLatestModule {
  pname = "harbor-scanner-sysdig-secure";
  version = "0.8.5";
  vendorHash = "sha256-zxxt0ZDiMHauliBtMeg9MHDyIrJIZ/Q2DWd6MVr5GT8=";
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
