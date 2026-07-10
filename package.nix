{ buildGoModule }:
buildGoModule {
  pname = "harbor-scanner-sysdig-secure";
  version = "0.8.4";
  vendorHash = "sha256-fytzhgoLL2OA4eK7HOyIbFmdhE/E6ceiYuynGLJT3gQ=";
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
