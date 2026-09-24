{ buildGoModule }:
buildGoModule {
  pname = "harbor-scanner-sysdig-secure";
  version = "0.8.5";
  vendorHash = "sha256-SdyfyWOH7XTl2lB151U68n8RzLUbOIuT/oyOa5PE85U=";
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
