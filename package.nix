{ buildGoModule }:
buildGoModule {
  pname = "harbor-scanner-sysdig-secure";
  version = "0.8.4";
  vendorHash = "sha256-zTLTbNYohQkYpvO8BDnFXczlcWABCvhwk/dRFmZuUqk=";
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
