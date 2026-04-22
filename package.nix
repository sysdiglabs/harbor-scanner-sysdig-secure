{ buildGoModule }:
buildGoModule {
  pname = "harbor-scanner-sysdig-secure";
  version = "0.8.4";
  vendorHash = "sha256-Wvz1TjkasrTYX3cI5dQGZLgoVUJxOpM3AniDfj4DfoE=";
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
