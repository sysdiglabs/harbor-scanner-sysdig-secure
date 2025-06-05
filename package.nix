{ buildGoModule }:
buildGoModule {
  pname = "harbor-scanner-sysdig-secure";
  version = "0.8.0";
  vendorHash = "sha256-da3up+9QRZR5oJokSGP89we6W2vku+ZdjQvL3hVfbpg=";
  src = ./.;

  doCheck = false;
}
