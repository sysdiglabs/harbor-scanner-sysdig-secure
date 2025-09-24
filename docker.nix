{
  dockerTools,
  harbor-adapter,
  cacert,
  bash,
  curl,
  coreutils,
}:
dockerTools.buildLayeredImage {
  name = "sysdiglabs/harbor-scanner-sysdig-secure";
  tag = harbor-adapter.version;
  contents = [
    harbor-adapter
    cacert
  ];

  # https://github.com/moby/moby/blob/46f7ab808b9504d735d600e259ca0723f76fb164/image/spec/spec.md#image-json-field-descriptions
  config = {
    Cmd = [ "/bin/harbor-scanner-sysdig-secure" ];
    User = "1000:1000";
    ExposedPorts = {
      "5000" = { };
    };
    Env = [
      "SSL_CERT_FILE=${cacert}/etc/ssl/certs/ca-bundle.crt"
      "NIX_SSL_CERT_FILE=${cacert}/etc/ssl/certs/ca-bundle.crt"
    ];
  };
}
