{ dockerTools, harbor-adapter }:
dockerTools.buildLayeredImage {
  name = "sysdiglabs/harbor-scanner-sysdig-secure";
  tag = harbor-adapter.version;
  contents = [ harbor-adapter ];
  config.Entrypoint = "harbor-scanner-sysdig-secure";
}
