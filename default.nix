with (import <nixpkgs> {});
derivation rec {
  name = "ecca-blog-0.2";
  builder = "${bash}/bin/bash";
  args = [ ./go-build-app.sh ];
  inherit go gcc git coreutils gnugrep cacert findutils;
  mattn_go_sqlite3 = import ./sqlite3.nix;
  coopernurse_gorp = import ./gorp.nix;
  eccentric = import ./eccentric-authentication.nix;
  unbound = import ./gwitmond-unbound.nix;
  godeps = [ mattn_go_sqlite3 coopernurse_gorp eccentric unbound ];
  src = "github.com/gwitmond/ecca-blog";
  system = builtins.currentSystem;
}