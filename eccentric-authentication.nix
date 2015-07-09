with (import <nixpkgs> {});
derivation rec {
  name = "gwitmond-eccentric-authentication";
  builder = "${bash}/bin/bash";
  args = [ ./go-build-lib.sh ];
  inherit stdenv cacert;
  buildInputs = [ go git ];
  gopkgs = [ "fpca" "camaker" ];
  gwitmond_unbound = import ./gwitmond-unbound.nix;
  godeps = [ gwitmond_unbound ];
  src = "github.com/gwitmond/eccentric-authentication";
  system = builtins.currentSystem;
}