with (import <nixpkgs> {});
derivation {
  name = "gwitmond-unbound";
  builder = "${bash}/bin/bash";
  args = [ ./go-build-lib.sh ];
  inherit stdenv cacert;
  buildInputs = [ go git ];
  cdeps = [ unbound ];
  src = "github.com/gwitmond/unbound";
  system = builtins.currentSystem;
}