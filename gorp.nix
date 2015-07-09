with (import <nixpkgs> {});
derivation {
  name = "coopernurse-gorp";
  builder = "${bash}/bin/bash";
  args = [ ./go-build-lib.sh ];
  buildInputs = [ go git ];
  inherit stdenv cacert;
  src = "github.com/coopernurse/gorp";
  system = builtins.currentSystem;
}