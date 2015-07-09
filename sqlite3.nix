with (import <nixpkgs> {});
derivation {
  name = "mattn-go-sqlite3";
  builder = "${bash}/bin/bash";
  args = [ ./go-build-lib.sh ];
  buildInputs = [ go git ];
  inherit stdenv cacert;
  src = "github.com/mattn/go-sqlite3";
  system = builtins.currentSystem;
}
