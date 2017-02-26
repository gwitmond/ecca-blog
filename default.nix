{ stdenv, buildGoPackage, fetchgit, fetchhg, fetchbzr, fetchsvn, unbound }:

buildGoPackage rec {
  name = "ecca-blog-${version}";
  version = "20151208-${stdenv.lib.strings.substring 0 7 rev}";
  rev = "0a8982e13e3acf38887366cb7f71518662ccea2b";

  goPackagePath = "github.com/gwitmond/ecca-blog";

  src = fetchgit {
    inherit rev;
    url = "https://github.com/gwitmond/ecca-blog";
    sha256 = "1x87a2m4h37qmq5ghbr9ypbypziwnvnriihw554n915iy6qvyd1y";
  };

  goDeps = ./deps.nix;

  buildInputs = [ unbound ];

  postInstall =
    ''
      #mkdir -p $bin
      cp -r $src/static $src/templates $bin/
    '';
    
  # TODO: add metadata https://nixos.org/nixpkgs/manual/#sec-standard-meta-attributes
  meta = {
    name = "ecca-blog";
    description = "Cryptographic secure anonymous blog";
    longDescription= ''
      EccaBlog is a demonstration of the Eccentric Authentication protocol.
      It features easy signup, end-to-end encrypted messages and end-to-end
      authenticated identities. All while the user remain anonymous.
    '';
    homepage = http://eccentric-authentication.org/;
    license = stdenv.lib.licenses.agpl3Plus;
    maintainers = [ "Guido Witmond <guido@witmond.nl>" ];
    platforms = stdenv.lib.platforms.all;
  };
}
