{stdenv, fetchurl, perl}:

stdenv.mkDerivation {
  name = "eccablog-0.1";
  builder = ./builder.sh;
  src = fetchurl {
    url = github.com/gwitmond/ecca-blog;
    md5 = "70c9ccf9fac07f762c24f2df2290784d";
  };
  inherit perl;

  meta = {
    description = "GNU Hello, a classic computer science tool";
    homepage = http://www.gnu.org/software/hello/;
  };
}
