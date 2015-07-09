#!/bin/bash

set -e
source $stdenv/setup

set -ex
#export PATH="${go}/bin:${gcc}/bin:${git}/bin:${coreutils}/bin:${gnugrep}/bin"
export GIT_SSL_CAINFO=${cacert}/etc/ca-bundle.crt
export GOPATH=`pwd`
echo go-deps is: ${godeps}
for i in ${godeps}; do
    GOPATH=${GOPATH}:${i}
done
echo cdeps is: ${cdeps}
for i in ${cdeps}; do
    test -d ${i}/include && INCLUDE="${INCLUDE} -I ${i}/include "
    test -d ${i}/lib     && LIB="${LIB} -L ${i}/lib "
done
#export CGO_FLAGS
git clone "https://"${src} src/${src}
pushd src/${src}
package=`grep -h '^package\s.*' *.go | head -1 | cut -d' ' -f 2`
if [ "x" != "x${cdeps}" ]; then
   file=`mktemp -p . cflagsXXXX.go`
   cat > $file <<EOF
package ${package}
// #cgo CFLAGS: $INCLUDE
// #cgo LDFLAGS: $LIB
import "C"
EOF
fi
#go test
go install -x
for i in ${gopkgs} ; do
    pushd $i
    go install -x
    popd
done
popd
mkdir ${out}
mv src pkg ${out}/
