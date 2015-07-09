#!/bin/bash

set -e
source ${stdenv}/setup

set -ex
# set CA for curl to github
export GIT_SSL_CAINFO=${cacert}/etc/ca-bundle.crt

# set gopaths
export GOPATH=`pwd`
echo go-deps is: ${godeps}
for i in ${godeps}; do
    GOPATH=${GOPATH}:${i}
done

# get the whole thing
git clone "https://"${src} src/${src}
pushd src/${src}

# set c dependency paths
echo cdeps is: ${cdeps}
if [ "x" != "x${cdeps}" ]; then
    for i in ${cdeps}; do
        test -d ${i}/include && INCLUDE="${INCLUDE} -I ${i}/include "
        test -d ${i}/lib     && LIB="${LIB} -L ${i}/lib "
    done

    # set the CFLAGS and LDFLAGS for the go build in a new .go file
    package=`grep -h '^package\s.*' *.go | head -1 | cut -d' ' -f 2`
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

# populate the output directory
if [ "x" != "x${installDirs}" ]; then
    mkdir -p ${out}/lib/
    for i in ${installDirs}; do
        cp -r ${i} ${out}/lib/
    done
fi

# place the go build results
popd
mkdir -p ${out}
mv bin ${out}/
