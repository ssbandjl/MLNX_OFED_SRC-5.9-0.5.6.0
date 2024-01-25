#!/bin/bash

CURDIR=$(readlink -f $0)
CURDIR=$(dirname $CURDIR)

if [ $# -eq 1 ]; then
    if [ -n "$1" ]; then
        INSTALLPATH=$1
    else
        echo "This script accepts one argument - install path, which cannot be empty"
        exit 1
    fi
else
    INSTALLPATH=$CURDIR/install
fi

#module load hpcx-gcc

cd utils
./make_mxml
cd ..

./configure --prefix=$INSTALLPATH --enable-shared --enable-static --enable-coll-details --with-mxmlpath=$PWD/utils/mxml --enable-commsize --enable-parser --with-map-comm-ranks=fast 2>&1 | tee build.log
make  2>&1 | tee make.log

#make install      # done separately by Makefile in mpitest dir. istall-ipm target


