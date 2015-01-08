#!/bin/bash
PROJECT=$1

if [ $# != 1 ]; then
    echo "you must specify a project name" 1>&2
    exit 0
fi

./configure --target-list=i386-softmmu --proj-name=${PROJECT} --prefix=$(pwd)/install --disable-gcc-check