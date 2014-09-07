#!/bin/bash

# prepend_copyright.sh
# Prepend copyright notice to all source files
# Usage: ./prepend_copyright.sh <copyright_file>


TEMPFILE=/tmp/prepend_license.tmp

FILES=$(cat <<EOF
TEMU_lib.h
TEMU_main.c
TEMU_main.h
TEMU_mem_def.h
TEMU_physaddr_info.c
TEMU_physaddr_info.h
TEMU_vm_compress.c
TEMU_vm_compress.h
sample_plugin/main.c
sample_plugin/main.h
sample_plugin/network.c
sample_plugin/network.h
shared/disasm-pp.h
shared/disasm.h
shared/hookapi.c
shared/hookapi.h
shared/hooks/function_map.cpp
shared/hooks/function_map.h
shared/hooks/hook_plugin_loader.cpp
shared/hooks/hook_plugin_loader.h
shared/hooks/hook_plugins/group_hook_helper.c
shared/hooks/hook_plugins/group_hook_helper.h
shared/hooks/hook_plugins/hook_plugin.c
shared/hooks/hook_plugins/hook_plugin.h
shared/hooks/hook_plugins/plugin.h
shared/hooks/ihook_helper.h
shared/hooks/reg_ids.h
shared/junk.c
shared/procmod.cpp
shared/procmod.h
shared/read_linux.c
shared/read_linux.h
shared/reduce_taint.c
shared/reduce_taint.h
taintcheck.c
taintcheck.h
EOF)

EXPECTED_ARGS=1
E_BADARGS=65

if [ $# -ne $EXPECTED_ARGS ]
then
    echo "Usage: `basename $0` <copyright_file>"
    echo "Example: `basename $0` README"
    exit $E_BADARGS
fi

if ! [ -f $1 ]
then
    echo "$1 does not exist!"
    exit $E_BADARGS
fi

COPYRIGHT_FILE=$1

for X in $FILES
do
    rm -f $TEMPFILE
    echo "/*" > $TEMPFILE
    cat $COPYRIGHT_FILE >> $TEMPFILE
    echo "*/" >> $TEMPFILE
    echo >> $TEMPFILE
    cat $X >> $TEMPFILE
    cp $TEMPFILE $X
done
