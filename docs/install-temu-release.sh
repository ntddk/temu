#!/bin/bash
# Instructions for installing TEMU 1.0 on Ubuntu 9.04 Linux 32-bit

# Things that require root access are preceded with "sudo".

# Last tested 2009-10-05

# This script will build TEMU in a "$HOME/bitblaze" directory,
# assuming that temu-1.0.tar.gz is in /tmp.
cd ~
mkdir bitblaze
cd bitblaze

# TEMU is based on QEMU. It's useful to have a vanilla QEMU for testing
# and image development:
sudo apt-get install qemu
# Stuff needed to compile QEMU/TEMU:
sudo apt-get build-dep qemu

# The KQEMU accelerator is not required for TEMU to work, but it can
# be useful to run VMs faster when you aren't taking traces.
# 
# The following commands would build a kqemu module compatible with
# your system QEMU, but in Ubuntu 9.04 that would be too new to work
# with TEMU.
# sudo apt-get install kqemu-common kqemu-source
# sudo apt-get install module-assistant
# sudo module-assistant -t auto-install kqemu

# For the BFD library:
sudo apt-get install binutils-dev

# TEMU needs GCC version 3.4 (neither 3.3 nor 4.x will work)
sudo apt-get install gcc-3.4

# Unpack source
tar xvzf /tmp/temu-1.0.tar.gz

# Build TEMU
# You can select one of several plugins; "tracecap" provides
# tracing functionality.
(cd temu-1.0 && ./configure --target-list=i386-softmmu --proj-name=tracecap \
                            --cc=gcc-3.4 --prefix=`pwd`/install)
(cd temu-1.0 && make)
(cd temu-1.0 && make install)
