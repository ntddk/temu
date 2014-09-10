# TEMU is Copyright (C) 2006-2010, BitBlaze Team.
# 
# You can redistribute and modify it under the terms of the GNU LGPL,
# version 2.1 or later, but it is made available WITHOUT ANY WARRANTY.

obj-m	:= linuxdrv.o
KDIR	:= /lib/modules/$(shell uname -r)/build
PWD	:= $(shell pwd)

default:
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) clean
	rm -rf Module.markers modules.order Module.symvers

