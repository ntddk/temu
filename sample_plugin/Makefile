# TEMU is Copyright (C) 2006-2010, BitBlaze Team.
# 
# You can redistribute and modify it under the terms of the GNU LGPL,
# version 2.1 or later, but it is made available WITHOUT ANY WARRANTY.

include ../config-host.mak

DEFINES=-I. -I.. -I$(SRC_PATH) -I$(SRC_PATH)/i386-softmmu -I$(SRC_PATH)/target-i386 -I$(SRC_PATH)/fpu
DEFINES+=-D_GNU_SOURCE

ifeq ($(ARCH), x86_64)
XED_PATH=$(SRC_PATH)/shared/xed2/xed2-intel64
endif
ifeq ($(ARCH), i386)
XED_PATH=$(SRC_PATH)/shared/xed2/xed2-ia32
endif


CFLAGS=-Wall -O4 -g -fPIC -MMD -I$(XED_PATH)/include
LDFLAGS=-g -Wl -shared 
LIBS=

LIBS+=-lm -L$(XED_PATH)/lib -lxed

PLUGIN = plugin.so

all: $(PLUGIN) 

%.o: %.c 
	gcc $(CFLAGS) $(DEFINES) -c -o $@ $<

%.o: %.cpp
	g++ $(CFLAGS) $(DEFINES) -c -o $@ $<

%.so: main.o network.o ../shared/procmod.o ../shared/read_linux.o ../shared/hookapi.o	../shared/hooks/function_map.o ../shared/reduce_taint.o
	g++ $(LDFLAGS) $^ -o $@ $(LIBS)

clean:
	rm -f *.o *.so *~ $(PLUGIN) ../shared/*.o ../shared/hooks/*.o

# Include automatically generated dependency files
-include $(wildcard *.d ../*.d ../shared/*d ../shared/*/*.d)

