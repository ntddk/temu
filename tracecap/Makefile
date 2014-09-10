# TEMU-Tracecap is Copyright (C) 2006-2010, BitBlaze Team.
#
# You can redistribute and modify it under the terms of the GNU LGPL,
# version 2.1 or later, but it is made available WITHOUT ANY WARRANTY.
#
# As an additional exception, the XED and Sleuthkit libraries, including
# updated or modified versions, are excluded from the requirements of
# the LGPL as if they were standard operating system libraries.

include ../config-host.mak

DEFINES=-I. -I.. -I$(SRC_PATH) -I$(SRC_PATH)/shared -I$(SRC_PATH)/slirp -I$(SRC_PATH)/shared/hooks -I$(SRC_PATH)/i386-softmmu -I$(SRC_PATH)/target-i386 -I$(SRC_PATH)/fpu 
DEFINES+=-D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE -D_GNU_SOURCE
DEFINES+=-I$(SRC_PATH)/shared/llconf/install/include
DEFINES+=-I$(SRC_PATH)/shared/sleuthkit/src/fstools -I$(SRC_PATH)/shared/sleuthkit/src/auxtools -I$(SRC_PATH)/shared/sleuthkit/src/imgtools -DLINUX2 -DTRACE_ENABLED

CC=gcc
CPP=g++
CFLAGS=-Wall -O2 -g -fPIC -MMD 
# CFLAGS=-Wall -g -fPIC 
LDFLAGS=-g -shared 
LIBS=-L$(SRC_PATH)/shared/sleuthkit/lib -lfstools -limgtools -lauxtools 
LIBS+=-L$(SRC_PATH)/shared/sleuthkit/src/afflib/lib/ -lafflib -L$(SRC_PATH)/shared/sleuthkit/src/libewf -lewf
LIBS+=$(SRC_PATH)/shared/llconf/install/lib/libllconf.a
LIBS+=-lcrypto

ifeq ($(ARCH), x86_64)
LIBS+=-L$(SRC_PATH)/shared/xed2/xed2-intel64/lib -lxed
DEFINES+= -I$(SRC_PATH)/shared/xed2/xed2-intel64/include
endif
ifeq ($(ARCH), i386)
LIBS+=-L$(SRC_PATH)/shared/xed2/xed2-ia32/lib -lxed
DEFINES+= -I$(SRC_PATH)/shared/xed2/xed2-ia32/include
endif

OBJS=state.o commands.o trace.o operandinfo.o conditions.o network.o errdet.o conf.o tracecap.o ../shared/procmod.o ../shared/read_linux.o readwrite.o 
OBJS+=../shared/hooks/function_map.o ../shared/hookapi.o  
OBJS+=../shared/hooks/hook_plugin_loader.o ext_hooks.o
OBJS+=../shared/reduce_taint.o hook_helpers.o 

all: tracecap.so ini/main.ini 

sleuthkit:
	$(MAKE) -C $(SRC_PATH)/shared/sleuthkit

hooks:
	$(MAKE) -C $(SRC_PATH)/shared/hooks/hook_plugins protos_hooks

ini/main.ini: ini/main.ini.in
	@perl -pe 's[SRC_PATH][$(SRC_PATH)]g' $< >$@

%.o: %.c 
	$(CC) $(CFLAGS) $(DEFINES) -c -o $@ $<

%.o: %.cpp
	$(CPP) $(CFLAGS) $(DEFINES) -c -o $@ $<

tracecap.so: $(OBJS)
	$(CPP) $(LDFLAGS) $^ -o $@ $(LIBS)
	ar cru libtracecap.a $@

tracecap-static.so: $(OBJS)
	$(CPP) -static-libgcc -Wl,-static $(LDFLAGS) $^ -o $@ $(LIBS)

clean:
	rm -f *.o  *.so *.a *~ $(PLUGIN) ../shared/*.o ../shared/hooks/*.o *.d ../*.d ../shared/*d ../shared/*/*.d ini/main.ini

# Include automatically generated dependency files
-include $(wildcard *.d ../*.d ../shared/*d ../shared/*/*.d)

