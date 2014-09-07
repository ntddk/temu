include ../../../config-host.mak

CC = gcc
CFLAGS=-I../../../ -I../../ -I.. -I../../../i386-softmmu -g -Wall -fPIC -O2 -D_GNU_SOURCE
LDFLAGS=-ldl -shared -g

 
GROUP_PLUGINS=sample_hook.so

TRACE_LIBS=-L../../../$(PROJECT_NAME)/ -l$(PROJECT_NAME)

.PHONY: clean kinda_clean 

# all: group_hooks generic_hooks project_hooks
all: group_hooks 

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

%.o: %.cpp
	g++ $(CFLAGS) -c -o $@ $<

group_hooks: $(GROUP_PLUGINS)

$(GROUP_PLUGINS): %.so: %.o hook_plugin.o group_hook_helper.o
	$(CC) $(LDFLAGS) $^ -o $@ $(TRACE_LIBS)


kinda_clean:
	rm -f *.o

clean:
	rm -f *.o *.so *~

