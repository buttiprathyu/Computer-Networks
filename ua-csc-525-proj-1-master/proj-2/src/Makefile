#------------------------------------------------------------------------------
# File: Makefile
#
# Note: This Makefile requires GNU make.
#
# (c) 2001,2000 Stanford University
#
#------------------------------------------------------------------------------

CC = gcc

OSTYPE = $(shell uname)

ifeq ($(OSTYPE),CYGWIN_NT-5.1)
ARCH = -D_CYGWIN_
endif

ifeq ($(OSTYPE),Linux)
ARCH = -D_LINUX_
SOCK = -lnsl -lrt
endif

ifeq ($(OSTYPE),SunOS)
ARCH =  -D_SOLARIS_
SOCK = -lnsl -lsocket
endif

ifeq ($(OSTYPE),Darwin)
ARCH = -D_DARWIN_
SOCK = 
endif

CFLAGS = -std=gnu99 -DVNL $(ARCH)
CFLAGS_DEBUG = -g -Wall -D_DEBUG_
CFLAGS_RELEASE = -D_RELEASE_

LIBS= $(SOCK) -lm -lresolv -lpthread
PFLAGS= -follow-child-processes=yes -cache-dir=/tmp/${USER}
PURIFY= purify ${PFLAGS}

sr_SRCS = vnlconn.c sr_router.c sr_main.c  \
          sr_if.c sr_rt.c sr_vns_comm.c   \
          sr_dumper.c sha1.c sr_pwospf.c \
          sr_util.c sr_debug.c sr_pwospf_graph.c

sr_OBJS = $(patsubst %.c,%.o,$(sr_SRCS))
sr_DEPS = $(patsubst %.c,.%.d,$(sr_SRCS))

all : debug
debug : CFLAGS += $(CFLAGS_DEBUG)
debug : sr
release : CFLAGS += $(CFLAGS_RELEASE)
release : sr

$(sr_OBJS) : %.o : %.c
	$(CC) -c $(CFLAGS) $< -o $@

$(sr_DEPS) : .%.d : %.c
	$(CC) -MM $(CFLAGS) $<  > $@

include $(sr_DEPS)	

sr : $(sr_OBJS)
	$(CC) $(CFLAGS) -o sr $(sr_OBJS) $(LIBS)

sr.purify : $(sr_OBJS)
	$(PURIFY) $(CC) $(CFLAGS) -o sr.purify $(sr_OBJS) $(LIBS)

.PHONY : clean clean-deps dist

clean:
	rm -f *.o *~ core sr *.dump *.tar tags

clean-deps:
	rm -f .*.d

dist-clean: clean clean-deps
	rm -f .*.swp pwospf_stub.tar.gz

dist: dist-clean
	(cd ..; tar -X pwospf_stub/exclude -cvf pwospf_stub.tar pwospf_stub/; gzip pwospf_stub.tar); \
    mv ../pwospf_stub.tar.gz .

tags:
	ctags *.c
