# SPDX-License-Identifier: GPL-2.0
include ../config.mk

TARGETS :=

ifeq ($(HAVE_MNL),y)

CFLAGS += -I./include/uapi/
MLXDEVMOBJ = mlxdevm.o
TARGETS += mlxdevm

endif

all: $(TARGETS) $(LIBS)

mlxdevm: $(MLXDEVMOBJ) $(LIBNETLINK)
	$(QUIET_LINK)$(CC) $^ $(LDFLAGS) $(LDLIBS) -o $@

install: all
	for i in $(TARGETS); \
	do install -m 0755 $$i $(DESTDIR)$(SBINDIR); \
	done

clean:
	rm -f $(MLXDEVMOBJ) $(TARGETS)
