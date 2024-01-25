SRC_C = $(wildcard *.c)
OBJ_C = $(SRC_C:.c=.o)
EXE_C = $(SRC_C:.c=)

CFLAGS = -g
LDFLAGS = -lm

MPI_HOME=
CC=$(MPI_HOME)/bin/mpicc
F90=$(MPI_HOME)/bin/mpif90
DESTDIR=
PREFIX=/usr/local/mpi/misc

all: all-c 

all-c: $(OBJ_C)
	$(foreach t,$(EXE_C),$(CC) -o $(t) $(t).o $(LDFLAGS);)

$(OBJ_C): %.o: %.c
	$(CC) -c $(CFLAGS) $< -o $@

$(EXE_C): $(OBJ_C)
	$(CC) -o $* $@ $(LDFLAGS)

install: $(EXE_C)
	mkdir -p $(DESTDIR)/$(PREFIX)
	cp -f $(EXE_C) hpcc_conf.pl $(DESTDIR)/$(PREFIX)


clean:
	@rm -f $(OBJ_C) $(EXE_C)
