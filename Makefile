#
## makefile for libion and iontest
#

export CROSS_COMPILE=aarch64-linux-gnu-
#export CROSS_COMPILE=/opt/gcc-linaro-6.3.1-2017.02-x86_64_aarch64-linux-gnu/bin/aarch64-linux-gnu-
CC := $(CROSS_COMPILE)gcc


LIBION_OBJ = ion.o IONmem.o
CFLAGS += -I ./include/
CFLAGS += -I ./kernel-headers/
LIBION = libion.so

IONTEST_OBJ = ion_test.o
IONTEST = iontest

.PHONY: clean

# rules
all: $(LIBION) $(IONTEST)

%.o: %.c
	$(CC) -c -fPIC  $(CFLAGS) $^ -o $@

$(LIBION): $(LIBION_OBJ)
	$(CC) -shared -fPIC $(CFLAGS) $^ -o $(LIBION)

$(IONTEST): $(IONTEST_OBJ) $(LIBION)
	$(CC) $^ $(CFLAGS)  -o $@

clean:
	rm -rf $(OBJ)
	rm -rf *.o

