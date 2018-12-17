LIBS=-lpcre -lcrypto -lm -lpthread
CFLAGS=-ggdb -O3 -Wall
OBJS=vanmin.o oclvanmin.o oclvanityminer.o oclengine.o keyconv.o pattern.o util.o
PROGS=vanmin keyconv oclvanmin oclvanityminer

PLATFORM=$(shell uname -s)
ifeq ($(PLATFORM),Darwin)
OPENCL_LIBS=-framework OpenCL
else
OPENCL_LIBS=-lOpenCL
endif


most: vanmin keyconv

all: $(PROGS)

vanmin: vanmin.o pattern.o util.o
	$(CC) $^ -o $@ $(CFLAGS) $(LIBS)

oclvanmin: oclvanmin.o oclengine.o pattern.o util.o
	$(CC) $^ -o $@ $(CFLAGS) $(LIBS) $(OPENCL_LIBS)

oclvanityminer: oclvanityminer.o oclengine.o pattern.o util.o
	$(CC) $^ -o $@ $(CFLAGS) $(LIBS) $(OPENCL_LIBS) -lcurl

keyconv: keyconv.o util.o
	$(CC) $^ -o $@ $(CFLAGS) $(LIBS)

clean:
	rm -f $(OBJS) $(PROGS) $(TESTS)
