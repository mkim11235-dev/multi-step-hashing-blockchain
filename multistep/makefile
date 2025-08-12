CC = gcc

OPENSSL_PREFIX := $(shell brew --prefix openssl@3)

CFLAGS = -Wall -Wextra -I$(OPENSSL_PREFIX)/include
LDFLAGS = -L$(OPENSSL_PREFIX)/lib -lcrypto -lssl -lm
OPT = -O3 -funroll-loops

all: multistep

multistep: main.o swifft.o setup.o
	$(CC) $(CFLAGS) $(OPT) -o multistep main.o swifft.o setup.o $(LDFLAGS)

main.o: main.c swifft.h
	$(CC) $(CFLAGS) $(OPT) -c main.c

swifft.o: swifft.c swifft.h
	$(CC) $(CFLAGS) $(OPT) -c swifft.c

setup.o: setup.c swifft.h
	$(CC) $(CFLAGS) $(OPT) -c setup.c

clean:
	rm -f *.o multistep
