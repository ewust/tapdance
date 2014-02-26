
CFLAGS+=-O3
LDFLAGS+=-lgmp -lcrypto


all: elligator2-test genkey

#curve25519-donna.c
elligator2-test: elligator2.c elligator2-test.c curve25519-donna-c64.o
	$(CC) -o $@ $(CFLAGS) $^ $(LDFLAGS)

genkey: genkey.c elligator2.c curve25519-donna.c
	$(CC) -o $@ $(CFLAGS) $^ $(LDFLAGS)
