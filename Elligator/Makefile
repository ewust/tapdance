
CFLAGS+=-O3
LDFLAGS+=-lgmp


all: elligator2-test genkey

elligator2-test: elligator2.c elligator2-test.c curve25519-donna.c
	$(CC) -o $@ $(CFLAGS) $^ $(LDFLAGS)

genkey: genkey.c elligator2.c curve25519-donna.c
	$(CC) -o $@ $(CFLAGS) $^ $(LDFLAGS)
