
LDFLAGS+=-lgmp

elligator2-test: elligator2.c elligator2-test.c curve25519-donna.c
	$(CC) -o $@ $(CFLAGS) $^ $(LDFLAGS)
