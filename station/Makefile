
CFLAGS+=-g #-O2
LDFLAGS+=-lpcap -levent -L/usr/lib/ -lcrypto -lssl ../../PF_RING/userland/lib/libpfring.a -lm

all: station


station: station.c ssl_api.c logger.c
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)
