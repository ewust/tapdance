
CFLAGS+=-I../../forge_socket/ -I/usr/local/include -I/usr/local/ssl/include -g #-O2
#LDFLAGS+=-lpcap -L/usr/local/lib -lcrypto -lssl -levent -levent_openssl ../../PF_RING/userland/lib/libpfring.a -lm
LDFLAGS=-L/usr/lib/ -L/usr/local/lib -L/usr/lib/ -lpcap -lcrypto -lssl -levent_core -levent_extra -lpfring -ldl -levent_openssl -lnuma #../../PF_RING/userland/lib/libpfring.a -lm

all: station


station: station.c ssl_api.c logger.c libforge_socket.o flow.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)
