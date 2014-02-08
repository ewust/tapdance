
CFLAGS+=-I../../forge_socket/ -g #-O2
#LDFLAGS+=-lpcap -L/usr/local/lib -lcrypto -lssl -levent -levent_openssl ../../PF_RING/userland/lib/libpfring.a -lm
LDFLAGS=-lpcap -L/usr/lib -lcrypto -lssl -levent -levent_openssl -lssl -lpfring #../../PF_RING/userland/lib/libpfring.a -lm

all: station


station: station.c ssl_api.c logger.c libforge_socket.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)
