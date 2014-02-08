
CFLAGS+=-I../../forge_socket/ -I/usr/include -g #-O2
#LDFLAGS+=-lpcap -L/usr/local/lib -lcrypto -lssl -levent -levent_openssl ../../PF_RING/userland/lib/libpfring.a -lm
LDFLAGS=-L/usr/lib -lpcap -lcrypto -lssl -levent_core -levent_extra -lpfring -ldl /usr/lib/libevent_openssl.a #../../PF_RING/userland/lib/libpfring.a -lm

all: station


station: station.c ssl_api.c logger.c libforge_socket.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)
