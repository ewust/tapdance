
CFLAGS+=-I../../forge_socket/ -I/usr/local/include -I/usr/local/ssl/include -I../Elligator/ -g #-O2
#LDFLAGS+=-lpcap -L/usr/local/lib -lcrypto -lssl -levent -levent_openssl ../../PF_RING/userland/lib/libpfring.a -lm
LDFLAGS=-L/usr/lib/ -L/usr/local/lib -L/usr/lib/ -lpcap -lcrypto -lssl -levent_core -levent_extra -lpfring -ldl -levent_openssl -lnuma -lgmp #../../PF_RING/userland/lib/libpfring.a -lm

all: station

OBJS=libforge_socket.o flow.o tcp.o ssl_api.o logger.o proxy_map.o ../Elligator/elligator2.c ../Elligator/curve25519-donna.c

station: station.c $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	rm -f $(OBJS) ./station
