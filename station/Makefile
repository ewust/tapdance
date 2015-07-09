

FORGE_SOCKET_PATH=../../forge_socket/   # EDIT ME


USE_PFRING=

CFLAGS+=-I$(FORGE_SOCKET_PATH) -I/usr/local/include -I/usr/local/ssl/include -I../Elligator/ -g #-O2
#LDFLAGS+=-lpcap -L/usr/local/lib -lcrypto -lssl -levent -levent_openssl ../../PF_RING/userland/lib/libpfring.a -lm
#LDFLAGS=-L/usr/lib -L/usr/local/ssl/lib -lpcap -lcrypto -lssl -levent_core -levent_extra -ldl -levent_openssl -lgmp # -lnuma #../../PF_RING/userland/lib/libpfring.a -lm

LDFLAGS=`pkg-config --libs openssl libevent`
LDFLAGS+=-levent_core -levent_extra -ldl -levent_openssl -lgmp -lpcap

ifdef USE_PFRING
LDFLAGS += -lpfring
CFLAGS += -DPFRING
endif

all: station

OBJS=libforge_socket.o flow.o tcp.o ssl_api.o logger.o proxy_map.o


station: station.c $(OBJS) ../Elligator/elligator2.c ../Elligator/curve25519-donna.c
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	rm -f $(OBJS) ./station
